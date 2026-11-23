//! The local search of messages, as the API searches the rooms of a Space: the text's words, each
//! the start of a word of the message (a one-letter one whole), its accents and its case aside, and
//! the filters `from`, `mentions`, `after`, `before` and `has`. A deleted message isn't found, nor one
//! that waits.

use rusqlite::params_from_iter;
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::store::{MAX_PAGE, Shown, select};
use crate::identity::invalid;
use crate::{Error, Tx};

/// The longest text a search takes, in characters, and the most words of it that count.
const MAX_TEXT: usize = 200;
const MAX_WORDS: usize = 10;
/// The most users `from` and `mentions` take.
const MAX_USERS: usize = 10;

#[derive(Debug, Deserialize)]
pub(crate) struct Search {
    #[serde(default)]
    text: Option<String>,
    /// One conversation's messages; every conversation's without it.
    #[serde(default)]
    conversation_id: Option<Uuid>,
    /// Written by one of these users.
    #[serde(default)]
    from: Vec<Uuid>,
    /// Mentioning one of these users, in its text or in the list its sender gave the API.
    #[serde(default)]
    mentions: Vec<Uuid>,
    /// Taken by the API at this time or later, in Unix milliseconds.
    #[serde(default)]
    after: Option<i64>,
    /// Taken by the API before this time.
    #[serde(default)]
    before: Option<i64>,
    /// With a file of one of these kinds; `file` is any file.
    #[serde(default)]
    has: Vec<Has>,
    limit: u32,
    #[serde(default)]
    offset: u32,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Has {
    Image,
    Video,
    Audio,
    File,
}

#[derive(Serialize)]
pub(crate) struct Found {
    /// How many messages match, past the page too.
    total: u64,
    /// A page of them, newest first.
    messages: Vec<Shown>,
}

pub(crate) fn search(tx: &Tx<'_>, request: Search) -> Result<Found, Error> {
    if request
        .text
        .as_ref()
        .is_some_and(|text| text.chars().count() > MAX_TEXT)
    {
        return Err(invalid(
            "text",
            "a search's text has 200 characters at most",
        ));
    }
    if request.from.len() > MAX_USERS {
        return Err(invalid("from", "a search takes 10 authors at most"));
    }
    if request.mentions.len() > MAX_USERS {
        return Err(invalid(
            "mentions",
            "a search takes 10 mentioned users at most",
        ));
    }
    let mut filter = Filter::default();
    filter.and("deleted = 0 AND status <> 'waiting'");
    if let Some(words) = request.text.as_deref().and_then(match_words) {
        let words = filter.value(words);
        filter.and(&format!(
            "id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH {words})"
        ));
    }
    if let Some(conversation) = request.conversation_id {
        let conversation = filter.value(conversation.as_bytes().to_vec());
        filter.and(&format!("conversation_id = {conversation}"));
    }
    if !request.from.is_empty() {
        let users = filter.list(&request.from);
        filter.and(&format!("user_id IN ({users})"));
    }
    if !request.mentions.is_empty() {
        let in_text: Vec<String> = request
            .mentions
            .iter()
            .map(|user| {
                let mention = filter.value(format!("<@{user}>"));
                format!("instr(text, {mention}) > 0")
            })
            .collect();
        let users = filter.list(&request.mentions);
        filter.and(&format!(
            "({} OR EXISTS (SELECT 1 FROM mentions x WHERE x.message = messages.id \
             AND x.user_id IN ({users})))",
            in_text.join(" OR ")
        ));
    }
    if let Some(after) = request.after {
        let after = filter.value(after);
        filter.and(&format!("sent_at >= {after}"));
    }
    if let Some(before) = request.before {
        let before = filter.value(before);
        filter.and(&format!("sent_at < {before}"));
    }
    if !request.has.is_empty() {
        let kinds: Vec<&str> = request
            .has
            .iter()
            .map(|has| match has {
                Has::Image => "(' ' || has || ' ') LIKE '% image %'",
                Has::Video => "(' ' || has || ' ') LIKE '% video %'",
                Has::Audio => "(' ' || has || ' ') LIKE '% audio %'",
                Has::File => "has IS NOT NULL",
            })
            .collect();
        filter.and(&format!("({})", kinds.join(" OR ")));
    }

    let condition = filter.conditions.join(" AND ");
    let total: i64 = tx.conn().query_row(
        &format!("SELECT count(*) FROM messages WHERE {condition}"),
        params_from_iter(&filter.values),
        |row| row.get(0),
    )?;
    let limit = filter.value(i64::from(request.limit.clamp(1, MAX_PAGE)));
    let offset = filter.value(i64::from(request.offset));
    let rows = select(
        tx,
        &format!("{condition} ORDER BY sent_at DESC, id DESC LIMIT {limit} OFFSET {offset}"),
        params_from_iter(&filter.values),
    )?;
    Ok(Found {
        total: u64::try_from(total).unwrap_or(0),
        messages: rows.into_iter().map(Shown::of).collect::<Result<_, _>>()?,
    })
}

/// A search's conditions and the values they take, numbered as they're added.
#[derive(Default)]
struct Filter {
    conditions: Vec<String>,
    values: Vec<Value>,
}

impl Filter {
    fn and(&mut self, condition: &str) {
        self.conditions.push(condition.to_owned());
    }

    /// The placeholder of a new value.
    fn value(&mut self, value: impl Into<Value>) -> String {
        self.values.push(value.into());
        format!("?{}", self.values.len())
    }

    /// The placeholders of users' IDs.
    fn list(&mut self, users: &[Uuid]) -> String {
        users
            .iter()
            .map(|user| self.value(user.as_bytes().to_vec()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The FTS5 query for a search's text: its words, all of them, each as the start of a word but a
/// one-letter one, which would match nearly everything. A word is a run of letters and digits, so
/// nothing in it is FTS5's syntax; the index folds case and accents, on the query as on the text.
fn match_words(text: &str) -> Option<String> {
    let words: Vec<String> = text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .take(MAX_WORDS)
        .map(|word| {
            if word.chars().count() > 1 {
                format!("\"{word}\"*")
            } else {
                format!("\"{word}\"")
            }
        })
        .collect();
    (!words.is_empty()).then(|| words.join(" "))
}
