//! The messages as this device keeps them: one row each, its text its author's latest edit that
//! counts (`refresh_text`), and the edits apart, each as it came. The search index follows the text
//! by itself (`messages_fts`, kept by the table's triggers). Also the history a client shows
//! (`messages`), and the records a backup or a history share carries out and brings in
//! (`records_for`, `import`).

use std::collections::BTreeSet;

use duvet_e2e_rules::MAX_MEMBERS;
use rusqlite::{OptionalExtension, Params, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::deviceless;
use super::{File, Record, RecordKind};
use crate::identity::{invalid, stored_uuid};
use crate::{Attachment, Envelope, Error, Tx};

/// The columns `Row::read` takes, in its order.
const COLUMNS: &str = "id, message_id, nonce, conversation_id, seq, user_id, device_id, \
    sent_at, envelope, text, edited_at, deleted, status, shared_by, reply_to, imported";

/// Whether a message can be shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Ok,
    /// Its queue's copy couldn't be opened: it waits for an import.
    Waiting,
    /// This device's own, encrypted and not yet sent, as far as it knows.
    Pending,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Waiting => "waiting",
            Status::Pending => "pending",
        }
    }

    fn from_name(name: &str) -> Result<Status, Error> {
        match name {
            "ok" => Ok(Status::Ok),
            "waiting" => Ok(Status::Waiting),
            "pending" => Ok(Status::Pending),
            _ => Err(malformed()),
        }
    }
}

/// A message as this device keeps it.
#[derive(Debug)]
pub(crate) struct Row {
    pub(crate) id: i64,
    /// The API's ID, unknown while this device's own is being sent.
    pub(crate) message_id: Option<Uuid>,
    /// The nonce this device sent its own under.
    pub(crate) nonce: Option<String>,
    pub(crate) conversation: Uuid,
    pub(crate) seq: Option<u64>,
    pub(crate) user: Uuid,
    pub(crate) device: Uuid,
    pub(crate) sent_at: i64,
    /// The message as it was sent; none while it waits, or once it's deleted.
    pub(crate) envelope: Option<Vec<u8>>,
    pub(crate) text: Option<String>,
    pub(crate) edited_at: Option<i64>,
    pub(crate) deleted: bool,
    pub(crate) status: Status,
    pub(crate) shared_by: Option<Uuid>,
    /// The message it answers, as the API gives it.
    pub(crate) reply_to: Option<Uuid>,
    /// Whether its content came from an import (a backup copy, a history share, a catch-up), which
    /// the API's word on deletions may erase; else this device decrypted it from its queue or sent
    /// it, and only its author's deletion erases it.
    pub(crate) imported: bool,
}

impl Row {
    /// A row of `COLUMNS`.
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Columns> {
        Ok(Columns {
            id: row.get(0)?,
            message_id: row.get(1)?,
            nonce: row.get(2)?,
            conversation: row.get(3)?,
            seq: row.get(4)?,
            user: row.get(5)?,
            device: row.get(6)?,
            sent_at: row.get(7)?,
            envelope: row.get(8)?,
            text: row.get(9)?,
            edited_at: row.get(10)?,
            deleted: row.get(11)?,
            status: row.get(12)?,
            shared_by: row.get(13)?,
            reply_to: row.get(14)?,
            imported: row.get(15)?,
        })
    }

    /// The files the message carries.
    pub(crate) fn attachments(&self) -> Result<Vec<Attachment>, Error> {
        match &self.envelope {
            Some(envelope) => match Envelope::decode(envelope) {
                Ok(Envelope::Message { attachments, .. }) => Ok(attachments),
                _ => Err(malformed()),
            },
            None => Ok(Vec::new()),
        }
    }
}

/// A row as SQLite gives it, before its IDs are read.
struct Columns {
    id: i64,
    message_id: Option<Vec<u8>>,
    nonce: Option<String>,
    conversation: Vec<u8>,
    seq: Option<i64>,
    user: Vec<u8>,
    device: Vec<u8>,
    sent_at: i64,
    envelope: Option<Vec<u8>>,
    text: Option<String>,
    edited_at: Option<i64>,
    deleted: bool,
    status: String,
    shared_by: Option<Vec<u8>>,
    reply_to: Option<Vec<u8>>,
    imported: bool,
}

impl Columns {
    fn into_row(self) -> Result<Row, Error> {
        let uuid = |bytes: Option<Vec<u8>>| bytes.as_deref().map(stored_uuid).transpose();
        Ok(Row {
            id: self.id,
            message_id: uuid(self.message_id)?,
            nonce: self.nonce,
            conversation: stored_uuid(&self.conversation)?,
            seq: self
                .seq
                .map(|seq| u64::try_from(seq).map_err(|_| malformed()))
                .transpose()?,
            user: stored_uuid(&self.user)?,
            device: stored_uuid(&self.device)?,
            sent_at: self.sent_at,
            envelope: self.envelope,
            text: self.text,
            edited_at: self.edited_at,
            deleted: self.deleted,
            status: Status::from_name(&self.status)?,
            shared_by: uuid(self.shared_by)?,
            reply_to: uuid(self.reply_to)?,
            imported: self.imported,
        })
    }
}

/// The rows `filter` (an SQL condition over `COLUMNS`, then any order and limit) selects.
pub(super) fn select(tx: &Tx<'_>, filter: &str, params: impl Params) -> Result<Vec<Row>, Error> {
    let mut statement = tx
        .conn()
        .prepare(&format!("SELECT {COLUMNS} FROM messages WHERE {filter}"))?;
    let columns = statement
        .query_map(params, Row::read)?
        .collect::<Result<Vec<_>, _>>()?;
    columns.into_iter().map(Columns::into_row).collect()
}

pub(crate) fn by_message_id(tx: &Tx<'_>, message_id: Uuid) -> Result<Option<Row>, Error> {
    Ok(select(tx, "message_id = ?1", [message_id.as_bytes().as_slice()])?.pop())
}

pub(crate) fn by_nonce(tx: &Tx<'_>, nonce: &str) -> Result<Option<Row>, Error> {
    Ok(select(tx, "nonce = ?1", [nonce])?.pop())
}

fn by_id(tx: &Tx<'_>, id: i64) -> Result<Row, Error> {
    select(tx, "id = ?1", [id])?.pop().ok_or_else(malformed)
}

/// A message as its envelope opens: the envelope itself, its text, and the kinds of its files.
pub(crate) struct Opened {
    envelope: Vec<u8>,
    text: Option<String>,
    has: Option<String>,
}

impl Opened {
    pub(crate) fn new(
        envelope: Vec<u8>,
        text: Option<String>,
        attachments: &[Attachment],
    ) -> Opened {
        let kinds: BTreeSet<&str> = attachments
            .iter()
            .map(|attachment| file_kind(&attachment.content_type))
            .collect();
        let has = (!kinds.is_empty()).then(|| kinds.into_iter().collect::<Vec<_>>().join(" "));
        Opened {
            envelope,
            text,
            has,
        }
    }
}

/// What the search's `has` knows a file as, by its type: `image`, `video`, `audio`, else `file`.
fn file_kind(content_type: &str) -> &'static str {
    let content_type = content_type.to_ascii_lowercase();
    if content_type.starts_with("image/") {
        "image"
    } else if content_type.starts_with("video/") {
        "video"
    } else if content_type.starts_with("audio/") {
        "audio"
    } else {
        "file"
    }
}

/// A message to keep.
pub(crate) struct NewRow<'a> {
    pub(crate) message_id: Option<Uuid>,
    pub(crate) nonce: Option<&'a str>,
    pub(crate) conversation: Uuid,
    pub(crate) seq: Option<u64>,
    pub(crate) user: Uuid,
    pub(crate) device: Uuid,
    pub(crate) sent_at: i64,
    /// What it holds; none for one that waits, or for the mark of a deleted one.
    pub(crate) opened: Option<&'a Opened>,
    pub(crate) status: Status,
    pub(crate) deleted: bool,
    pub(crate) shared_by: Option<Uuid>,
    pub(crate) reply_to: Option<Uuid>,
    /// Whether an import brought it (`Row::imported`).
    pub(crate) imported: bool,
}

/// Keeps a message: its row's ID.
pub(crate) fn insert(tx: &Tx<'_>, new: NewRow<'_>) -> Result<i64, Error> {
    tx.conn().execute(
        "INSERT INTO messages (message_id, nonce, conversation_id, seq, user_id, device_id, \
         sent_at, envelope, text, deleted, status, shared_by, has, reply_to, imported) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            new.message_id.map(|id| id.as_bytes().to_vec()),
            new.nonce,
            new.conversation.as_bytes().as_slice(),
            new.seq.map(stored_seq).transpose()?,
            new.user.as_bytes().as_slice(),
            new.device.as_bytes().as_slice(),
            new.sent_at,
            new.opened.map(|opened| opened.envelope.as_slice()),
            new.opened.and_then(|opened| opened.text.as_deref()),
            new.deleted,
            new.status.name(),
            new.shared_by.map(|user| user.as_bytes().to_vec()),
            new.opened.and_then(|opened| opened.has.as_deref()),
            new.reply_to.map(|id| id.as_bytes().to_vec()),
            new.imported,
        ],
    )?;
    Ok(tx.conn().last_insert_rowid())
}

/// What a message is once its content is here: what was waiting for it, a copy an import brought
/// before the queue's, or the mark of a deletion that turned out not to be its author's.
pub(crate) struct Filled<'a> {
    pub(crate) seq: Option<u64>,
    pub(crate) user: Uuid,
    pub(crate) device: Uuid,
    pub(crate) sent_at: i64,
    pub(crate) opened: &'a Opened,
    pub(crate) shared_by: Option<Uuid>,
    /// What it answers, if this content says; else what the row knew stays.
    pub(crate) reply_to: Option<Uuid>,
    /// Whether an import brought it (`Row::imported`).
    pub(crate) imported: bool,
}

/// The row `id`, a copy an import brought, holds a message this device has now decrypted itself: only
/// its author's deletion takes it from here on (`Row::imported`). Its text and edits stay as they are.
pub(crate) fn decrypted(tx: &Tx<'_>, id: i64) -> Result<(), Error> {
    tx.conn()
        .execute("UPDATE messages SET imported = 0 WHERE id = ?1", [id])?;
    Ok(())
}

pub(crate) fn fill(tx: &Tx<'_>, id: i64, filled: Filled<'_>) -> Result<(), Error> {
    tx.conn().execute(
        "UPDATE messages SET seq = ?2, user_id = ?3, device_id = ?4, sent_at = ?5, envelope = ?6, \
         text = ?7, has = ?8, edited_at = NULL, deleted = 0, status = 'ok', shared_by = ?9, \
         reply_to = COALESCE(?10, reply_to), imported = ?11 WHERE id = ?1",
        params![
            id,
            filled.seq.map(stored_seq).transpose()?,
            filled.user.as_bytes().as_slice(),
            filled.device.as_bytes().as_slice(),
            filled.sent_at,
            filled.opened.envelope.as_slice(),
            filled.opened.text.as_deref(),
            filled.opened.has.as_deref(),
            filled.shared_by.map(|user| user.as_bytes().to_vec()),
            filled.reply_to.map(|id| id.as_bytes().to_vec()),
            filled.imported,
        ],
    )?;
    Ok(())
}

/// This device's own message once the API has it: its ID and its number, what it answers, and from
/// the queue's copy the time the API took it and whom it mentions. Another row with that ID gives
/// way only when it stands for this same message (`takes_over`). Anything else, or another ID than
/// the one bound already, leaves every row as it is: false.
pub(crate) fn bind(
    tx: &Tx<'_>,
    row: &Row,
    message_id: Option<Uuid>,
    seq: u64,
    sent_at: Option<i64>,
    mentions: &[Uuid],
    reply_to: Option<Uuid>,
) -> Result<bool, Error> {
    let mut deleted = row.deleted;
    if let Some(message_id) = message_id {
        if row.message_id.is_some_and(|bound| bound != message_id) {
            return Ok(false);
        }
        if let Some(other) = by_message_id(tx, message_id)?
            && other.id != row.id
        {
            let Some(holds) = takes_over(row, &other) else {
                return Ok(false);
            };
            deleted |= holds;
            tx.conn()
                .execute("DELETE FROM messages WHERE id = ?1", [other.id])?;
        }
    }
    tx.conn().execute(
        "UPDATE messages SET message_id = COALESCE(?2, message_id), seq = ?3, \
         sent_at = COALESCE(?4, sent_at), reply_to = COALESCE(?5, reply_to), status = 'ok' \
         WHERE id = ?1",
        params![
            row.id,
            message_id.map(|id| id.as_bytes().to_vec()),
            stored_seq(seq)?,
            sent_at,
            reply_to.map(|id| id.as_bytes().to_vec()),
        ],
    )?;
    if deleted {
        erase(tx, &by_id(tx, row.id)?)?;
        return Ok(true);
    }
    if !mentions.is_empty() {
        set_mentions(tx, row.id, mentions)?;
    }
    deviceless::note(tx, row.conversation, row.id)?;
    Ok(true)
}

/// Whether `other`, which has the ID the API gave this device's message `row`, stands for that same
/// message in its conversation, and if so whether it holds a deletion of it:
/// - a deletion's mark, left by a deletion of a message this device didn't have: this user's holds,
///   and another user's is none, as only the author deletes;
/// - a copy an import brought before the API's answer came: this device's own message, with the
///   same envelope, which gives way.
///
/// None for anything else, which the API's ID can't take over: another message, deleted or not.
fn takes_over(row: &Row, other: &Row) -> Option<bool> {
    if other.conversation != row.conversation {
        return None;
    }
    if other.deleted {
        let mark = other.seq.is_none() && other.nonce.is_none();
        return mark.then_some(other.user == row.user);
    }
    let copy = other.status == Status::Ok
        && other.nonce.is_none()
        && (other.user, other.device) == (row.user, row.device)
        && other.envelope.is_some()
        && other.envelope == row.envelope;
    copy.then_some(false)
}

/// What a message answers, when nothing said it yet: the API's answer to this device's message can
/// say it after the queue's copy didn't. A deleted message takes none.
pub(crate) fn fill_reply_to(tx: &Tx<'_>, id: i64, reply_to: Uuid) -> Result<(), Error> {
    tx.conn().execute(
        "UPDATE messages SET reply_to = COALESCE(reply_to, ?2) WHERE id = ?1 AND deleted = 0",
        params![id, reply_to.as_bytes().as_slice()],
    )?;
    Ok(())
}

/// The users a message mentions, as its sender listed them for the API: as many as a conversation
/// has members, at most.
pub(crate) fn set_mentions(tx: &Tx<'_>, id: i64, users: &[Uuid]) -> Result<(), Error> {
    tx.conn()
        .execute("DELETE FROM mentions WHERE message = ?1", [id])?;
    for user in users.iter().take(MAX_MEMBERS) {
        tx.conn().execute(
            "INSERT OR IGNORE INTO mentions (message, user_id) VALUES (?1, ?2)",
            params![id, user.as_bytes().as_slice()],
        )?;
    }
    Ok(())
}

/// An edit to keep.
pub(crate) struct NewEdit<'a> {
    pub(crate) conversation: Uuid,
    pub(crate) message_id: Uuid,
    pub(crate) seq: Option<u64>,
    pub(crate) user: Uuid,
    pub(crate) device: Uuid,
    pub(crate) sent_at: i64,
    pub(crate) text: &'a str,
    /// The SHA-256 of this device's own, to know it when the queue brings it back.
    pub(crate) echo: Option<&'a [u8]>,
    pub(crate) shared_by: Option<Uuid>,
}

pub(crate) fn add_edit(tx: &Tx<'_>, edit: NewEdit<'_>) -> Result<(), Error> {
    tx.conn().execute(
        "INSERT INTO edits (conversation_id, message_id, seq, user_id, device_id, sent_at, text, \
         echo, shared_by) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            edit.conversation.as_bytes().as_slice(),
            edit.message_id.as_bytes().as_slice(),
            edit.seq.map(stored_seq).transpose()?,
            edit.user.as_bytes().as_slice(),
            edit.device.as_bytes().as_slice(),
            edit.sent_at,
            edit.text,
            edit.echo,
            edit.shared_by.map(|user| user.as_bytes().to_vec()),
        ],
    )?;
    Ok(())
}

/// This device's own edit back from the queue: its number, and the time the API took it. The
/// message it edits, if it was one.
pub(crate) fn echo_edit(
    tx: &Tx<'_>,
    conversation: Uuid,
    echo: &[u8],
    seq: u64,
    sent_at: Option<i64>,
) -> Result<Option<Uuid>, Error> {
    let message: Option<Vec<u8>> = tx
        .conn()
        .query_row(
            "UPDATE edits SET seq = ?3, sent_at = COALESCE(?4, sent_at), echo = NULL \
             WHERE conversation_id = ?1 AND echo = ?2 RETURNING message_id",
            params![
                conversation.as_bytes().as_slice(),
                echo,
                stored_seq(seq)?,
                sent_at
            ],
            |row| row.get(0),
        )
        .optional()?;
    message.as_deref().map(stored_uuid).transpose()
}

/// Sets a message's text to its author's latest edit that counts (by when the API took it), or to
/// the text it was sent with when it has none. An edit to no text leaves none. An edit counts when
/// this device has it itself, when it came in its author's own package, or when the member who
/// shared this copy of the message shared it too: once the author's own copy replaces theirs, their
/// edits no longer count. The first two are on the author's word, and outrank the third whatever
/// its date: a sharer's edit shows only while the message has none on its author's word.
pub(crate) fn refresh_text(tx: &Tx<'_>, id: i64) -> Result<(), Error> {
    let row = by_id(tx, id)?;
    let (Some(message_id), Some(envelope), false) = (row.message_id, &row.envelope, row.deleted)
    else {
        return Ok(());
    };
    let latest: Option<(String, i64)> = tx
        .conn()
        .query_row(
            "SELECT text, sent_at FROM edits WHERE conversation_id = ?1 AND message_id = ?2 \
             AND user_id = ?3 AND (shared_by IS NULL OR shared_by = ?3 OR shared_by IS ?4) \
             ORDER BY (shared_by IS NULL OR shared_by = ?3) DESC, sent_at DESC, id DESC LIMIT 1",
            params![
                row.conversation.as_bytes().as_slice(),
                message_id.as_bytes().as_slice(),
                row.user.as_bytes().as_slice(),
                row.shared_by.as_ref().map(|by| by.as_bytes().as_slice()),
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (text, edited_at) = match latest {
        Some((text, at)) => ((!text.is_empty()).then_some(text), Some(at)),
        None => match Envelope::decode(envelope) {
            Ok(Envelope::Message { text, .. }) => (text, None),
            _ => return Err(malformed()),
        },
    };
    if (&text, edited_at) != (&row.text, row.edited_at) {
        tx.conn().execute(
            "UPDATE messages SET text = ?2, edited_at = ?3 WHERE id = ?1",
            params![id, text, edited_at],
        )?;
    }
    Ok(())
}

/// A message deleted for everyone: its text, its file, its edits and its mentions go, and its row
/// stays as the mark that it was deleted, so nothing brings it back.
pub(crate) fn erase(tx: &Tx<'_>, row: &Row) -> Result<(), Error> {
    tx.conn().execute(
        "UPDATE messages SET envelope = NULL, text = NULL, has = NULL, edited_at = NULL, \
         reply_to = NULL, deleted = 1 WHERE id = ?1",
        [row.id],
    )?;
    if let Some(message_id) = row.message_id {
        forget_edits(tx, row.conversation, message_id)?;
    }
    tx.conn()
        .execute("DELETE FROM mentions WHERE message = ?1", [row.id])?;
    tx.conn()
        .execute("DELETE FROM deviceless WHERE message = ?1", [row.id])?;
    // Nor is it sent again: its nonce is spent.
    if let Some(nonce) = &row.nonce {
        tx.conn()
            .execute("DELETE FROM outbox WHERE nonce = ?1", [nonce])?;
    }
    Ok(())
}

/// A message's row dropped: its mentions and its notes go with it (the tables' cascade), its words
/// leave the search index (the trigger), and its ciphertext the outbox, if it waits there. For a
/// message this device encrypted and never sent (`discard`), and for one it couldn't read, which a
/// deletion leaves only the mark of.
pub(crate) fn forget(tx: &Tx<'_>, row: &Row) -> Result<(), Error> {
    tx.conn()
        .execute("DELETE FROM messages WHERE id = ?1", [row.id])?;
    if let Some(nonce) = &row.nonce {
        tx.conn()
            .execute("DELETE FROM outbox WHERE nonce = ?1", [nonce])?;
    }
    Ok(())
}

pub(crate) fn forget_edits(tx: &Tx<'_>, conversation: Uuid, message_id: Uuid) -> Result<(), Error> {
    tx.conn().execute(
        "DELETE FROM edits WHERE conversation_id = ?1 AND message_id = ?2",
        params![
            conversation.as_bytes().as_slice(),
            message_id.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(crate) struct ListMessages {
    conversation_id: Uuid,
    /// The page ends before the message of this number.
    #[serde(default)]
    before: Option<u64>,
    /// How many messages the page has: a page needs it.
    #[serde(default)]
    limit: Option<u32>,
    /// The messages asked for by their IDs, in place of a page: 200 at most.
    #[serde(default)]
    ids: Option<Vec<Uuid>>,
}

#[derive(Serialize)]
pub(crate) struct Page {
    messages: Vec<Shown>,
}

/// A message as `messages` and `search` show it.
#[derive(Serialize)]
pub(crate) struct Shown {
    conversation_id: Uuid,
    message_id: Option<Uuid>,
    /// This device's own message's nonce.
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    seq: Option<u64>,
    user_id: Uuid,
    device_id: Uuid,
    sent_at: i64,
    edited_at: Option<i64>,
    status: Status,
    text: Option<String>,
    attachments: Vec<File>,
    shared_by: Option<Uuid>,
    /// The message it answers.
    reply_to: Option<Uuid>,
}

impl Shown {
    pub(crate) fn of(row: Row) -> Result<Shown, Error> {
        let attachments = row.attachments()?.into_iter().map(File::from).collect();
        Ok(Shown {
            conversation_id: row.conversation,
            message_id: row.message_id,
            nonce: row.nonce,
            seq: row.seq,
            user_id: row.user,
            device_id: row.device,
            sent_at: row.sent_at,
            edited_at: row.edited_at,
            status: row.status,
            text: row.text,
            attachments,
            shared_by: row.shared_by,
            reply_to: row.reply_to,
        })
    }
}

/// The most messages a page or a search gives at once.
pub(super) const MAX_PAGE: u32 = 100;

/// The most messages `messages` takes by their IDs.
const MAX_IDS: usize = 200;

/// A page of the conversation's history, newest first: this device's own still being sent, then the
/// rest by their number. Or, by `ids`, the messages of those IDs this device has in the
/// conversation, in the same order. Deleted messages aren't in either.
pub(crate) fn messages(tx: &Tx<'_>, request: ListMessages) -> Result<Page, Error> {
    let conversation = request.conversation_id.as_bytes().as_slice();
    let rows = match (request.ids, request.before, request.limit) {
        (Some(ids), None, None) => {
            if ids.len() > MAX_IDS {
                return Err(Error::TooLarge {
                    limit: MAX_IDS as u64,
                });
            }
            let marks = vec!["?"; ids.len()].join(", ");
            select(
                tx,
                &format!(
                    "conversation_id = ? AND deleted = 0 AND message_id IN ({marks}) \
                     ORDER BY seq IS NOT NULL, seq DESC, id DESC"
                ),
                rusqlite::params_from_iter(
                    std::iter::once(conversation)
                        .chain(ids.iter().map(|id| id.as_bytes().as_slice())),
                ),
            )?
        }
        (Some(_), ..) => return Err(invalid("ids", "messages by IDs take no page")),
        (None, _, None) => return Err(invalid("limit", "a page has a limit")),
        (None, before, Some(limit)) => select(
            tx,
            "conversation_id = ?1 AND deleted = 0 AND (?2 IS NULL OR seq < ?2) \
             ORDER BY seq IS NOT NULL, seq DESC, id DESC LIMIT ?3",
            params![
                conversation,
                before.map(|seq| i64::try_from(seq).unwrap_or(i64::MAX)),
                limit.clamp(1, MAX_PAGE)
            ],
        )?,
    };
    Ok(Page {
        messages: rows.into_iter().map(Shown::of).collect::<Result<_, _>>()?,
    })
}

/// What a backup's segment or a history share carries of `conversation` between `from_ms` and
/// `to_ms` (the end excluded), by the time the API took each: the messages this device shows, as
/// they were sent, and their authors' edits, each in its own time. Neither one still being sent nor
/// one that waits is in it.
pub fn records_for(
    tx: &Tx<'_>,
    conversation: Uuid,
    from_ms: i64,
    to_ms: i64,
) -> Result<Vec<Record>, Error> {
    let rows = select(
        tx,
        "conversation_id = ?1 AND sent_at >= ?2 AND sent_at < ?3",
        params![conversation.as_bytes().as_slice(), from_ms, to_ms],
    )?;
    let mut records: Vec<Record> = rows.iter().filter_map(message_record).collect();
    records.extend(edit_records(
        tx,
        "e.sent_at >= ?2 AND e.sent_at < ?3",
        params![conversation.as_bytes().as_slice(), from_ms, to_ms],
    )?);
    sort(&mut records);
    Ok(records)
}

/// Which records of a conversation a package carries, with their authors' edits: what this device
/// shows of it (a share), or what it noted for one of its members (a catch-up, under the identity
/// it pins for them now).
pub(crate) enum Scope {
    Shown { conversation: Uuid },
    Noted { conversation: Uuid, user: Uuid },
}

/// Hands `each` the records of `scope` sent from `since` on (all of them, with none), one at a
/// time, oldest or newest first, in a package's order (by time, then number: every entry of a
/// conversation's queue has its own), until it answers false: what a package carries, read
/// without holding all of it. The records `records_for` and `noted_records` give, but of the edits
/// only those that count on this device (`refresh_text`), a sharer's only while the message has
/// none on its author's word: a package carries what it shows.
///
/// The indexes `messages_by_time` and `edits_by_time` give that order, so SQLite sorts nothing:
/// it reads no more rows than `each` takes, never the whole range at once.
pub(crate) fn each_record(
    tx: &Tx<'_>,
    scope: &Scope,
    since: Option<i64>,
    newest_first: bool,
    mut each: impl FnMut(Record) -> Result<bool, Error>,
) -> Result<(), Error> {
    let (conversation, user, messages, edits) = match scope {
        Scope::Shown { conversation } => (
            *conversation,
            Uuid::nil(),
            "m.conversation_id = ?1".to_string(),
            "e.conversation_id = ?1".to_string(),
        ),
        Scope::Noted { conversation, user } => (
            *conversation,
            *user,
            format!("m.conversation_id = ?1 AND m.id IN ({})", deviceless::NOTED),
            format!("e.conversation_id = ?1 AND m.id IN ({})", deviceless::NOTED),
        ),
    };
    let order = if newest_first { "DESC" } else { "ASC" };
    let mut statement = tx.conn().prepare(&format!(
        "SELECT 0, m.message_id, m.seq, m.user_id, m.device_id, m.sent_at, m.envelope, NULL, \
         m.shared_by, m.reply_to FROM messages m WHERE {messages} AND m.status = 'ok' \
         AND m.deleted = 0 AND m.message_id IS NOT NULL AND m.seq IS NOT NULL \
         AND m.envelope IS NOT NULL AND m.sent_at >= ?3 \
         UNION ALL \
         SELECT 1, e.message_id, e.seq, e.user_id, e.device_id, e.sent_at, NULL, e.text, \
         e.shared_by, NULL FROM edits e JOIN messages m ON m.message_id = e.message_id \
         AND m.conversation_id = e.conversation_id AND m.user_id = e.user_id \
         WHERE {edits} AND e.seq IS NOT NULL AND m.deleted = 0 AND m.status = 'ok' \
         AND (e.shared_by IS NULL OR e.shared_by = m.user_id OR (e.shared_by IS m.shared_by \
         AND NOT EXISTS (SELECT 1 FROM edits a WHERE a.message_id = e.message_id \
         AND a.conversation_id = e.conversation_id AND a.user_id = m.user_id \
         AND (a.shared_by IS NULL OR a.shared_by = m.user_id)))) \
         AND e.sent_at >= ?3 \
         ORDER BY 6 {order}, 3 {order}"
    ))?;
    let mut rows = statement.query(params![
        conversation.as_bytes().as_slice(),
        user.as_bytes().as_slice(),
        since.unwrap_or(i64::MIN)
    ])?;
    while let Some(row) = rows.next()? {
        let edit: bool = row.get(0)?;
        let id = stored_uuid(&row.get::<_, Vec<u8>>(1)?)?;
        let envelope = if edit {
            Envelope::Edit {
                message_id: id,
                text: row.get(7)?,
            }
            .encode()?
        } else {
            row.get(6)?
        };
        let uuid = |bytes: Option<Vec<u8>>| bytes.as_deref().map(stored_uuid).transpose();
        let record = Record {
            kind: if edit {
                RecordKind::Edit
            } else {
                RecordKind::Message
            },
            id,
            seq: u64::try_from(row.get::<_, i64>(2)?).map_err(|_| malformed())?,
            user: stored_uuid(&row.get::<_, Vec<u8>>(3)?)?,
            device: stored_uuid(&row.get::<_, Vec<u8>>(4)?)?,
            sent: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
            envelope,
            shared_by: uuid(row.get(8)?)?,
            reply_to: uuid(row.get(9)?)?,
        };
        if !each(record)? {
            break;
        }
    }
    Ok(())
}

/// A message's record, if it's one to carry: sent, shown and not deleted.
pub(super) fn message_record(row: &Row) -> Option<Record> {
    if row.deleted || row.status != Status::Ok {
        return None;
    }
    Some(Record {
        kind: RecordKind::Message,
        id: row.message_id?,
        seq: row.seq?,
        user: row.user,
        device: row.device,
        sent: u64::try_from(row.sent_at).unwrap_or(0),
        envelope: row.envelope.clone()?,
        shared_by: row.shared_by,
        reply_to: row.reply_to,
    })
}

/// The records of the edits `filter` selects (an SQL condition over `edits e` whose `?1` is the
/// conversation) that count: their author's, of a message this device shows, once the queue gave
/// them their number.
pub(super) fn edit_records(
    tx: &Tx<'_>,
    filter: &str,
    params: impl Params,
) -> Result<Vec<Record>, Error> {
    type Columns = (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64, String, Option<Vec<u8>>);
    let mut statement = tx.conn().prepare(&format!(
        "SELECT e.message_id, e.seq, e.user_id, e.device_id, e.sent_at, e.text, e.shared_by \
         FROM edits e JOIN messages m ON m.message_id = e.message_id \
         AND m.conversation_id = e.conversation_id AND m.user_id = e.user_id \
         WHERE e.conversation_id = ?1 AND e.seq IS NOT NULL AND m.deleted = 0 \
         AND m.status = 'ok' AND {filter}"
    ))?;
    let edits = statement
        .query_map(params, |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })?
        .collect::<Result<Vec<Columns>, _>>()?;
    edits
        .into_iter()
        .map(|(message, seq, user, device, sent, text, shared_by)| {
            let id = stored_uuid(&message)?;
            Ok(Record {
                kind: RecordKind::Edit,
                id,
                seq: u64::try_from(seq).map_err(|_| malformed())?,
                user: stored_uuid(&user)?,
                device: stored_uuid(&device)?,
                sent: u64::try_from(sent).unwrap_or(0),
                envelope: Envelope::Edit {
                    message_id: id,
                    text,
                }
                .encode()?,
                shared_by: shared_by.as_deref().map(stored_uuid).transpose()?,
                reply_to: None,
            })
        })
        .collect()
}

/// Records in the order they were sent.
pub(super) fn sort(records: &mut [Record]) {
    records.sort_by_key(|record| (record.sent, record.seq, record.kind == RecordKind::Edit));
}

/// Brings `records` of `conversation` in, from a backup or a history share (`shared_by`, who shared
/// them, else whoever the records say did). Nothing here is overwritten: a message this device has
/// stays as it is, but one that waits takes the record's content. A message deleted here stays
/// deleted, and an edit counts only from its message's author. How many records changed something.
pub fn import(
    tx: &Tx<'_>,
    conversation: Uuid,
    records: &[Record],
    shared_by: Option<Uuid>,
) -> Result<usize, Error> {
    let mut imported = 0;
    for record in records {
        let shared_by = shared_by.or(record.shared_by);
        let changed = match record.kind {
            RecordKind::Message => import_message(tx, conversation, record, shared_by, None)?,
            RecordKind::Edit => import_edit(tx, conversation, record, shared_by)?,
        };
        if changed {
            imported += 1;
        }
    }
    Ok(imported)
}

/// Brings in one `record` of `conversation` from a package `sharer` shared, marked as shared by
/// them: as [`import`] does, but a message that waits takes only a record whose user is its sender
/// as the API named them, a message record from its own author's package (`sharer` is its user)
/// replaces a copy another member shared of that author's message, and another member's edit counts
/// only on a copy that same member shared, whose text is already on their word and marked so, and
/// only while the message has no edit on its author's word (`refresh_text`). On a message this
/// device read itself, or another sharer's copy, it's dropped: it could put any text in its
/// author's name. Whether it changed something.
pub fn import_shared(
    tx: &Tx<'_>,
    conversation: Uuid,
    record: &Record,
    sharer: Uuid,
) -> Result<bool, Error> {
    match record.kind {
        RecordKind::Message => import_message(tx, conversation, record, Some(sharer), Some(sharer)),
        RecordKind::Edit if record.user != sharer => {
            let on_their_copy =
                by_message_id(tx, record.id)?.is_some_and(|row| row.shared_by == Some(sharer));
            if !on_their_copy {
                return Ok(false);
            }
            import_edit(tx, conversation, record, Some(sharer))
        }
        RecordKind::Edit => import_edit(tx, conversation, record, Some(sharer)),
    }
}

/// `package` is the sharer of the package the record came in, for [`import_shared`]'s rules.
fn import_message(
    tx: &Tx<'_>,
    conversation: Uuid,
    record: &Record,
    shared_by: Option<Uuid>,
    package: Option<Uuid>,
) -> Result<bool, Error> {
    let (Ok(Envelope::Message { text, attachments }), Ok(sent_at)) = (
        Envelope::decode(&record.envelope),
        i64::try_from(record.sent),
    ) else {
        return Ok(false);
    };
    if i64::try_from(record.seq).is_err() {
        return Ok(false);
    }
    let opened = Opened::new(record.envelope.clone(), text, &attachments);
    let id = match by_message_id(tx, record.id)? {
        None => insert(
            tx,
            NewRow {
                message_id: Some(record.id),
                nonce: None,
                conversation,
                seq: Some(record.seq),
                user: record.user,
                device: record.device,
                sent_at,
                opened: Some(&opened),
                status: Status::Ok,
                deleted: false,
                shared_by,
                reply_to: record.reply_to,
                imported: true,
            },
        )?,
        Some(row) if row.conversation != conversation => return Ok(false),
        // Deleted by its author: it stays deleted. A mark another user left wasn't a deletion.
        Some(row) if row.deleted && row.user == record.user => return Ok(false),
        // What waits is its sender's, as the API named them: a package fills it only as theirs.
        Some(row)
            if package.is_some() && row.status == Status::Waiting && row.user != record.user =>
        {
            return Ok(false);
        }
        // Its author's own package outweighs a copy another member shared of their message: a copy
        // of the same user's, as no package moves a message to another author.
        Some(row)
            if row.deleted
                || row.status == Status::Waiting
                || package.is_some_and(|sharer| {
                    sharer == record.user
                        && row.user == record.user
                        && row.shared_by.is_some_and(|by| by != sharer)
                }) =>
        {
            fill(
                tx,
                row.id,
                Filled {
                    seq: row.seq.or(Some(record.seq)),
                    user: record.user,
                    device: record.device,
                    sent_at,
                    opened: &opened,
                    shared_by,
                    reply_to: record.reply_to,
                    imported: true,
                },
            )?;
            row.id
        }
        Some(_) => return Ok(false),
    };
    refresh_text(tx, id)?;
    Ok(true)
}

fn import_edit(
    tx: &Tx<'_>,
    conversation: Uuid,
    record: &Record,
    shared_by: Option<Uuid>,
) -> Result<bool, Error> {
    let (Ok(Envelope::Edit { message_id, text }), Ok(seq), Ok(sent_at)) = (
        Envelope::decode(&record.envelope),
        i64::try_from(record.seq),
        i64::try_from(record.sent),
    ) else {
        return Ok(false);
    };
    if message_id != record.id {
        return Ok(false);
    }
    // An edit is known by its message, its number and its author: another user's row under the
    // same number neither stands in for the author's edit nor keeps it out. Nor does a copy another
    // member shared: only this device's own, or one the same package's sharer brought.
    let known: Option<i64> = tx
        .conn()
        .query_row(
            "SELECT id FROM edits WHERE conversation_id = ?1 AND message_id = ?2 AND seq = ?3 \
             AND user_id = ?4 AND (shared_by IS NULL OR shared_by IS ?5)",
            params![
                conversation.as_bytes().as_slice(),
                message_id.as_bytes().as_slice(),
                seq,
                record.user.as_bytes().as_slice(),
                shared_by.as_ref().map(|by| by.as_bytes().as_slice())
            ],
            |row| row.get(0),
        )
        .optional()?;
    if known.is_some() {
        return Ok(false);
    }
    let target = by_message_id(tx, message_id)?;
    match &target {
        Some(row) if row.conversation != conversation || row.deleted => return Ok(false),
        Some(row) if row.status != Status::Waiting && row.user != record.user => return Ok(false),
        _ => {}
    }
    add_edit(
        tx,
        NewEdit {
            conversation,
            message_id,
            seq: Some(record.seq),
            user: record.user,
            device: record.device,
            sent_at,
            text: &text,
            echo: None,
            shared_by,
        },
    )?;
    if let Some(row) = target {
        refresh_text(tx, row.id)?;
    }
    Ok(true)
}

/// A queue number as SQLite keeps it.
pub(crate) fn stored_seq(seq: u64) -> Result<i64, Error> {
    i64::try_from(seq).map_err(|_| Error::Internal("a message's number is out of range".into()))
}

pub(super) fn malformed() -> Error {
    Error::Internal("a stored message is malformed".into())
}
