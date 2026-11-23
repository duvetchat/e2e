//! Members without a device: a member whose devices all left, or who never had one, can't read what
//! the group carries meanwhile. This device notes for them what it sends in that time, under the
//! identity it had pinned for them then (none, if it had none). Once a device of theirs enters the
//! group (another device's commit brings its leaf), or the client no longer counts them as without
//! one, they're due a catch-up with what was noted, which `apply` names (`catch_up_due`) until the
//! catch-up empties the note. A catch-up goes only to the identity the note was made for, or to any
//! when none was pinned then: a new identity of theirs gets none of what was sent before it.

use std::collections::BTreeSet;

use duvet_e2e_rules::{DeviceCertificate, NewLeaf};
use rusqlite::params;
use serde::Deserialize;
use uuid::Uuid;

use super::store::{edit_records, message_record, select, sort};
use super::{Empty, Record};
use crate::identity::{invalid, not_found, stored_uuid};
use crate::mls::GroupRow;
use crate::{Error, Tx};

/// The noted messages whose identity is the one now pinned for their user, or none.
const NOTED: &str = "SELECT d.message FROM deviceless d LEFT JOIN contacts c ON c.user_id = d.user_id \
     WHERE d.conversation_id = ?1 AND d.user_id = ?2 \
     AND (d.identity_key IS NULL OR d.identity_key = c.identity_key)";

/// The messages a catch-up can carry, as `message_record` makes their records: shown, not deleted,
/// with the API's ID and number. One still waiting for the API's answer isn't one yet.
const CARRIED: &str = "SELECT id FROM messages WHERE status = 'ok' AND deleted = 0 \
     AND message_id IS NOT NULL AND seq IS NOT NULL AND envelope IS NOT NULL";

#[derive(Debug, Deserialize)]
pub(crate) struct WithoutDevices {
    conversation_id: Uuid,
    /// The conversation's members who have no device now, as the API says: all of them.
    users: Vec<Uuid>,
}

/// The members of a conversation who have no device now, as the client learns it from the API. It
/// replaces what this device was told before; what it already noted stays for their catch-up.
pub(crate) fn without_devices(tx: &Tx<'_>, request: WithoutDevices) -> Result<Empty, Error> {
    let conversation = request.conversation_id;
    let row = GroupRow::read(tx, conversation)?.ok_or_else(|| not_found("group"))?;
    let own = tx.own_user()?;
    for &user in &request.users {
        if Some(user) == own {
            return Err(invalid("users", "this device's own user has a device"));
        }
        if !row.members.contains(user) {
            return Err(not_found("member"));
        }
    }
    tx.conn().execute(
        "DELETE FROM deviceless_users WHERE conversation_id = ?1",
        [conversation.as_bytes().as_slice()],
    )?;
    for user in &request.users {
        tx.conn().execute(
            "INSERT OR IGNORE INTO deviceless_users (conversation_id, user_id) VALUES (?1, ?2)",
            params![
                conversation.as_bytes().as_slice(),
                user.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(Empty {})
}

/// Notes the message `message` (its row) of `conversation`, which this device sent, for every member
/// without a device there now, with the identity it has pinned for each.
pub(crate) fn note(tx: &Tx<'_>, conversation: Uuid, message: i64) -> Result<(), Error> {
    tx.conn().execute(
        "INSERT OR IGNORE INTO deviceless (conversation_id, user_id, message, identity_key) \
         SELECT u.conversation_id, u.user_id, ?2, c.identity_key FROM deviceless_users u \
         LEFT JOIN contacts c ON c.user_id = u.user_id WHERE u.conversation_id = ?1",
        params![conversation.as_bytes().as_slice(), message],
    )?;
    Ok(())
}

/// The leaves a commit brought into `conversation`'s group: their users have a device there now.
pub(crate) fn entered(tx: &Tx<'_>, conversation: Uuid, leaves: &[NewLeaf]) -> Result<(), Error> {
    let users: BTreeSet<Uuid> = leaves
        .iter()
        .filter_map(|leaf| DeviceCertificate::read_unverified(&leaf.credential).ok())
        .map(|certificate| certificate.user)
        .collect();
    for user in users {
        tx.conn().execute(
            "DELETE FROM deviceless_users WHERE conversation_id = ?1 AND user_id = ?2",
            params![
                conversation.as_bytes().as_slice(),
                user.as_bytes().as_slice()
            ],
        )?;
    }
    Ok(())
}

/// The members of the conversation (`row`, as this device holds it) due a catch-up: a device of
/// theirs is here now, and this device noted for them, under the identity they have, a message a
/// catch-up can carry. One still waiting for the API's answer makes them due once it has it.
pub(crate) fn catch_up_due(
    tx: &Tx<'_>,
    conversation: Uuid,
    row: Option<&GroupRow>,
) -> Result<Vec<Uuid>, Error> {
    let Some(row) = row else {
        return Ok(Vec::new());
    };
    let mut statement = tx.conn().prepare(&format!(
        "SELECT DISTINCT d.user_id FROM deviceless d LEFT JOIN contacts c ON c.user_id = d.user_id \
         WHERE d.conversation_id = ?1 \
         AND (d.identity_key IS NULL OR d.identity_key = c.identity_key) \
         AND d.message IN ({CARRIED}) \
         AND NOT EXISTS (SELECT 1 FROM deviceless_users u \
             WHERE u.conversation_id = d.conversation_id AND u.user_id = d.user_id) \
         ORDER BY d.user_id"
    ))?;
    let users = statement
        .query_map([conversation.as_bytes().as_slice()], |row| {
            row.get::<_, Vec<u8>>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut due = Vec::new();
    for user in users {
        let user = stored_uuid(&user)?;
        if row.members.contains(user) {
            due.push(user);
        }
    }
    Ok(due)
}

/// What this device noted for `user` in `conversation` under the identity it has pinned for them now
/// (or before it pinned any), for their catch-up: the messages, as they were sent, and their
/// authors' edits. One deleted since isn't there.
pub fn noted_records(tx: &Tx<'_>, conversation: Uuid, user: Uuid) -> Result<Vec<Record>, Error> {
    let rows = select(
        tx,
        &format!("id IN ({NOTED})"),
        params![
            conversation.as_bytes().as_slice(),
            user.as_bytes().as_slice()
        ],
    )?;
    let mut records: Vec<Record> = rows.iter().filter_map(message_record).collect();
    records.extend(edit_records(
        tx,
        &format!("m.id IN ({NOTED})"),
        params![
            conversation.as_bytes().as_slice(),
            user.as_bytes().as_slice()
        ],
    )?);
    sort(&mut records);
    Ok(records)
}

/// Empties what this device noted for `user` in `conversation` that a catch-up can carry, once
/// their catch-up is made: they're no longer due one. A message still waiting for the API's
/// answer, which no catch-up had, keeps its note for the next.
pub fn forget_noted(tx: &Tx<'_>, conversation: Uuid, user: Uuid) -> Result<(), Error> {
    tx.conn().execute(
        &format!(
            "DELETE FROM deviceless WHERE conversation_id = ?1 AND user_id = ?2 \
             AND message IN ({CARRIED})"
        ),
        params![
            conversation.as_bytes().as_slice(),
            user.as_bytes().as_slice()
        ],
    )?;
    Ok(())
}
