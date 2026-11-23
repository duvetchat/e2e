//! The messages, edits and deletions a conversation's queue brings. Another device's are opened and
//! kept in the transaction that moved the group's state on; this device's own come back as its own,
//! known by their ciphertext. One that can't be opened is kept as waiting, for an import to replace.

use duvet_e2e_rules::{DeviceCertificate, group_id_parts};
use openmls::prelude::{BasicCredential, Credential, ProcessMessageError, ProcessedMessageContent};
use rusqlite::{OptionalExtension, params};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::store::{self, Filled, NewEdit, NewRow, Opened, Status};
use super::{MAX_CIPHERTEXT, NOT_AUTHOR};
use crate::mls::apply::{
    Applied, Conversation, Entry, EntryHandler, EntryKind, protocol_message, rejected,
};
use crate::{Envelope, Error, Tx};

/// What can't be opened: a message MLS refused, one whose plaintext isn't an envelope, one beyond
/// 32 KiB, which isn't read.
const MESSAGE: &str = "message";
const ENVELOPE: &str = "envelope";
const TOO_LARGE: &str = "too_large";

/// The handler of the queue's `message`, `edit` and `delete` entries.
pub(crate) struct Messages;

impl EntryHandler for Messages {
    fn apply(&self, tx: &Tx<'_>, at: &mut Conversation, entry: &Entry) -> Result<Applied, Error> {
        // Out of the group, there's nothing to open it with.
        let (Some(row), Some(group)) = (at.row.as_ref(), at.group.as_mut()) else {
            return Ok(Applied::Ignored);
        };
        let conversation = at.id;
        if entry.data.len() > MAX_CIPHERTEXT {
            return undecryptable(tx, conversation, entry, TOO_LARGE);
        }
        if let Some(own) = own_echo(tx, conversation, entry)? {
            return Ok(own);
        }
        let Some(message) = protocol_message(&entry.data) else {
            return undecryptable(tx, conversation, entry, MESSAGE);
        };
        match group_id_parts(message.group_id()) {
            Ok((other, _)) if other != conversation => return Ok(rejected("wrong_group")),
            // Another generation's: one before a reset, or one this device hasn't joined.
            Ok((_, generation)) if generation == row.generation => {}
            _ => return undecryptable(tx, conversation, entry, MESSAGE),
        }
        let processed = match group.process_message(tx.provider(), message) {
            Ok(processed) => processed,
            Err(ProcessMessageError::StorageError(error)) => {
                return Err(Error::Storage(error.to_string()));
            }
            Err(_) => return undecryptable(tx, conversation, entry, MESSAGE),
        };
        let credential = processed.credential().clone();
        let plain = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
            // One this device sent, which it kept as it made it.
            ProcessedMessageContent::OwnPrivateMessage => return Ok(Applied::Own),
            // A commit or a proposal, which isn't a message.
            _ => return Ok(rejected("malformed")),
        };
        let (user, device) = sender(&credential)?;
        let Ok(envelope) = Envelope::decode(&plain) else {
            return undecryptable(tx, conversation, entry, ENVELOPE);
        };
        let applied = Applied::Done {
            epoch: group.epoch().as_u64(),
        };
        let from = Received {
            conversation,
            entry,
            user,
            device,
            sent_at: entry.sent_at.unwrap_or(tx.now()),
        };
        match envelope {
            Envelope::Message { text, attachments } => {
                let opened = Opened::new(plain, text, &attachments);
                keep_message(tx, &from, &opened, applied)
            }
            Envelope::Edit { message_id, text } => keep_edit(tx, &from, message_id, &text, applied),
            Envelope::Delete { message_id } => keep_delete(tx, &from, message_id, applied),
        }
    }
}

/// An entry as it was opened: its conversation, and the device MLS says sent it.
struct Received<'a> {
    conversation: Uuid,
    entry: &'a Entry,
    user: Uuid,
    device: Uuid,
    sent_at: i64,
}

/// The user and the device of a member's leaf: its certificate, checked as the leaf entered.
fn sender(credential: &Credential) -> Result<(Uuid, Uuid), Error> {
    let certificate = BasicCredential::try_from(credential.clone())
        .ok()
        .and_then(|basic| DeviceCertificate::read_unverified(basic.identity()).ok())
        .ok_or_else(|| Error::Internal("a stored group isn't one of Duvet's".into()))?;
    Ok((certificate.user, certificate.device))
}

/// Another device's message: kept. What waited for it, a copy an import brought first, or the mark
/// of a deletion that wasn't its author's, take its content; edits that waited for it apply.
fn keep_message(
    tx: &Tx<'_>,
    from: &Received<'_>,
    opened: &Opened,
    applied: Applied,
) -> Result<Applied, Error> {
    let entry = from.entry;
    let known = match entry.message_id {
        Some(message_id) => store::by_message_id(tx, message_id)?,
        None => None,
    };
    let filled = |id| {
        store::fill(
            tx,
            id,
            Filled {
                seq: Some(entry.seq),
                user: from.user,
                device: from.device,
                sent_at: from.sent_at,
                opened,
                shared_by: None,
            },
        )
    };
    let id = match known {
        None => store::insert(
            tx,
            NewRow {
                message_id: entry.message_id,
                nonce: None,
                conversation: from.conversation,
                seq: Some(entry.seq),
                user: from.user,
                device: from.device,
                sent_at: from.sent_at,
                opened: Some(opened),
                status: Status::Ok,
                deleted: false,
                shared_by: None,
            },
        )?,
        Some(row) if row.conversation != from.conversation => return Ok(rejected("wrong_group")),
        Some(row) if row.deleted && row.user == from.user => return Ok(Applied::Ignored),
        Some(row) if row.deleted || row.status == Status::Waiting || row.shared_by.is_some() => {
            filled(row.id)?;
            row.id
        }
        Some(_) => return Ok(Applied::Ignored),
    };
    store::set_mentions(tx, id, &entry.mentions)?;
    store::refresh_text(tx, id)?;
    Ok(applied)
}

/// An edit counts from its message's author alone. One of a message this device can't read yet
/// waits for it, and counts if its author made it.
fn keep_edit(
    tx: &Tx<'_>,
    from: &Received<'_>,
    message_id: Uuid,
    text: &str,
    applied: Applied,
) -> Result<Applied, Error> {
    let target = store::by_message_id(tx, message_id)?;
    match &target {
        Some(row) if row.conversation != from.conversation => return Ok(rejected("wrong_group")),
        Some(row) if row.deleted => return Ok(Applied::Ignored),
        Some(row) if row.status != Status::Waiting && row.user != from.user => {
            return Ok(rejected(NOT_AUTHOR));
        }
        _ => {}
    }
    store::add_edit(
        tx,
        NewEdit {
            conversation: from.conversation,
            message_id,
            seq: Some(from.entry.seq),
            user: from.user,
            device: from.device,
            sent_at: from.sent_at,
            text,
            echo: None,
            shared_by: None,
        },
    )?;
    if let Some(row) = target {
        store::refresh_text(tx, row.id)?;
    }
    Ok(applied)
}

/// A deletion counts from its message's author alone: the message's text, file and edits go. One of
/// a message this device hasn't got leaves a mark, so nothing brings that message in later.
fn keep_delete(
    tx: &Tx<'_>,
    from: &Received<'_>,
    message_id: Uuid,
    applied: Applied,
) -> Result<Applied, Error> {
    match store::by_message_id(tx, message_id)? {
        Some(row) if row.conversation != from.conversation => Ok(rejected("wrong_group")),
        Some(row) if row.deleted => Ok(Applied::Ignored),
        Some(row) if row.user != from.user => Ok(rejected(NOT_AUTHOR)),
        Some(row) => {
            store::erase(tx, &row)?;
            Ok(applied)
        }
        None => {
            store::insert(
                tx,
                NewRow {
                    message_id: Some(message_id),
                    nonce: None,
                    conversation: from.conversation,
                    seq: None,
                    user: from.user,
                    device: from.device,
                    sent_at: from.sent_at,
                    opened: None,
                    status: Status::Ok,
                    deleted: true,
                    shared_by: None,
                },
            )?;
            store::forget_edits(tx, from.conversation, message_id)?;
            Ok(applied)
        }
    }
}

/// An entry this device can't open. A message is kept as waiting, with the ID, the sender and the
/// time the API gives, unless the device has it already.
fn undecryptable(
    tx: &Tx<'_>,
    conversation: Uuid,
    entry: &Entry,
    reason: &'static str,
) -> Result<Applied, Error> {
    if entry.kind == EntryKind::Message
        && let Some(message_id) = entry.message_id
        && store::by_message_id(tx, message_id)?.is_none()
    {
        let id = store::insert(
            tx,
            NewRow {
                message_id: Some(message_id),
                nonce: None,
                conversation,
                seq: Some(entry.seq),
                user: entry.sender_user.unwrap_or_default(),
                device: entry.sender_device.unwrap_or_default(),
                sent_at: entry.sent_at.unwrap_or(tx.now()),
                opened: None,
                status: Status::Waiting,
                deleted: false,
                shared_by: None,
            },
        )?;
        store::set_mentions(tx, id, &entry.mentions)?;
    }
    Ok(Applied::Undecryptable { reason })
}

/// This device's own message or edit, back from the queue: known by its ciphertext, which MLS
/// wouldn't open for it. A message takes the ID, the number and the time the API gave it, unless
/// that ID can't be its own (`store::bind`): then its rows stay as they are, and the copy is still
/// its own.
fn own_echo(tx: &Tx<'_>, conversation: Uuid, entry: &Entry) -> Result<Option<Applied>, Error> {
    let nonce: Option<String> = tx
        .conn()
        .query_row(
            "SELECT nonce FROM outbox WHERE conversation_id = ?1 AND ciphertext = ?2",
            params![conversation.as_bytes().as_slice(), entry.data.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(nonce) = nonce {
        if let Some(row) = store::by_nonce(tx, &nonce)? {
            store::bind(
                tx,
                &row,
                entry.message_id,
                entry.seq,
                entry.sent_at,
                &entry.mentions,
            )?;
        }
        tx.conn()
            .execute("DELETE FROM outbox WHERE nonce = ?1", [&nonce])?;
        return Ok(Some(Applied::Own));
    }
    let echo = Sha256::digest(&entry.data);
    if let Some(message_id) =
        store::echo_edit(tx, conversation, echo.as_slice(), entry.seq, entry.sent_at)?
    {
        if let Some(row) = store::by_message_id(tx, message_id)? {
            store::refresh_text(tx, row.id)?;
        }
        return Ok(Some(Applied::Own));
    }
    Ok(None)
}
