//! What this device sends: a message (`encrypt`, then `sent` once the API has it), an edit of its
//! own and a deletion of its own. Each is kept here as it's made, before it leaves: once it's
//! encrypted, not even this device can open it.

use openmls::prelude::tls_codec::Serialize as _;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::store::{self, NewEdit, NewRow, Opened, Row, Status};
use super::{Content, Empty, MAX_CIPHERTEXT, NOT_AUTHOR, deviceless};
use crate::identity::{invalid, not_found};
use crate::protocol::b64;
use crate::{Envelope, Error, OwnDevice, Tx, mls};

/// The longest nonce the API keeps, in characters.
const MAX_NONCE: usize = 64;

#[derive(Debug, Deserialize)]
pub(crate) struct Encrypt {
    conversation_id: Uuid,
    /// The client's one-time name for this message, which a retry sends again.
    nonce: String,
    envelope: Content,
}

#[derive(Serialize)]
pub(crate) struct Encrypted {
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    generation: u32,
    epoch: u64,
    sender_device_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Sent {
    conversation_id: Uuid,
    nonce: String,
    /// The ID the API gave the message.
    message_id: Uuid,
    /// The message's number in the conversation's queue.
    seq: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Edit {
    conversation_id: Uuid,
    message_id: Uuid,
    text: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Delete {
    conversation_id: Uuid,
    message_id: Uuid,
}

#[derive(Serialize)]
pub(crate) struct Changed {
    #[serde(with = "b64")]
    ciphertext: Vec<u8>,
    generation: u32,
    epoch: u64,
}

/// A message in the conversation's group, for the API, kept here first as being sent (`pending`),
/// and in the outbox: a retry under the same nonce gets the same ciphertext, not encrypted again,
/// which the API knows by the nonce. The nonce is spent once the message comes back from the queue.
/// Before encrypting, what keeps this device from committing keeps it from sending
/// (`ready_to_send`). The message is noted then for the members without a device (`deviceless`).
pub(crate) fn encrypt(tx: &Tx<'_>, request: Encrypt) -> Result<Encrypted, Error> {
    let conversation = request.conversation_id;
    if request.nonce.is_empty() || request.nonce.chars().count() > MAX_NONCE {
        return Err(invalid("nonce", "a nonce has 1 to 64 characters"));
    }
    let envelope = request.envelope.into_envelope()?;
    let plain = envelope.encode()?;
    let own = tx.own_device()?;
    if let Some(row) = store::by_nonce(tx, &request.nonce)? {
        return retry(tx, &request.nonce, conversation, &row, &plain, &own);
    }
    let sealed = seal(tx, conversation, &own, &plain)?;
    tx.conn().execute(
        "INSERT INTO outbox (nonce, conversation_id, ciphertext, generation, epoch, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            request.nonce,
            conversation.as_bytes().as_slice(),
            sealed.ciphertext,
            sealed.generation,
            i64::try_from(sealed.epoch)
                .map_err(|_| Error::Internal("the group's epoch is out of range".into()))?,
            tx.now()
        ],
    )?;
    let Envelope::Message { text, attachments } = envelope else {
        return Err(Error::Internal(
            "a message's envelope isn't a message".into(),
        ));
    };
    let opened = Opened::new(plain, text, &attachments);
    let id = store::insert(
        tx,
        NewRow {
            message_id: None,
            nonce: Some(&request.nonce),
            conversation,
            seq: None,
            user: own.user,
            device: own.device,
            sent_at: tx.now(),
            opened: Some(&opened),
            status: Status::Pending,
            deleted: false,
            shared_by: None,
        },
    )?;
    // Noted as it leaves, for whoever has no device now: by the API's answer, the client may have
    // learned that one of theirs entered after it, which can't read it.
    deviceless::note(tx, conversation, id)?;
    Ok(Encrypted {
        ciphertext: sealed.ciphertext,
        generation: sealed.generation,
        epoch: sealed.epoch,
        sender_device_id: own.device,
    })
}

/// `encrypt` again under a nonce it took: the same ciphertext while the message waits in the outbox,
/// for the same message in the same conversation. Once its copy came back, the nonce is spent.
fn retry(
    tx: &Tx<'_>,
    nonce: &str,
    conversation: Uuid,
    row: &Row,
    plain: &[u8],
    own: &OwnDevice,
) -> Result<Encrypted, Error> {
    let waiting: Option<(Vec<u8>, i64, i64)> = tx
        .conn()
        .query_row(
            "SELECT ciphertext, generation, epoch FROM outbox WHERE nonce = ?1",
            [nonce],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((ciphertext, generation, epoch)) = waiting else {
        return Err(Error::Exists {
            what: "message".into(),
        });
    };
    if row.conversation != conversation || row.envelope.as_deref() != Some(plain) {
        return Err(invalid("nonce", "the nonce was used for another message"));
    }
    let stored = || Error::Internal("a message waiting to be sent is malformed".into());
    Ok(Encrypted {
        ciphertext,
        generation: u32::try_from(generation).map_err(|_| stored())?,
        epoch: u64::try_from(epoch).map_err(|_| stored())?,
        sender_device_id: own.device,
    })
}

/// The API's answer to a message this device sent: its ID and its number, bound to its nonce. The
/// same answer again changes nothing, and another is refused, as is the ID of another message.
pub(crate) fn sent(tx: &Tx<'_>, request: Sent) -> Result<Empty, Error> {
    if i64::try_from(request.seq).is_err() {
        return Err(invalid("seq", "the message's number is out of range"));
    }
    let row = store::by_nonce(tx, &request.nonce)?
        .filter(|row| row.conversation == request.conversation_id)
        .ok_or_else(|| not_found("message"))?;
    match row.message_id {
        None => {
            if !store::bind(tx, &row, Some(request.message_id), request.seq, None, &[])? {
                return Err(invalid("message_id", "another message has this ID"));
            }
        }
        Some(bound) if bound != request.message_id => {
            return Err(invalid(
                "message_id",
                "the message was sent under another ID",
            ));
        }
        Some(_) if row.seq != Some(request.seq) => {
            return Err(invalid("seq", "the message was sent under another number"));
        }
        Some(_) => {}
    }
    Ok(Empty {})
}

/// An edit of one of this device's user's messages, for the API, applied here at once: this device
/// can't open it when the queue brings it back. An edit to no text is for a message with files.
pub(crate) fn edit(tx: &Tx<'_>, request: Edit) -> Result<Changed, Error> {
    let conversation = request.conversation_id;
    let own = tx.own_device()?;
    let row = own_message(tx, conversation, request.message_id, &own)?;
    if row.deleted || row.status != Status::Ok {
        return Err(not_found("message"));
    }
    if request.text.is_empty() && row.attachments()?.is_empty() {
        return Err(invalid("text", "a message without files keeps some text"));
    }
    let plain = Envelope::Edit {
        message_id: request.message_id,
        text: request.text.clone(),
    }
    .encode()?;
    let sealed = seal(tx, conversation, &own, &plain)?;
    let echo = Sha256::digest(&sealed.ciphertext);
    store::add_edit(
        tx,
        NewEdit {
            conversation,
            message_id: request.message_id,
            seq: None,
            user: own.user,
            device: own.device,
            sent_at: tx.now(),
            text: &request.text,
            echo: Some(echo.as_slice()),
            shared_by: None,
        },
    )?;
    store::refresh_text(tx, row.id)?;
    deviceless::note(tx, conversation, row.id)?;
    Ok(sealed.changed())
}

/// A deletion of one of this device's user's messages for everyone, for the API, done here at once.
/// One deleted already can be sent again.
pub(crate) fn delete(tx: &Tx<'_>, request: Delete) -> Result<Changed, Error> {
    let conversation = request.conversation_id;
    let own = tx.own_device()?;
    let row = own_message(tx, conversation, request.message_id, &own)?;
    let plain = Envelope::Delete {
        message_id: request.message_id,
    }
    .encode()?;
    let sealed = seal(tx, conversation, &own, &plain)?;
    if !row.deleted {
        store::erase(tx, &row)?;
    }
    Ok(sealed.changed())
}

/// The message `message_id` of `conversation`, which must be this device's user's.
fn own_message(
    tx: &Tx<'_>,
    conversation: Uuid,
    message_id: Uuid,
    own: &OwnDevice,
) -> Result<Row, Error> {
    let row = store::by_message_id(tx, message_id)?
        .filter(|row| row.conversation == conversation)
        .ok_or_else(|| not_found("message"))?;
    if row.user != own.user {
        return Err(Error::RuleViolation {
            rule: NOT_AUTHOR.into(),
        });
    }
    Ok(row)
}

/// What `plain` is encrypted to in the group: the ciphertext, and the generation and epoch it's of.
struct Sealed {
    ciphertext: Vec<u8>,
    generation: u32,
    epoch: u64,
}

impl Sealed {
    fn changed(self) -> Changed {
        Changed {
            ciphertext: self.ciphertext,
            generation: self.generation,
            epoch: self.epoch,
        }
    }
}

/// Encrypts `plain` as an application message of the conversation's group, at its epoch, once this
/// device may send there. A ciphertext over 32 KiB is `too_large`, and nothing of it is kept.
fn seal(tx: &Tx<'_>, conversation: Uuid, own: &OwnDevice, plain: &[u8]) -> Result<Sealed, Error> {
    mls::ready_to_send(tx, conversation)?;
    let (mut group, row) = mls::load_group(tx, conversation)?;
    let message = group
        .create_message(tx.provider(), &own.signer, plain)
        .map_err(|error| Error::Internal(format!("MLS: {error}")))?;
    let ciphertext = message
        .tls_serialize_detached()
        .map_err(|_| Error::Internal("an MLS message couldn't be encoded".into()))?;
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Error::TooLarge {
            limit: MAX_CIPHERTEXT as u64,
        });
    }
    Ok(Sealed {
        ciphertext,
        generation: row.generation,
        epoch: group.epoch().as_u64(),
    })
}
