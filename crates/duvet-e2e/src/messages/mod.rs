//! A conversation's messages: what this device sends (`encrypt`, then `sent` once the API has it),
//! its edits and deletions (`edit`, `delete`), what the queue brings (the `message`, `edit` and
//! `delete` entries `apply` hands `Messages`), the local history (`messages`) and its search, and
//! the members without a device for whom this device notes what it sends.
//!
//! What MLS opens is kept in the same transaction as the group state that opened it: OpenMLS drops
//! each key as it uses it, so a message opened and not kept would be lost for good. Nor can this
//! device open what it sends itself: it keeps its own messages, edits and deletions as it makes
//! them, and knows them by their ciphertext when the queue brings them back.

mod deviceless;
mod receive;
mod search;
mod send;
mod store;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::invalid;
use crate::protocol::b64;
use crate::{Attachment, Envelope, Error, ThumbnailRef};

pub(crate) use deviceless::{WithoutDevices, catch_up_due, entered, without_devices};
pub use deviceless::{forget_noted, noted_records};
pub(crate) use receive::Messages;
pub(crate) use search::{Search, search};
pub(crate) use send::{Delete, Discard, Edit, Encrypt, Sent, delete, discard, edit, encrypt, sent};
pub(crate) use store::{ListMessages, messages};
pub use store::{import, records_for};

/// The largest ciphertext of a message, an edit or a deletion: 32 KiB.
pub const MAX_CIPHERTEXT: usize = 32 * 1024;

/// What refuses an edit or a deletion of another user's message.
const NOT_AUTHOR: &str = "not_author";

/// A message or an edit as a backup's segment and a history share carry it, in CBOR.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub kind: RecordKind,
    /// The message's ID; an edit's is the ID of the message it edits.
    pub id: Uuid,
    /// Its number in the conversation's queue.
    pub seq: u64,
    pub user: Uuid,
    pub device: Uuid,
    /// When the API took it, in Unix milliseconds.
    pub sent: u64,
    /// Its envelope: the message as it was sent, or the edit.
    #[serde(with = "serde_bytes")]
    pub envelope: Vec<u8>,
    /// Who shared it with this device, when a history share brought it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_by: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    Message,
    Edit,
}

/// A command's empty reply: `{}`.
#[derive(Serialize)]
pub(crate) struct Empty {}

/// A message's content as the JSON protocol carries it: what `encrypt` takes. Its binary fields
/// are base64.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Content {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    attachments: Vec<File>,
}

impl Content {
    /// The message's envelope. The format's own rules are `Envelope::encode`'s.
    fn into_envelope(self) -> Result<Envelope, Error> {
        let attachments = self
            .attachments
            .into_iter()
            .map(File::into_attachment)
            .collect::<Result<_, _>>()?;
        Ok(Envelope::Message {
            text: self.text,
            attachments,
        })
    }
}

/// A file a message carries, as `encrypt` takes it and `messages` and `search` show it.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct File {
    id: Uuid,
    #[serde(
        serialize_with = "b64::serialize",
        deserialize_with = "b64::secret::deserialize"
    )]
    key: Zeroizing<Vec<u8>>,
    #[serde(with = "b64")]
    sha256: Vec<u8>,
    name: String,
    #[serde(rename = "type")]
    content_type: String,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(default, with = "b64::option", skip_serializing_if = "Option::is_none")]
    waveform: Option<Vec<u8>>,
    #[serde(default, with = "b64::option", skip_serializing_if = "Option::is_none")]
    thumbnail: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    thumbnail_ref: Option<FileRef>,
}

/// A thumbnail that is a file of its own.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FileRef {
    id: Uuid,
    #[serde(
        serialize_with = "b64::serialize",
        deserialize_with = "b64::secret::deserialize"
    )]
    key: Zeroizing<Vec<u8>>,
    #[serde(with = "b64")]
    sha256: Vec<u8>,
    size: u64,
}

impl File {
    fn into_attachment(self) -> Result<Attachment, Error> {
        Ok(Attachment {
            id: self.id,
            key: key(&self.key)?,
            sha256: sha256(&self.sha256)?,
            name: self.name,
            content_type: self.content_type,
            size: self.size,
            width: self.width,
            height: self.height,
            duration_ms: self.duration_ms,
            waveform: self.waveform,
            thumbnail: self.thumbnail,
            thumbnail_ref: self
                .thumbnail_ref
                .map(|thumbnail| {
                    Ok::<_, Error>(ThumbnailRef {
                        id: thumbnail.id,
                        key: key(&thumbnail.key)?,
                        sha256: sha256(&thumbnail.sha256)?,
                        size: thumbnail.size,
                    })
                })
                .transpose()?,
        })
    }
}

impl From<Attachment> for File {
    fn from(attachment: Attachment) -> File {
        File {
            id: attachment.id,
            key: Zeroizing::new(attachment.key.to_vec()),
            sha256: attachment.sha256.to_vec(),
            name: attachment.name,
            content_type: attachment.content_type,
            size: attachment.size,
            width: attachment.width,
            height: attachment.height,
            duration_ms: attachment.duration_ms,
            waveform: attachment.waveform,
            thumbnail: attachment.thumbnail,
            thumbnail_ref: attachment.thumbnail_ref.map(|thumbnail| FileRef {
                id: thumbnail.id,
                key: Zeroizing::new(thumbnail.key.to_vec()),
                sha256: thumbnail.sha256.to_vec(),
                size: thumbnail.size,
            }),
        }
    }
}

fn key(key: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut sized = Zeroizing::new([0; 32]);
    if key.len() != sized.len() {
        return Err(invalid("envelope", "a file's key is 32 bytes"));
    }
    sized.copy_from_slice(key);
    Ok(sized)
}

fn sha256(hash: &[u8]) -> Result<[u8; 32], Error> {
    hash.try_into()
        .map_err(|_| invalid("envelope", "a file's SHA-256 is 32 bytes"))
}
