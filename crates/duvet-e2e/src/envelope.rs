//! The envelope: what a message of a conversation holds once MLS opens it, in CBOR. It takes one
//! of three forms:
//!
//! - a message, `{v: 1, text?, attachments?: [Attachment]}`, with text or at least one file;
//! - an edit, `{v: 1, edit: message_id, text}`;
//! - a deletion, `{v: 1, delete: message_id}`.
//!
//! Nothing else reads: another `v`, a field v1 doesn't have, or two forms at once.

use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::Error;
use crate::identity::{from_cbor, invalid, to_cbor};

/// The largest envelope: it rides in a message's ciphertext, which holds 32 KiB at most.
pub const MAX_ENVELOPE: usize = 32 * 1024;

/// The largest thumbnail a message carries inside it; a bigger one is a file of its own.
pub const MAX_THUMBNAIL: usize = 8 * 1024;

/// What a message of a conversation holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Envelope {
    /// A message: its text, its files, or both.
    Message {
        text: Option<String>,
        attachments: Vec<Attachment>,
    },
    /// New text for one of the author's messages: none, when it clears a file's caption.
    Edit { message_id: Uuid, text: String },
    /// One of the author's messages, deleted for everyone.
    Delete { message_id: Uuid },
}

/// A file a message carries: which one, the key its parts open with, and what it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    /// The ID the file was uploaded under, which binds its parts.
    pub id: Uuid,
    /// The key its parts are sealed with, drawn for this file alone.
    #[serde(with = "secret_key")]
    pub key: Zeroizing<[u8; 32]>,
    /// The SHA-256 of the file as it was, which the client checks once it has it whole.
    #[serde(with = "serde_bytes")]
    pub sha256: [u8; 32],
    pub name: String,
    /// Its MIME type.
    #[serde(rename = "type")]
    pub content_type: String,
    /// Its size before it was encrypted, in bytes.
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// A voice note's waveform.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub waveform: Option<Vec<u8>>,
    /// Its thumbnail, inside the message: 8 KiB at most.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub thumbnail: Option<Vec<u8>>,
    /// Its thumbnail as a file of its own, when it's bigger.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thumbnail_ref: Option<ThumbnailRef>,
}

/// A thumbnail too big to ride inside its message: a second encrypted file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThumbnailRef {
    pub id: Uuid,
    #[serde(with = "secret_key")]
    pub key: Zeroizing<[u8; 32]>,
    #[serde(with = "serde_bytes")]
    pub sha256: [u8; 32],
    pub size: u64,
}

impl Envelope {
    /// The envelope's bytes. One the format doesn't allow gives `bad_command` (field
    /// `envelope`), and one over 32 KiB `too_large`.
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.check().map_err(|reason| invalid("envelope", reason))?;
        let bytes = to_cbor(&self.wire())?;
        if bytes.len() > MAX_ENVELOPE {
            return Err(too_large());
        }
        Ok(bytes)
    }

    /// The envelope `bytes` hold. Anything but exactly one form of v1 gives `decrypt_failed`
    /// (kind `envelope`), and more than 32 KiB `too_large`, before a byte of it is read.
    pub fn decode(bytes: &[u8]) -> Result<Envelope, Error> {
        if bytes.len() > MAX_ENVELOPE {
            return Err(too_large());
        }
        from_cbor::<Wire<'static>>(bytes)
            .and_then(Wire::into_envelope)
            .filter(|envelope| envelope.check().is_ok())
            .ok_or_else(|| Error::DecryptFailed {
                kind: "envelope".into(),
            })
    }

    /// Why the format doesn't allow this envelope, if it doesn't.
    fn check(&self) -> Result<(), &'static str> {
        match self {
            Envelope::Message { text, attachments } => {
                if text.as_deref() == Some("") {
                    return Err("a message without text leaves the text field out");
                }
                if text.is_none() && attachments.is_empty() {
                    return Err("a message has text or a file");
                }
                attachments.iter().try_for_each(Attachment::check)
            }
            Envelope::Edit { .. } | Envelope::Delete { .. } => Ok(()),
        }
    }

    fn wire(&self) -> Wire<'_> {
        let none: &[Attachment] = &[];
        let (text, attachments, edit, delete) = match self {
            Envelope::Message { text, attachments } => {
                (text.as_deref(), attachments.as_slice(), None, None)
            }
            Envelope::Edit { message_id, text } => {
                (Some(text.as_str()), none, Some(*message_id), None)
            }
            Envelope::Delete { message_id } => (None, none, None, Some(*message_id)),
        };
        Wire {
            v: 1,
            text: text.map(Cow::Borrowed),
            attachments: (!attachments.is_empty()).then_some(Cow::Borrowed(attachments)),
            edit,
            delete,
        }
    }
}

impl Attachment {
    fn check(&self) -> Result<(), &'static str> {
        match &self.thumbnail {
            Some(thumbnail) if thumbnail.len() > MAX_THUMBNAIL => {
                Err("a thumbnail inside a message is 8 KiB at most")
            }
            Some(_) if self.thumbnail_ref.is_some() => {
                Err("a thumbnail is inside the message or apart, not both")
            }
            _ => Ok(()),
        }
    }
}

/// An envelope as its CBOR holds it: every form's fields, each optional.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire<'a> {
    v: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    text: Option<Cow<'a, str>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachments: Option<Cow<'a, [Attachment]>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    edit: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delete: Option<Uuid>,
}

impl Wire<'_> {
    /// The one form the fields make, when they make exactly one. A list of files is never
    /// empty: a message without files has none.
    fn into_envelope(self) -> Option<Envelope> {
        if self.v != 1
            || self
                .attachments
                .as_ref()
                .is_some_and(|files| files.is_empty())
        {
            return None;
        }
        match (self.edit, self.delete, self.text, self.attachments) {
            (None, None, text, attachments) => Some(Envelope::Message {
                text: text.map(Cow::into_owned),
                attachments: attachments.map(Cow::into_owned).unwrap_or_default(),
            }),
            (Some(message_id), None, Some(text), None) => Some(Envelope::Edit {
                message_id,
                text: text.into_owned(),
            }),
            (None, Some(message_id), None, None) => Some(Envelope::Delete { message_id }),
            _ => None,
        }
    }
}

fn too_large() -> Error {
    Error::TooLarge {
        limit: MAX_ENVELOPE as u64,
    }
}

/// A key in CBOR: its 32 bytes, kept where they're wiped as they drop.
mod secret_key {
    use serde::{Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub(super) fn serialize<S: Serializer>(
        key: &Zeroizing<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(key.as_slice())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        serde_bytes::deserialize(deserializer).map(Zeroizing::new)
    }
}
