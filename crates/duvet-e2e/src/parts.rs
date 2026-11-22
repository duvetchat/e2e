//! The encrypted parts of attachments and history packages. A file, or a package, is cut in parts
//! of one size, each sealed on its own with AES-256-GCM under a key drawn for that file alone, so
//! it opens part by part as it downloads:
//!
//! - the nonce is `00 00 00 || index (u64, big-endian) || 01` on the last part and `00` on the
//!   others, so parts can't trade places and a file cut short at a part's end doesn't open;
//! - the associated data is the file's or the package's 16-byte ID, so no part passes for
//!   another file's;
//! - every part but the last is whole, the last holds the rest, and an empty file is one empty
//!   last part.
//!
//! A key seals one file: other bytes sealed at the same index under it would reuse a nonce.

use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::{invalid, random};
use crate::protocol::b64;
use crate::{Error, Tx};

/// The plaintext an attachment's part holds: 64 KiB.
pub const ATTACHMENT_PART: usize = 65_536;

/// The plaintext a history package's part holds: 1 MiB.
pub const PACKAGE_PART: usize = 1_048_576;

/// What sealing adds to each part: AES-GCM's tag.
pub const TAG: usize = 16;

/// Part `index` of a file or package, its last one when `last`, sealed with the file's key and
/// bound to its ID. `plain` is one part: AES-GCM refuses nothing under 64 GiB.
pub fn seal_part(key: &[u8; 32], id: Uuid, index: u64, last: bool, plain: &[u8]) -> Vec<u8> {
    Aes256Gcm::new(key.into())
        .encrypt(
            &nonce(index, last),
            Payload {
                msg: plain,
                aad: id.as_bytes(),
            },
        )
        .expect("AES-GCM seals anything under 64 GiB")
}

/// The plaintext of a part `seal_part` sealed with the same key, ID, index and place. Anything
/// else gives `decrypt_failed`, of kind `attachment`.
pub fn open_part(
    key: &[u8; 32],
    id: Uuid,
    index: u64,
    last: bool,
    sealed: &[u8],
) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new(key.into())
        .decrypt(
            &nonce(index, last),
            Payload {
                msg: sealed,
                aad: id.as_bytes(),
            },
        )
        .map_err(|_| failed())
}

/// `00 00 00 || index (u64, big-endian) || 01` on the last part, `00` on the others.
fn nonce(index: u64, last: bool) -> Nonce<Aes256Gcm> {
    let mut nonce = [0u8; 12];
    nonce[3..11].copy_from_slice(&index.to_be_bytes());
    nonce[11] = u8::from(last);
    nonce.into()
}

/// Whether `len` bytes of plaintext have their place at part `index`, the last one when `last`,
/// of something cut in parts of `part_size`: every part but the last is whole, the last holds
/// the rest, and only an empty file's one part is empty.
pub(crate) fn fits(part_size: usize, index: u64, last: bool, len: usize) -> bool {
    if last {
        len <= part_size && (len > 0 || index == 0)
    } else {
        len == part_size
    }
}

fn failed() -> Error {
    Error::DecryptFailed {
        kind: "attachment".into(),
    }
}

/// A part of an attachment, as `attachment_encrypt` and `attachment_decrypt` take it.
#[derive(Debug, Deserialize)]
pub(crate) struct AttachmentPart {
    #[serde(with = "b64::secret")]
    key: Zeroizing<Vec<u8>>,
    attachment_id: Uuid,
    index: u64,
    last: bool,
    #[serde(with = "b64")]
    data: Vec<u8>,
}

impl AttachmentPart {
    fn key(&self) -> Result<&[u8; 32], Error> {
        self.key
            .as_slice()
            .try_into()
            .map_err(|_| invalid("key", "the key is 32 bytes"))
    }
}

#[derive(Serialize)]
pub(crate) struct AttachmentKey {
    #[serde(with = "b64")]
    key: Zeroizing<Vec<u8>>,
}

#[derive(Serialize)]
pub(crate) struct Data {
    #[serde(with = "b64")]
    data: Vec<u8>,
}

/// A new key, for one file.
pub(crate) fn attachment_key(tx: &Tx<'_>) -> Result<AttachmentKey, Error> {
    Ok(AttachmentKey {
        key: random(tx.provider().rand(), 32)?,
    })
}

/// A part of a file, sealed: 64 KiB of it at most, and all of that in every part but the last.
pub(crate) fn attachment_encrypt(part: AttachmentPart) -> Result<Data, Error> {
    let key = part.key()?;
    if part.data.len() > ATTACHMENT_PART {
        return Err(Error::TooLarge {
            limit: ATTACHMENT_PART as u64,
        });
    }
    if !fits(ATTACHMENT_PART, part.index, part.last, part.data.len()) {
        return Err(invalid(
            "data",
            "every part but the last is whole, and only an empty file's one part is empty",
        ));
    }
    Ok(Data {
        data: seal_part(key, part.attachment_id, part.index, part.last, &part.data),
    })
}

/// A part of a file, opened. One that can't be in its place, by its size, gives `decrypt_failed`
/// before it's opened.
pub(crate) fn attachment_decrypt(part: AttachmentPart) -> Result<Data, Error> {
    let key = part.key()?;
    if part.data.len() > ATTACHMENT_PART + TAG {
        return Err(Error::TooLarge {
            limit: (ATTACHMENT_PART + TAG) as u64,
        });
    }
    let len = part.data.len().checked_sub(TAG).ok_or_else(failed)?;
    if !fits(ATTACHMENT_PART, part.index, part.last, len) {
        return Err(failed());
    }
    Ok(Data {
        data: open_part(key, part.attachment_id, part.index, part.last, &part.data)?,
    })
}
