//! The recovery key and what it opens: the backup key, which it wraps, and the identity, which the
//! backup key encrypts. The server keeps both blobs; only the recovery key opens them.
//!
//! A recovery key is 32 random bytes and a 3-byte check, the first bytes of
//! SHA-256("duvet recovery checksum v1" || the 32 bytes), in base58: exactly 48 characters, read
//! ignoring spaces and dashes. A mistyped character fails the check, all but once in 16 million.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use openmls_traits::random::OpenMlsRand;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{from_cbor, invalid, random, to_cbor};
use crate::Error;

/// A recovery key's length in base58 characters.
pub const LENGTH: usize = 48;

const CHECKSUM_LABEL: &[u8] = b"duvet recovery checksum v1";
const CHECK: usize = 3;
const RECOVERY_INFO: &[u8] = b"duvet recovery v1";
const BACKUP_KEY_AAD: &[u8] = b"duvet backup key v1";
const IDENTITY_AAD: &[u8] = b"duvet identity v1";
const KEY_ID_LABEL: &[u8] = b"duvet backup key id v1";
const NONCE: usize = 12;

/// What a person may type between a recovery key's characters: dashes as keyboards write them.
const DASHES: [char; 7] = [
    '-', '\u{2010}', '\u{2011}', '\u{2012}', '\u{2013}', '\u{2014}', '\u{2212}',
];

/// The backup key wrapped by the recovery key: `{v: 1, nonce, ct}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedBackupKey {
    v: u32,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

/// The identity encrypted with the backup key: `{v: 1, key_id, nonce, ct}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptedIdentity {
    v: u32,
    #[serde(with = "serde_bytes")]
    key_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

/// A new recovery key, as the person writes it down.
pub fn generate(rand: &impl OpenMlsRand) -> Result<Zeroizing<String>, Error> {
    // 35 bytes under 58^47 take fewer characters, about one in 25: those are drawn again.
    for _ in 0..64 {
        let key = random(rand, 32)?;
        let mut checked = Zeroizing::new([0u8; 32 + CHECK]);
        checked[..32].copy_from_slice(&key);
        checked[32..].copy_from_slice(&check(&key));
        let text = encode(&*checked)?;
        if text.len() == LENGTH {
            return Ok(text);
        }
    }
    Err(Error::Internal(
        "the randomness gives no recovery key".into(),
    ))
}

/// The 32 bytes of key a recovery key's text spells, its spaces and dashes aside. Only a key's own
/// spelling reads: 48 characters of the alphabet that decode to 35 bytes and encode back the same,
/// whose last 3 are the first 32's check.
pub fn parse(text: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut compact = Zeroizing::new(String::with_capacity(text.len()));
    compact.extend(
        text.chars()
            .filter(|c| !c.is_whitespace() && !DASHES.contains(c)),
    );
    if compact.len() != LENGTH {
        return Err(not_a_key());
    }
    let mut checked = Zeroizing::new([0u8; 32 + CHECK]);
    let written = bs58::decode(compact.as_bytes())
        .onto(&mut *checked)
        .map_err(|_| not_a_key())?;
    if written != checked.len() || *encode(&*checked)? != *compact {
        return Err(not_a_key());
    }
    let (key, given) = checked.split_at(32);
    if given != check(key).as_slice() {
        return Err(invalid(
            "recovery_key",
            "the recovery key's check doesn't match",
        ));
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(key);
    Ok(out)
}

/// A key's check: the first 3 bytes of SHA-256("duvet recovery checksum v1" || key).
fn check(key: &[u8]) -> [u8; CHECK] {
    let digest = Sha256::new()
        .chain_update(CHECKSUM_LABEL)
        .chain_update(key)
        .finalize();
    let mut check = [0u8; CHECK];
    check.copy_from_slice(&digest[..CHECK]);
    check
}

/// The backup key, wrapped by the key HKDF derives from the recovery key and the user's ID.
pub fn wrap_backup_key(
    rand: &impl OpenMlsRand,
    recovery_key: &[u8; 32],
    user: Uuid,
    backup_key: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let nonce = random(rand, NONCE)?.to_vec();
    let ct = seal(
        &*wrapping_key(recovery_key, user)?,
        &nonce,
        &associated(BACKUP_KEY_AAD, user),
        backup_key,
    )?;
    to_cbor(&WrappedBackupKey { v: 1, nonce, ct })
}

/// The backup key `wrap_backup_key` wrapped. Another recovery key or user gives `decrypt_failed`.
pub fn unwrap_backup_key(
    recovery_key: &[u8; 32],
    user: Uuid,
    wrapped: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let wrapped: WrappedBackupKey = from_cbor(wrapped)
        .filter(|wrapped: &WrappedBackupKey| wrapped.v == 1 && wrapped.nonce.len() == NONCE)
        .ok_or_else(|| invalid("wrapped_backup_key", "the wrapped backup key is malformed"))?;
    open(
        &*wrapping_key(recovery_key, user)?,
        &wrapped.nonce,
        &associated(BACKUP_KEY_AAD, user),
        &wrapped.ct,
        "backup_key",
    )
}

/// The identity's secret, encrypted with the backup key.
pub fn encrypt_identity(
    rand: &impl OpenMlsRand,
    backup_key: &[u8; 32],
    user: Uuid,
    identity: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let nonce = random(rand, NONCE)?.to_vec();
    let ct = seal(
        backup_key,
        &nonce,
        &associated(IDENTITY_AAD, user),
        identity,
    )?;
    to_cbor(&EncryptedIdentity {
        v: 1,
        key_id: key_id(backup_key).to_vec(),
        nonce,
        ct,
    })
}

/// The identity's secret `encrypt_identity` encrypted. Another backup key or user gives `decrypt_failed`.
pub fn decrypt_identity(
    backup_key: &[u8; 32],
    user: Uuid,
    encrypted: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let encrypted: EncryptedIdentity = from_cbor(encrypted)
        .filter(|encrypted: &EncryptedIdentity| encrypted.v == 1 && encrypted.nonce.len() == NONCE)
        .ok_or_else(|| invalid("encrypted_identity", "the encrypted identity is malformed"))?;
    if encrypted.key_id != key_id(backup_key) {
        return Err(Error::DecryptFailed {
            kind: "identity".into(),
        });
    }
    open(
        backup_key,
        &encrypted.nonce,
        &associated(IDENTITY_AAD, user),
        &encrypted.ct,
        "identity",
    )
}

/// Which backup key encrypted something, without telling the key: the first 8 bytes of
/// SHA-256("duvet backup key id v1" || key).
pub fn key_id(backup_key: &[u8; 32]) -> [u8; 8] {
    let digest = Sha256::new()
        .chain_update(KEY_ID_LABEL)
        .chain_update(backup_key)
        .finalize();
    let mut id = [0u8; 8];
    id.copy_from_slice(&digest[..8]);
    id
}

/// A key and its check in base58, written once into a buffer of its final size.
fn encode(bytes: &[u8]) -> Result<Zeroizing<String>, Error> {
    // 35 bytes take 48 characters at most; the buffer has room to spare.
    let mut buffer = Zeroizing::new([0u8; 64]);
    let written = bs58::encode(bytes)
        .onto(&mut buffer[..])
        .map_err(|_| Error::Internal("a recovery key couldn't be written".into()))?;
    let text = std::str::from_utf8(&buffer[..written])
        .map_err(|_| Error::Internal("a recovery key couldn't be written".into()))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn not_a_key() -> Error {
    invalid("recovery_key", "the recovery key isn't valid")
}

/// HKDF-SHA256 of the recovery key's 32 bytes (its check aside), salted with the user's ID.
fn wrapping_key(recovery_key: &[u8; 32], user: Uuid) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(user.as_bytes().as_slice()), recovery_key)
        .expand(RECOVERY_INFO, &mut *key)
        .map_err(|_| Error::Internal("the wrapping key couldn't be derived".into()))?;
    Ok(key)
}

fn associated(label: &[u8], user: Uuid) -> Vec<u8> {
    [label, user.as_bytes().as_slice()].concat()
}

fn seal(key: &[u8; 32], nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Internal("AES-256-GCM refused its key".into()))?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::Internal("AES-256-GCM couldn't encrypt".into()))
}

/// The 32 bytes `seal` sealed, or `decrypt_failed` with `kind`.
fn open(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    kind: &str,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let failed = || Error::DecryptFailed { kind: kind.into() };
    let plain = Zeroizing::new(
        Aes256Gcm::new_from_slice(key)
            .map_err(|_| Error::Internal("AES-256-GCM refused its key".into()))?
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| failed())?,
    );
    let mut secret = Zeroizing::new([0u8; 32]);
    if plain.len() != secret.len() {
        return Err(failed());
    }
    secret.copy_from_slice(&plain);
    Ok(secret)
}
