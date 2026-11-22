//! Changing the user's identity: starting over without the recovery key (`reset_identity`), and
//! changing the keys once a device is lost (`rotate_keys`). Either gives the user a new identity,
//! which certifies this device anew and signs a new device list from version 1, a new backup key
//! and a new recovery key, and the user's contacts see the change. A rotation keeps the devices
//! that stay on the list and the backup keys from before, sealed with the new one; starting over
//! keeps neither.
//!
//! The device's leaf in each of its groups still carries the certificate of the identity before.
//! The members took it as it entered and don't check it again, but a welcome or an external join
//! holds it to the new identity: every group of the device is due for `refresh` at once, whose
//! commit brings the leaf with the new certificate.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use openmls::prelude::{BasicCredential, MlsGroup};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::identity::{CreatedIdentity, new_identity};
use super::{BACKUP_KEY, from_cbor, invalid, meta_get, meta_put, not_found, random, to_cbor};
use crate::{Error, Tx};

/// `meta`'s row for the backup keys before the current one, sealed with it, for the backup's
/// re-encryption to open the segments they encrypted ([`Tx::previous_backup_keys`]).
const PREVIOUS_BACKUP_KEYS: &str = "previous_backup_keys";

/// `leaf_updated_at` of a leaf whose certificate the identity no longer signs: due for `refresh`
/// at once, whatever the clock says.
const STALE_LEAF: i64 = i64::MIN;

const PREVIOUS_KEYS_AAD: &[u8] = b"duvet previous backup keys v1";
const KEY: usize = 32;
const NONCE: usize = 12;

/// The backup keys before the current one, sealed with it (AES-256-GCM, with
/// "duvet previous backup keys v1" || user_id as associated data): `{v: 1, nonce, ct}`, `ct` their
/// 32 bytes each, oldest first.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousKeys {
    v: u32,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

/// Starts over: a new identity, whose list has this device alone, and a new backup key, which
/// keeps none from before. For a user with neither the recovery key nor another device; on a device
/// that had the identity, the user's other devices are off the list from now on, and come back
/// only as new devices of the new identity.
pub(crate) fn reset_identity(tx: &mut Tx<'_>) -> Result<CreatedIdentity, Error> {
    let own = tx.own_device()?;
    let (created, backup_key) = new_identity(tx, &own, vec![own.device])?;
    keep_previous(tx, own.user, &backup_key, &[])?;
    all_groups_due(tx)?;
    Ok(created)
}

/// Changes the keys once devices are lost: a new identity, whose list has the devices that stay
/// (all but `remove`, this one among them), and a new backup key, which keeps those from before for
/// the backup's segments. What the lost devices hold opens nothing made from now on.
pub(crate) fn rotate_keys(tx: &mut Tx<'_>, remove: &[Uuid]) -> Result<CreatedIdentity, Error> {
    let own = tx.own_device()?;
    if tx.own_identity_key()?.is_none() {
        return Err(not_found("identity"));
    }
    let current = tx
        .device_list_of(own.user)?
        .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
    if remove.iter().any(|device| !current.contains(*device)) {
        return Err(not_found("device"));
    }
    if remove.contains(&own.device) {
        return Err(invalid(
            "remove",
            "the device that changes the keys stays on the list",
        ));
    }
    // A device off its own list is on its way out: the identity it would hold certifies nothing
    // anyone takes.
    if !current.contains(own.device) {
        return Err(Error::RuleViolation {
            rule: "device_not_listed".into(),
        });
    }
    let kept = kept_keys(tx, own.user)?;
    let staying = current
        .devices
        .iter()
        .copied()
        .filter(|device| !remove.contains(device))
        .collect();
    let (created, backup_key) = new_identity(tx, &own, staying)?;
    keep_previous(tx, own.user, &backup_key, &kept)?;
    all_groups_due(tx)?;
    Ok(created)
}

impl Tx<'_> {
    /// The backup keys before the current one, oldest first: what the rotations kept, so the
    /// backup's segments they encrypted still open. None without a backup key.
    pub fn previous_backup_keys(&self) -> Result<Vec<Zeroizing<[u8; 32]>>, Error> {
        let (Some(user), Some(current)) = (self.own_user()?, backup_key(self)?) else {
            return Ok(Vec::new());
        };
        let keys = previous_keys(self, user, &current)?;
        let (keys, _) = keys.as_chunks::<KEY>();
        Ok(keys.iter().map(|key| Zeroizing::new(*key)).collect())
    }
}

/// When this device's leaf in `group`, which a commit of its own just brought, counts as new: now,
/// unless the commit was made before the identity changed, and the leaf carries the certificate
/// of the identity before. That leaf is due for `refresh` at once.
pub(crate) fn renewed_at(tx: &Tx<'_>, group: &MlsGroup) -> Result<i64, Error> {
    let certificate: Option<Vec<u8>> = tx
        .conn()
        .query_row("SELECT certificate FROM device", [], |row| row.get(0))
        .optional()?
        .flatten();
    let current = match (group.own_leaf_node(), certificate) {
        (Some(leaf), Some(certificate)) => BasicCredential::try_from(leaf.credential().clone())
            .is_ok_and(|basic| basic.identity() == certificate.as_slice()),
        _ => false,
    };
    Ok(if current { tx.now() } else { STALE_LEAF })
}

/// Every group of the device is due for `refresh`: its leaf there carries the certificate of the
/// identity before.
fn all_groups_due(tx: &Tx<'_>) -> Result<(), Error> {
    tx.conn()
        .execute("UPDATE groups SET leaf_updated_at = ?1", [STALE_LEAF])?;
    Ok(())
}

/// The backup keys a rotation keeps: those before the current one, then the current one, 32 bytes
/// each, oldest first. None while the device has no backup key.
fn kept_keys(tx: &Tx<'_>, user: Uuid) -> Result<Zeroizing<Vec<u8>>, Error> {
    let Some(current) = backup_key(tx)? else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    let previous = previous_keys(tx, user, &current)?;
    let mut kept = Zeroizing::new(Vec::with_capacity(previous.len() + KEY));
    kept.extend_from_slice(&previous);
    kept.extend_from_slice(&*current);
    Ok(kept)
}

/// The device's backup key.
fn backup_key(tx: &Tx<'_>) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    let Some(stored) = meta_get(tx, BACKUP_KEY)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    if stored.len() != KEY {
        return Err(Error::Internal("the stored backup key is malformed".into()));
    }
    let mut key = Zeroizing::new([0u8; KEY]);
    key.copy_from_slice(&stored);
    Ok(Some(key))
}

/// The backup keys before `current`, which seals them: 32 bytes each, oldest first.
fn previous_keys(tx: &Tx<'_>, user: Uuid, current: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let Some(stored) = meta_get(tx, PREVIOUS_BACKUP_KEYS)? else {
        return Ok(Zeroizing::new(Vec::new()));
    };
    let sealed: PreviousKeys = from_cbor(&stored)
        .filter(|sealed: &PreviousKeys| sealed.v == 1 && sealed.nonce.len() == NONCE)
        .ok_or_else(malformed)?;
    let keys = Zeroizing::new(
        cipher(current)?
            .decrypt(
                Nonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ct,
                    aad: &associated(user),
                },
            )
            .map_err(|_| malformed())?,
    );
    if keys.len() % KEY != 0 {
        return Err(malformed());
    }
    Ok(keys)
}

/// Keeps `keys`, the backup keys before `backup_key`, the current one, sealed with it; with none
/// to keep, no row.
fn keep_previous(tx: &Tx<'_>, user: Uuid, backup_key: &[u8], keys: &[u8]) -> Result<(), Error> {
    if keys.is_empty() {
        tx.conn()
            .execute("DELETE FROM meta WHERE key = ?1", [PREVIOUS_BACKUP_KEYS])?;
        return Ok(());
    }
    let nonce = random(tx.provider().rand(), NONCE)?.to_vec();
    let ct = cipher(backup_key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: keys,
                aad: &associated(user),
            },
        )
        .map_err(|_| Error::Internal("AES-256-GCM couldn't encrypt".into()))?;
    meta_put(
        tx,
        PREVIOUS_BACKUP_KEYS,
        &to_cbor(&PreviousKeys { v: 1, nonce, ct })?,
    )
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm, Error> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| Error::Internal("AES-256-GCM refused its key".into()))
}

fn associated(user: Uuid) -> Vec<u8> {
    [PREVIOUS_KEYS_AAD, user.as_bytes().as_slice()].concat()
}

fn malformed() -> Error {
    Error::Internal("the stored backup keys from before are malformed".into())
}
