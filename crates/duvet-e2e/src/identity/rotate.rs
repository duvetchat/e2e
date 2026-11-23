//! Changing the user's identity: starting over without the recovery key (`reset_identity`, on a
//! device without the identity), and changing the keys once a device is lost (`rotate_keys`).
//! Either gives the user a new identity, which certifies this device and signs a new device list
//! from version 1, a new backup key and a new recovery key, and the user's contacts see the
//! change. A rotation keeps the devices that stay on the list and the backup keys from before,
//! sealed with the new one; starting over keeps neither.
//!
//! Each device that stays gets the new identity from the rotating one: a transfer, sealed to its
//! HPKE key and signed by the rotating device as a direct message of type `rotation.transfer`, with
//! a certificate of its own keys from the new identity, the new list and the backup keys.
//!
//! After a rotation, the device's leaf in each of its groups still carries the certificate of the
//! identity before. The members took it as it entered and don't check it again, but a welcome or
//! an external join holds it to the new identity: every group of the device is due for `refresh`
//! at once, whose commit brings the leaf with the new certificate. So is every group of a device
//! that takes a transfer.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use duvet_e2e_rules::{DeviceCertificate, DeviceList};
use openmls::prelude::{BasicCredential, MlsGroup};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::identity::{CreatedIdentity, create_identity, new_identity};
use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_KEY, IDENTITY_SECRET, Identity, OwnDevice, from_cbor,
    invalid, meta_get, meta_put, not_found, random, to_cbor, unix_ms,
};
use crate::protocol::b64;
use crate::{DirectMessage, Error, Tx};

/// The type of the direct message that carries a rotation's new identity to a device that stays.
pub(crate) const ROTATION_TRANSFER: &str = "rotation.transfer";

/// Room for a transfer's fixed parts besides its certificates, its list and the backup keys from
/// before: its buffer is sized ahead, so no copy of a secret is left behind as it grows.
const TRANSFER_FIXED: usize = 256;

/// A rotation's transfer to a device that stays: `{v: 1, identity, backup_key,
/// previous_backup_keys, certificate, device_list, sender}`. `identity` is the new identity's
/// 32-byte secret, `backup_key` the new backup key, `previous_backup_keys` those before it (32
/// bytes each, oldest first), `certificate` the receiving device's from the new identity,
/// `device_list` the new list, and `sender` the sending device's certificate from the identity
/// before, which the receiving device still holds.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    v: u32,
    #[serde(with = "secret")]
    identity: Zeroizing<[u8; 32]>,
    #[serde(with = "secret")]
    backup_key: Zeroizing<[u8; 32]>,
    #[serde(with = "secret")]
    previous_backup_keys: Zeroizing<Vec<u8>>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
}

/// What `rotate_keys` answers: `create_identity`'s reply, and the devices that stay.
#[derive(Serialize)]
pub(crate) struct Rotated {
    #[serde(flatten)]
    created: CreatedIdentity,
    transfers: Vec<Handed>,
}

/// A device that stays but the rotating one: its certificate from the new identity, for the
/// server, and its transfer, for its inbox.
#[derive(Serialize)]
struct Handed {
    device_id: Uuid,
    #[serde(with = "b64")]
    certificate: Vec<u8>,
    #[serde(with = "b64")]
    transfer: Vec<u8>,
}

/// What a device that stays answers as it takes a rotation's transfer.
#[derive(Serialize)]
pub(crate) struct Transferred {
    #[serde(with = "b64")]
    identity_key: Vec<u8>,
    #[serde(with = "b64")]
    certificate: Vec<u8>,
}

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

/// Starts over, for a user with neither the recovery key nor another device: a new identity, whose
/// list has this device alone, and a new backup key, which opens nothing from before. The server
/// takes them in place of the user's identity, list and backup. On the device that's creating an
/// identity where there's none: a device that holds the identity changes the keys instead
/// (`rotate_keys`), which gives it all that starting over would and keeps the backup keys from
/// before, and starting over there is `exists`.
pub(crate) fn reset_identity(tx: &mut Tx<'_>) -> Result<CreatedIdentity, Error> {
    create_identity(tx)
}

/// Changes the keys once devices are lost: a new identity, whose list has the devices that stay
/// (all but `remove`, this one among them), and a new backup key, which keeps those from before for
/// the backup's segments. What the lost devices hold opens nothing made from now on: no device of
/// the user that holds the new list sends in a group while a lost device's leaf is in it, and its
/// next commit there takes that leaf out (`ready_to_send`, `commit_pending`).
///
/// Each device that stays but this one is certified anew, for its own keys as its certificate
/// among `certificates` has them (the user's devices' certificates as the server serves them,
/// which the identity this device holds must have signed), and gets the new identity, sealed to
/// it: `transfers`. A device that stays with no certificate there, or whose certificates disagree
/// on its keys, is `bad_command` (`certificates`).
pub(crate) fn rotate_keys(
    tx: &mut Tx<'_>,
    remove: &[Uuid],
    certificates: &[Vec<u8>],
) -> Result<Rotated, Error> {
    let own = tx.own_device()?;
    let Some(held) = tx.own_identity_key()? else {
        return Err(not_found("identity"));
    };
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
        return Err(rule("device_not_listed"));
    }
    let staying: Vec<Uuid> = current
        .devices
        .iter()
        .copied()
        .filter(|device| !remove.contains(device))
        .collect();
    let keys = staying_keys(&own, &held, &staying, certificates)?;
    let sender = own
        .certificate
        .clone()
        .ok_or_else(|| Error::Internal("the device has the identity but no certificate".into()))?;
    let kept = kept_keys(tx, own.user)?;
    let (created, backup_key) = new_identity(tx, &own, staying)?;
    keep_previous(tx, own.user, &backup_key, &kept)?;
    let transfers = hand_over(tx, &own, &keys, &sender, &backup_key, &kept)?;
    all_groups_due(tx)?;
    Ok(Rotated { created, transfers })
}

/// A device that stays but the rotating one, with its keys as its certificate has them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Staying {
    device: Uuid,
    signature_key: [u8; 32],
    hpke_key: [u8; 32],
}

/// Each device of `staying` but this one, with its keys from its certificate among
/// `certificates`, which `held`, the identity this device holds, must have signed. One that doesn't
/// verify is `invalid_signature`; the certificates of other devices aren't read.
fn staying_keys(
    own: &OwnDevice,
    held: &[u8; 32],
    staying: &[Uuid],
    certificates: &[Vec<u8>],
) -> Result<Vec<Staying>, Error> {
    let mut found = BTreeMap::new();
    for signed in certificates {
        let Ok(claimed) = DeviceCertificate::read_unverified(signed) else {
            continue;
        };
        if claimed.device == own.device || !staying.contains(&claimed.device) {
            continue;
        }
        let certificate =
            DeviceCertificate::verify(signed, held).map_err(|_| signature("certificate"))?;
        if certificate.user != own.user {
            return Err(rule("wrong_user"));
        }
        let keys = Staying {
            device: certificate.device,
            signature_key: array(&certificate.signature_key)?,
            hpke_key: array(&certificate.hpke_key)?,
        };
        if *found.entry(certificate.device).or_insert(keys) != keys {
            return Err(invalid(
                "certificates",
                "a device's certificates give it different keys",
            ));
        }
    }
    staying
        .iter()
        .filter(|&&device| device != own.device)
        .map(|device| {
            found
                .get(device)
                .copied()
                .ok_or_else(|| invalid("certificates", "a device that stays has no certificate"))
        })
        .collect()
}

/// For each device of `keys`: a certificate of its keys from the new identity, which this device
/// holds now, and its transfer, sealed to its HPKE key and signed by this device, with this
/// device's certificate from the identity before, `sender`.
fn hand_over(
    tx: &Tx<'_>,
    own: &OwnDevice,
    keys: &[Staying],
    sender: &[u8],
    backup_key: &[u8],
    previous: &[u8],
) -> Result<Vec<Handed>, Error> {
    let identity = tx
        .own_identity()?
        .ok_or_else(|| Error::Internal("the new identity isn't stored".into()))?;
    let secret = meta_get(tx, IDENTITY_SECRET)?
        .map(Zeroizing::new)
        .ok_or_else(|| Error::Internal("the new identity isn't stored".into()))?;
    let list = meta_get(tx, DEVICE_LIST)?
        .ok_or_else(|| Error::Internal("the new identity has no device list".into()))?;
    let created = unix_ms(tx)?;
    keys.iter()
        .map(|staying| {
            let certificate = DeviceCertificate::new(
                own.user,
                staying.device,
                staying.signature_key,
                staying.hpke_key,
                created,
            )
            .sign(&identity.signer)
            .map_err(|_| Error::Internal("the identity couldn't sign".into()))?;
            let transfer = Transfer {
                v: 1,
                identity: secret_array(&secret)?,
                backup_key: secret_array(backup_key)?,
                previous_backup_keys: Zeroizing::new(previous.to_vec()),
                certificate: certificate.clone(),
                device_list: list.clone(),
                sender: sender.to_vec(),
            };
            let capacity =
                TRANSFER_FIXED + certificate.len() + list.len() + sender.len() + previous.len();
            let mut payload = Zeroizing::new(Vec::with_capacity(capacity));
            ciborium::into_writer(&transfer, &mut *payload)
                .map_err(|_| Error::Internal("a CBOR value couldn't be written".into()))?;
            let transfer = DirectMessage::seal(
                tx.provider(),
                &own.signer,
                own.device,
                staying.device,
                &staying.hpke_key,
                ROTATION_TRANSFER,
                &payload,
            )?;
            Ok(Handed {
                device_id: staying.device,
                certificate,
                transfer,
            })
        })
        .collect()
}

/// A rotation's transfer, which another device of the user sent this one as it changed the keys,
/// as `receive_direct` takes it. It counts only if it holds up:
/// - its sender's certificate, which rides in it, is one the identity this device holds signed,
///   for a device this device's list names, and the sender signed the message with its key;
/// - the new identity is the one the server serves for the user now, `served`: a thief holding a
///   lost device holds the identity before too, and could make a rotation of its own, and the
///   server, which ends the lost device's sessions, decides which one counts;
/// - the new identity signs its list, which names this device and the sender, and a certificate
///   of this device's own keys.
///
/// Then this device has the new identity, its certificate, the list and the backup key, keeps its
/// own backup keys from before with the transfer's, and every group of it is due for `refresh`. A
/// transfer it took already is `exists`.
pub(crate) fn receive_rotation(
    tx: &Tx<'_>,
    message: &[u8],
    served: Option<&[u8]>,
) -> Result<Transferred, Error> {
    let own = tx.own_device()?;
    let held = tx
        .own_identity_key()?
        .ok_or_else(|| not_found("identity"))?;
    let served: [u8; 32] = served
        .ok_or_else(|| {
            invalid(
                "identity_key",
                "a rotation's transfer needs the identity the server serves",
            )
        })?
        .try_into()
        .map_err(|_| invalid("identity_key", "the identity key isn't 32 bytes"))?;
    let provider = tx.provider();

    // The sender's certificate is inside: read it, then open the message as every direct message
    // is opened, verified with the key that certificate holds.
    let (_, from) = DirectMessage::header(message)?;
    let claimed = read_transfer(&DirectMessage::peek(
        provider,
        &own.hpke.private,
        own.device,
        message,
    )?)?;
    if Identity::from_secret(&claimed.identity).public == held {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    let sender =
        DeviceCertificate::verify(&claimed.sender, &held).map_err(|_| signature("certificate"))?;
    if sender.user != own.user {
        return Err(rule("wrong_user"));
    }
    if sender.device != from || sender.device == own.device {
        return Err(rule("wrong_device"));
    }
    let listed = tx
        .device_list_of(own.user)?
        .is_some_and(|list| list.contains(sender.device));
    if !listed {
        return Err(rule("device_not_listed"));
    }
    let (_, payload) = DirectMessage::open(
        provider,
        &own.hpke.private,
        own.device,
        from,
        &array(&sender.signature_key)?,
        message,
    )?;
    let transfer = read_transfer(&payload)?;

    let identity = Identity::from_secret(&transfer.identity);
    if identity.public != served {
        return Err(rule("identity_mismatch"));
    }
    let list = DeviceList::verify(&transfer.device_list, &identity.public)
        .map_err(|_| signature("device_list"))?;
    if list.user != own.user {
        return Err(rule("wrong_user"));
    }
    if !list.contains(own.device) || !list.contains(sender.device) {
        return Err(rule("device_not_listed"));
    }
    let certificate = DeviceCertificate::verify(&transfer.certificate, &identity.public)
        .map_err(|_| signature("certificate"))?;
    if certificate.user != own.user {
        return Err(rule("wrong_user"));
    }
    let own_keys =
        certificate.signature_key == own.signer.public() && certificate.hpke_key == own.hpke.public;
    if certificate.device != own.device || !own_keys {
        return Err(rule("wrong_device"));
    }

    // The backup keys from before: this device's own, then the transfer's it hasn't, each once.
    if transfer.previous_backup_keys.len() % KEY != 0 {
        return Err(unreadable());
    }
    let own_kept = kept_keys(tx, own.user)?;
    let mut kept = Zeroizing::new(Vec::with_capacity(
        own_kept.len() + transfer.previous_backup_keys.len(),
    ));
    kept.extend_from_slice(&own_kept);
    for key in transfer.previous_backup_keys.chunks(KEY) {
        if !own_kept.chunks(KEY).any(|kept| kept == key) {
            kept.extend_from_slice(key);
        }
    }

    tx.conn().execute(
        "UPDATE device SET certificate = ?1",
        [&transfer.certificate],
    )?;
    meta_put(tx, IDENTITY_KEY, &identity.public)?;
    meta_put(tx, IDENTITY_SECRET, &*transfer.identity)?;
    meta_put(tx, DEVICE_LIST, &transfer.device_list)?;
    meta_put(tx, BACKUP_KEY, &*transfer.backup_key)?;
    keep_previous(tx, own.user, &*transfer.backup_key, &kept)?;
    all_groups_due(tx)?;
    Ok(Transferred {
        identity_key: identity.public.to_vec(),
        certificate: transfer.certificate,
    })
}

/// A transfer's payload, read through a scratch buffer that's wiped after.
fn read_transfer(payload: &[u8]) -> Result<Transfer, Error> {
    let mut scratch = Zeroizing::new([0u8; 4096]);
    let mut bytes = payload;
    let transfer: Transfer = ciborium::de::from_reader_with_buffer(&mut bytes, &mut scratch[..])
        .map_err(|_| unreadable())?;
    if transfer.v != 1 || !bytes.is_empty() {
        return Err(unreadable());
    }
    Ok(transfer)
}

/// Secret bytes in CBOR, kept where they're wiped as they drop.
mod secret {
    use serde::{Deserializer, Serializer};
    use zeroize::{Zeroize, Zeroizing};

    pub(super) fn serialize<S: Serializer, T: AsRef<[u8]> + Zeroize>(
        bytes: &Zeroizing<T>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(AsRef::<[u8]>::as_ref(&**bytes))
    }

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<Zeroizing<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: serde_bytes::Deserialize<'de> + Zeroize,
    {
        serde_bytes::deserialize(deserializer).map(Zeroizing::new)
    }
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

/// 32 secret bytes, copied where they're wiped as they drop.
fn secret_array(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if bytes.len() != KEY {
        return Err(Error::Internal("a key isn't 32 bytes".into()));
    }
    let mut key = Zeroizing::new([0u8; KEY]);
    key.copy_from_slice(bytes);
    Ok(key)
}

fn array(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Internal("a key isn't 32 bytes".into()))
}

/// A change the rules of identities don't allow, by name.
fn rule(name: &str) -> Error {
    Error::RuleViolation { rule: name.into() }
}

fn signature(what: &str) -> Error {
    Error::InvalidSignature { what: what.into() }
}

/// A transfer that opens but isn't one.
fn unreadable() -> Error {
    Error::DecryptFailed {
        kind: "transfer".into(),
    }
}
