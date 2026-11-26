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
//! identity before. The members took it as it entered and don't check it again, and a device that
//! joins takes it while the identity it pins certifies the same device with the same key. Every
//! group of the device is due for `refresh` at once all the same, whose commit brings the leaf
//! with the new certificate. So is every group of a device that takes a transfer.

use std::collections::BTreeMap;
use std::iter;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use duvet_e2e_rules::{DeviceCertificate, DeviceList};
use openmls::prelude::{BasicCredential, MlsGroup};
use openmls_traits::OpenMlsProvider;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::identity::{
    CreatedIdentity, Kept, KeptRotation, create_identity, drop_kept, keep, kept, new_identity,
};
use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_KEY, IDENTITY_SECRET, Identity, OwnDevice, from_cbor,
    invalid, keep_certificates, keep_earlier_identity, meta_get, meta_put, not_found, random,
    to_cbor, unix_ms,
};
use crate::backup::Day;
use crate::protocol::b64;
use crate::{DirectMessage, Error, Tx};

/// The type of the direct message that carries a rotation's new identity to a device that stays.
pub(crate) const ROTATION_TRANSFER: &str = "rotation.transfer";

/// Room for a transfer's fixed parts besides its certificates, its list and the backup keys from
/// before: its buffer is sized ahead, so no copy of a secret is left behind as it grows.
const TRANSFER_FIXED: usize = 256;

/// A rotation's transfer to a device that stays: `{v: 1, identity, backup_key,
/// previous_backup_keys, certificate, device_list, previous_list, sender}`. `identity` is the new
/// identity's 32-byte secret, `backup_key` the new backup key, `previous_backup_keys` those before
/// it (each with the day it was replaced on, oldest first), `certificate` the receiving device's from
/// the new identity, `device_list` the new list. `previous_list` and `sender` are of the identity
/// before, which the receiving device still holds: the user's list as the sending device had it,
/// and the sending device's certificate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    v: u32,
    #[serde(with = "secret")]
    identity: Zeroizing<[u8; 32]>,
    #[serde(with = "secret")]
    backup_key: Zeroizing<[u8; 32]>,
    previous_backup_keys: Vec<EarlierKey>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    previous_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
}

/// What `rotate_keys` answers: `create_identity`'s reply, the backup keys from before sealed with
/// the new one, for the server to keep beside the wrapped backup key (none when this device kept
/// none, as it held no backup key), and the devices that stay.
#[derive(Serialize)]
pub(crate) struct Rotated {
    #[serde(flatten)]
    created: CreatedIdentity,
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    wrapped_previous_backup_keys: Option<Vec<u8>>,
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
/// Room for an earlier key in CBOR: its 32 bytes, its day and their names.
const EARLIER_KEY_ROOM: usize = 64;

/// A backup key from before the current one, and the UTC day it was replaced on (`YYYY-MM-DD`): it
/// opens only the backup's segments of the days before that one, so whoever kept it (the lost device
/// a rotation is for) can't seal segments of later days that devices would take.
///
/// Its key is wiped where it lies as it drops, so a list of them is sized before keys go in, read by
/// reference, and sorted in place: a list that grows, or hands its keys out by value, leaves copies
/// in the blocks it frees.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EarlierKey {
    #[serde(with = "secret")]
    pub(crate) key: Zeroizing<[u8; 32]>,
    pub(crate) until: Day,
}

/// The backup keys before the current one, sealed with it (AES-256-GCM, with
/// "duvet previous backup keys v1" || user_id as associated data): `{v: 1, nonce, ct}`, `ct` the CBOR
/// list of the keys (`EarlierKey`: `{key, until}`), oldest first.
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
/// the backup's segments. What the lost devices hold opens nothing made from now on in the groups
/// the user's remaining devices share with them: no device of the user that holds the new list
/// sends in such a group while a lost device's leaf is in it, and its next commit there takes that
/// leaf out (`ready_to_send`, `commit_pending`). In a group where a lost device is its user's only
/// one, other users' devices take out only devices of their own users: its removal waits for the
/// server's proposal there.
///
/// Each device that stays but this one is certified anew, for its own keys as its certificate
/// among `certificates` has them (the user's devices' certificates as the server serves them,
/// which the identity this device holds must have signed), and gets the new identity, sealed to
/// it: `transfers`. A device that stays with no certificate there, or whose certificates disagree
/// on its keys, is `bad_command` (`certificates`).
///
/// The reply is kept until the client confirms its upload (`identity_uploaded`): run again until
/// then, it's the same rotation ([`rotate_again`]), and only then does it take `gone`, with the
/// user's list as the server serves it (`served_list`).
pub(crate) fn rotate_keys(
    tx: &mut Tx<'_>,
    remove: &[Uuid],
    certificates: &[Vec<u8>],
    gone: &[Uuid],
    served_list: Option<&[u8]>,
) -> Result<Rotated, Error> {
    let own = tx.own_device()?;
    let Some(held) = tx.own_identity_key()? else {
        return Err(not_found("identity"));
    };
    let current = tx
        .device_list_of(own.user)?
        .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
    // A device off its own list is on its way out: the identity it would hold certifies nothing
    // anyone takes.
    if !current.contains(own.device) {
        return Err(rule("device_not_listed"));
    }
    if let Some(waiting) = kept(tx)?
        && waiting.rotation.is_some()
    {
        return rotate_again(tx, &own, remove, certificates, gone, served_list, waiting);
    }
    if !gone.is_empty() {
        return Err(invalid(
            "gone",
            "only a key change that waits for its upload takes gone",
        ));
    }
    if remove.iter().any(|device| !current.contains(*device)) {
        return Err(not_found("device"));
    }
    if remove.contains(&own.device) {
        return Err(invalid(
            "remove",
            "the device that changes the keys stays on the list",
        ));
    }
    let staying: Vec<Uuid> = current
        .devices
        .iter()
        .copied()
        .filter(|device| !remove.contains(device))
        .collect();
    let keys = staying_keys(&own, &[held], &staying, certificates)?;
    let sender = own
        .certificate
        .clone()
        .ok_or_else(|| Error::Internal("the device has the identity but no certificate".into()))?;
    let kept = kept_keys(tx, own.user, 0)?;
    let previous_list = meta_get(tx, DEVICE_LIST)?
        .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
    keep_earlier_identity(tx, own.user, &held)?;
    let (created, backup_key) = new_identity(tx, &own, staying)?;
    keep_previous(tx, own.user, &backup_key, &kept)?;
    // What a device recovered with the new recovery key takes, to open the segments of those keys.
    let wrapped_previous_backup_keys = meta_get(tx, PREVIOUS_BACKUP_KEYS)?;
    let before = Before {
        sender: &sender,
        list: &previous_list,
        backup_keys: &kept,
    };
    let transfers = hand_over(tx, &own, &keys, &backup_key, &before)?;
    keep_handed_certificates(tx, own.user, &transfers)?;
    let mut removed = remove.to_vec();
    removed.sort_unstable();
    removed.dedup();
    keep(
        tx,
        &Kept {
            created: created.clone(),
            wrapped_previous_backup_keys: wrapped_previous_backup_keys.clone(),
            rotation: Some(KeptRotation {
                removed,
                sender,
                previous_list,
            }),
        },
    )?;
    all_groups_due(tx)?;
    Ok(Rotated {
        created,
        wrapped_previous_backup_keys,
        transfers,
    })
}

/// `rotate_keys` run again before the client confirmed its upload: the same new identity, recovery
/// key and blobs, and the transfers sealed again to the devices that stay, for their keys as the
/// certificates the server serves have them, signed by the identity this device holds or, the
/// upload never having landed, by one it kept from before. Run with other devices to remove, it's
/// `bad_command` (`remove`): the rotation made is the one that waits.
///
/// `gone` are devices its list keeps that the server no longer has, as another device took them
/// off the list and the API took that: it signs its list again without them, under the same
/// identity, still at version 1, as the list it replaces never went up and the API takes a new
/// identity's list only at 1. The server could have this device sign a list without a device that's
/// there by not serving its certificate, so the client names them to its person first, and the
/// core takes `gone` only with the proof that case always has, which a server alone can't sign:
/// `served_list`, the user's list as the server serves it, signed by the identity the rotation
/// replaced, newer than the list the rotation was made on, and without the devices gone.
///
/// A device of `gone` that's this one, that the rotation didn't keep as it was made, or that has a
/// certificate among `certificates` is `bad_command` (`gone`), and so is a served list that names
/// one; a missing or older served list is `bad_command` (`served_list`), and one the identity
/// before didn't sign `invalid_signature` (`device_list`). Run again after its answer was lost, a
/// `gone` whose devices are off the rotation's list already answers as its first run did.
fn rotate_again(
    tx: &Tx<'_>,
    own: &OwnDevice,
    remove: &[Uuid],
    certificates: &[Vec<u8>],
    gone: &[Uuid],
    served_list: Option<&[u8]>,
    mut waiting: Kept,
) -> Result<Rotated, Error> {
    let held = &tx
        .own_identity_key()?
        .ok_or_else(|| not_found("identity"))?;
    let rotation = waiting
        .rotation
        .as_ref()
        .ok_or_else(|| Error::Internal("the kept identity isn't a rotation's".into()))?;
    let mut asked = remove.to_vec();
    asked.sort_unstable();
    asked.dedup();
    if asked != rotation.removed {
        return Err(invalid(
            "remove",
            "a rotation waits for its upload: run it again as it was, or confirm its upload first",
        ));
    }
    let mut staying = DeviceList::verify(&waiting.created.device_list, held)
        .map_err(|_| Error::Internal("the kept rotation's list doesn't verify".into()))?
        .devices;
    if !gone.is_empty() {
        let (before, made_on) = replaced_by(tx, own.user, rotation)?;
        for device in gone {
            let served = certificates.iter().any(|signed| {
                DeviceCertificate::read_unverified(signed)
                    .is_ok_and(|certificate| certificate.device == *device)
            });
            if *device == own.device {
                return Err(invalid(
                    "gone",
                    "the device that changes the keys stays on the list",
                ));
            }
            // As the rotation was made: a run after one whose answer was lost finds it off already.
            if !made_on.contains(*device) || rotation.removed.contains(device) {
                return Err(invalid(
                    "gone",
                    "a device that's gone is one the waiting key change keeps",
                ));
            }
            if served {
                return Err(invalid(
                    "gone",
                    "a device whose certificate the server serves isn't gone",
                ));
            }
        }
        let served = served_list.ok_or_else(|| {
            invalid(
                "served_list",
                "a key change run again with gone takes the user's list as the server serves it",
            )
        })?;
        let served = DeviceList::verify(served, &before).map_err(|_| signature("device_list"))?;
        if served.user != own.user {
            return Err(rule("wrong_user"));
        }
        if served.version <= made_on.version {
            return Err(invalid(
                "served_list",
                "the served list isn't newer than the one the key change was made on",
            ));
        }
        if gone.iter().any(|device| served.contains(*device)) {
            return Err(invalid(
                "gone",
                "a device that's gone isn't on the user's list as the server serves it",
            ));
        }
        if staying.iter().any(|device| gone.contains(device)) {
            staying.retain(|device| !gone.contains(device));
            let identity = tx
                .own_identity()?
                .ok_or_else(|| Error::Internal("the new identity isn't stored".into()))?;
            let list = DeviceList::new(own.user, identity.public, 1, staying.clone())
                .sign(&identity.signer)
                .map_err(|_| Error::Internal("the identity couldn't sign".into()))?;
            meta_put(tx, DEVICE_LIST, &list)?;
            waiting.created.device_list = list;
            keep(tx, &waiting)?;
        }
    }
    let mut signers = vec![*held];
    signers.extend(tx.earlier_identities_of(own.user)?);
    let keys = staying_keys(own, &signers, &staying, certificates)?;
    // The keys the first run certified, which it keeps: no other keys get the identity.
    for staying in &keys {
        let first = tx
            .certificate_of(own.user, staying.device)?
            .and_then(|signed| DeviceCertificate::verify(&signed, held).ok());
        let other = first.is_some_and(|first| {
            first.signature_key != staying.signature_key || first.hpke_key != staying.hpke_key
        });
        if other {
            return Err(invalid(
                "certificates",
                "a device's certificate gives it other keys than the rotation certified",
            ));
        }
    }
    let backup_key = backup_key(tx)?
        .ok_or_else(|| Error::Internal("the new identity has no backup key".into()))?;
    let earlier = tx.earlier_backup_keys()?;
    let before = Before {
        sender: &rotation.sender,
        list: &rotation.previous_list,
        backup_keys: &earlier,
    };
    let transfers = hand_over(tx, own, &keys, &*backup_key, &before)?;
    keep_handed_certificates(tx, own.user, &transfers)?;
    Ok(Rotated {
        created: waiting.created,
        wrapped_previous_backup_keys: waiting.wrapped_previous_backup_keys,
        transfers,
    })
}

/// The new identity's certificates of the user's devices: this one's, and those of the devices that
/// stay, which `transfers` hand out.
fn keep_handed_certificates(tx: &Tx<'_>, user: Uuid, transfers: &[Handed]) -> Result<(), Error> {
    let certified = tx
        .own_device()?
        .certificate
        .ok_or_else(|| Error::Internal("the new identity isn't stored".into()))?;
    let staying = transfers.iter().map(|handed| handed.certificate.as_slice());
    keep_certificates(
        tx,
        user,
        iter::once(certified.as_slice()).chain(staying),
        true,
    )
}

/// A device that stays but the rotating one, with its keys as its certificate has them.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Staying {
    device: Uuid,
    signature_key: [u8; 32],
    hpke_key: [u8; 32],
}

/// Each device of `staying` but this one, with its keys from its certificate among
/// `certificates`, which one of `identities` must have signed (the identity this device holds, and,
/// for a rotation run again, those it kept from before). One that doesn't verify is
/// `invalid_signature`; the certificates of other devices aren't read.
fn staying_keys(
    own: &OwnDevice,
    identities: &[[u8; 32]],
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
        let certificate = identities
            .iter()
            .find_map(|identity| DeviceCertificate::verify(signed, identity).ok())
            .ok_or_else(|| signature("certificate"))?;
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

/// What a transfer carries of the identity before: the sending device's certificate, the user's
/// list as the sending device had it, and the backup keys before the new one.
struct Before<'a> {
    sender: &'a [u8],
    list: &'a [u8],
    backup_keys: &'a [EarlierKey],
}

/// For each device of `keys`: a certificate of its keys from the new identity, which this device
/// holds now, and its transfer, sealed to its HPKE key and signed by this device, with what it
/// carries of the identity before.
fn hand_over(
    tx: &Tx<'_>,
    own: &OwnDevice,
    keys: &[Staying],
    backup_key: &[u8],
    before: &Before<'_>,
) -> Result<Vec<Handed>, Error> {
    let (sender, previous) = (before.sender, before.backup_keys);
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
                previous_backup_keys: previous.to_vec(),
                certificate: certificate.clone(),
                device_list: list.clone(),
                previous_list: before.list.to_vec(),
                sender: sender.to_vec(),
            };
            let capacity = TRANSFER_FIXED
                + certificate.len()
                + list.len()
                + before.list.len()
                + sender.len()
                + previous.len() * EARLIER_KEY_ROOM;
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
/// - its sender's certificate, which rides in it, is one the identity it replaces signed, for a
///   device the user's list under that identity names (while a rotation waits, see below), and the
///   sender signed the message with its key;
/// - the new identity is the one the server serves for the user now, `served`: a thief holding a
///   lost device holds the identity before too, and could make a rotation of its own, and the
///   server, which ends the lost device's sessions, decides which one counts;
/// - the new identity signs its list, which names this device and the sender, and a certificate
///   of this device's own keys.
///
/// The identity it replaces is the one this device holds; while a rotation of this device's own
/// waits for its upload, the one that rotation replaced: the waiting rotation's identity signed
/// nothing the server has (another device's rotation landed first). Its sender must then be a
/// device that rotation keeps, with the keys it certified for it, as whoever holds the identity
/// before (a lost device's holder among them) signs a certificate for any device, on any list. Its
/// new list may keep no device that rotation removes (`removed_device_listed`), and it may not bring
/// back the identity it replaces. That holds against whoever holds only devices this device's
/// person named lost; one who also holds a device the person kept can still send a transfer that
/// passes, once the server serves their identity.
///
/// Then this device has the new identity, its certificate, the list and the backup key, keeps its
/// own backup keys from before with the transfer's, and every group of it is due for `refresh`.
/// What an identity command of its own kept for its upload goes: it was made for the identity
/// replaced. A waiting rotation's identity isn't kept as one the user had before, but its backup
/// key is, with the one before it: what this device sealed under either moves to the new key. A
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
    let waiting = kept(tx)?.and_then(|kept| kept.rotation);
    let before = match &waiting {
        Some(rotation) => replaced_by(tx, own.user, rotation)?.0,
        None => held,
    };
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
    let brought = Identity::from_secret(&claimed.identity).public;
    if brought == held || brought == before {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    // The user's list before the change, as the sending device had it.
    let carried = DeviceList::verify(&claimed.previous_list, &before)
        .map_err(|_| signature("device_list"))?;
    if carried.user != own.user {
        return Err(rule("wrong_user"));
    }
    let sender = DeviceCertificate::verify(&claimed.sender, &before)
        .map_err(|_| signature("certificate"))?;
    if sender.user != own.user {
        return Err(rule("wrong_user"));
    }
    if sender.device != from || sender.device == own.device {
        return Err(rule("wrong_device"));
    }
    let listed = match &waiting {
        // A device the waiting rotation keeps, with the keys it certified: whoever holds the
        // identity before signs a certificate for any device.
        Some(_) => tx
            .certificate_of(own.user, sender.device)?
            .and_then(|signed| DeviceCertificate::verify(&signed, &held).ok())
            .is_some_and(|certified| {
                certified.signature_key == sender.signature_key
                    && certified.hpke_key == sender.hpke_key
            }),
        // On this device's list, or the sending device's when newer (a device set up while this one
        // was away).
        None => match tx.device_list_of(own.user)? {
            Some(list) if carried.version <= list.version => list,
            _ => carried,
        }
        .contains(sender.device),
    };
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
    // Taken, it would put back on this device's list a device its person named lost.
    let keeps_removed = waiting
        .as_ref()
        .is_some_and(|rotation| rotation.removed.iter().any(|device| list.contains(*device)));
    if keeps_removed {
        return Err(rule("removed_device_listed"));
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

    // The backup keys from before: this device's own, then the transfer's it hasn't, each once, with
    // the earliest day either says it was replaced on (this device's current key, replaced now as it
    // takes the transfer, was replaced when the rotation was made). While a rotation of its own
    // waits, the key the server knew it to hold is the one before that rotation's: it sealed under
    // it until then, and under the rotation's after.
    let mut kept = kept_keys(tx, own.user, transfer.previous_backup_keys.len())?;
    let replaced = match kept.len() {
        len if waiting.is_some() && len > 1 => Some(len - 2),
        len => len.checked_sub(1),
    };
    for earlier in &transfer.previous_backup_keys {
        match kept.iter_mut().find(|kept| *kept.key == *earlier.key) {
            Some(kept) => kept.until = kept.until.min(earlier.until),
            None => kept.push(earlier.clone()),
        }
    }
    // What this device sealed under its own key of the days from the one it was replaced on no
    // longer opens: those days are built again, under the new key.
    if let Some(replaced) = replaced {
        crate::backup::rebuild_from(tx, kept[replaced].until)?;
    }
    kept.sort_unstable_by_key(|kept| kept.until);

    tx.conn().execute(
        "UPDATE device SET certificate = ?1",
        [&transfer.certificate],
    )?;
    meta_put(tx, IDENTITY_KEY, &identity.public)?;
    meta_put(tx, IDENTITY_SECRET, &*transfer.identity)?;
    meta_put(tx, DEVICE_LIST, &transfer.device_list)?;
    meta_put(tx, BACKUP_KEY, &*transfer.backup_key)?;
    // What an identity command of this device kept for its upload was made for the identity
    // replaced now: run again, it would hand that one out.
    drop_kept(tx)?;
    keep_previous(tx, own.user, &*transfer.backup_key, &kept)?;
    keep_earlier_identity(tx, own.user, &before)?;
    keep_certificates(
        tx,
        own.user,
        iter::once(transfer.certificate.as_slice()),
        true,
    )?;
    all_groups_due(tx)?;
    Ok(Transferred {
        identity_key: identity.public.to_vec(),
        certificate: transfer.certificate,
    })
}

/// The identity that `rotation`, this device's own waiting for its upload, replaced, which
/// `keep_earlier_identity` kept as it was made, with the user's list under it as this device had it
/// then: the earlier identity that signs the rotation's `previous_list`.
fn replaced_by(
    tx: &Tx<'_>,
    user: Uuid,
    rotation: &KeptRotation,
) -> Result<([u8; 32], DeviceList), Error> {
    tx.earlier_identities_of(user)?
        .into_iter()
        .find_map(|identity| {
            DeviceList::verify(&rotation.previous_list, &identity)
                .ok()
                .map(|list| (identity, list))
        })
        .ok_or_else(|| {
            Error::Internal("the identity a waiting rotation replaced isn't kept".into())
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
        Ok(self
            .earlier_backup_keys()?
            .iter()
            .map(|earlier| earlier.key.clone())
            .collect())
    }

    /// The backup keys before the current one, oldest first, each with the UTC day it was replaced
    /// on. None without a backup key.
    pub(crate) fn earlier_backup_keys(&self) -> Result<Vec<EarlierKey>, Error> {
        let (Some(user), Some(current)) = (self.own_user()?, backup_key(self)?) else {
            return Ok(Vec::new());
        };
        previous_keys(self, user, &current)
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

/// The backup keys a rotation keeps: those before the current one, then the current one, replaced
/// today, oldest first; none while the device has no backup key. The list has room for `more`, so
/// it never grows.
fn kept_keys(tx: &Tx<'_>, user: Uuid, more: usize) -> Result<Vec<EarlierKey>, Error> {
    let Some(current) = backup_key(tx)? else {
        return Ok(Vec::with_capacity(more));
    };
    let previous = previous_keys(tx, user, &current)?;
    let mut kept = Vec::with_capacity(previous.len() + 1 + more);
    kept.extend(previous.iter().cloned());
    kept.push(EarlierKey {
        key: current,
        until: Day::of(tx.now()),
    });
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

/// The backup keys before `current`, which seals them, oldest first.
fn previous_keys(tx: &Tx<'_>, user: Uuid, current: &[u8; 32]) -> Result<Vec<EarlierKey>, Error> {
    let Some(stored) = meta_get(tx, PREVIOUS_BACKUP_KEYS)? else {
        return Ok(Vec::new());
    };
    let sealed = read_previous(&stored).ok_or_else(malformed)?;
    unseal_previous(&sealed, user, current).ok_or_else(malformed)
}

/// The backup keys before `backup_key` that the server keeps for `user`, as `rotate_keys` handed
/// them out (`wrapped_previous_backup_keys`), which a device recovered with the recovery key or
/// approved after a rotation takes, oldest first. What isn't such a blob is `bad_command`; one that
/// doesn't open with `backup_key` for `user` (another user's, or altered), `decrypt_failed`
/// (`previous_backup_keys`).
pub(super) fn opened_previous(
    sealed: &[u8],
    user: Uuid,
    backup_key: &[u8; 32],
) -> Result<Vec<EarlierKey>, Error> {
    let sealed = read_previous(sealed).ok_or_else(|| {
        invalid(
            "wrapped_previous_backup_keys",
            "the earlier backup keys are malformed",
        )
    })?;
    unseal_previous(&sealed, user, backup_key).ok_or_else(|| Error::DecryptFailed {
        kind: "previous_backup_keys".into(),
    })
}

/// Backup keys from before, sealed: `{v: 1, nonce, ct}`.
fn read_previous(bytes: &[u8]) -> Option<PreviousKeys> {
    from_cbor(bytes).filter(|sealed: &PreviousKeys| sealed.v == 1 && sealed.nonce.len() == NONCE)
}

/// The keys `sealed` holds, opened with `backup_key` for `user`, oldest first. Read through a scratch
/// buffer that's wiped after.
fn unseal_previous(
    sealed: &PreviousKeys,
    user: Uuid,
    backup_key: &[u8; 32],
) -> Option<Vec<EarlierKey>> {
    let plain = Zeroizing::new(
        cipher(backup_key)
            .ok()?
            .decrypt(
                Nonce::from_slice(&sealed.nonce),
                Payload {
                    msg: &sealed.ct,
                    aad: &associated(user),
                },
            )
            .ok()?,
    );
    let mut scratch = Zeroizing::new([0u8; 4096]);
    let mut bytes = plain.as_slice();
    let keys: Vec<EarlierKey> =
        ciborium::de::from_reader_with_buffer(&mut bytes, &mut scratch[..]).ok()?;
    bytes.is_empty().then_some(keys)
}

/// Keeps `keys`, the backup keys before `backup_key`, the current one, sealed with it; with none
/// to keep, no row.
pub(super) fn keep_previous(
    tx: &Tx<'_>,
    user: Uuid,
    backup_key: &[u8],
    keys: &[EarlierKey],
) -> Result<(), Error> {
    if keys.is_empty() {
        tx.conn()
            .execute("DELETE FROM meta WHERE key = ?1", [PREVIOUS_BACKUP_KEYS])?;
        return Ok(());
    }
    let mut plain = Zeroizing::new(Vec::with_capacity(keys.len() * EARLIER_KEY_ROOM));
    ciborium::into_writer(&keys, &mut *plain)
        .map_err(|_| Error::Internal("a CBOR value couldn't be written".into()))?;
    let nonce = random(tx.provider().rand(), NONCE)?.to_vec();
    let ct = cipher(backup_key)?
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plain,
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
