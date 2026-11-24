//! The user's identity: made on their first device, it signs each device's certificate and the
//! list of their devices.

use duvet_e2e_rules::{DeviceCertificate, DeviceList};
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_KEY, IDENTITY_SECRET, Identity, meta_get, meta_put,
    not_found, random, recovery, unix_ms,
};
use crate::messages::Empty;
use crate::protocol::b64;
use crate::{Error, OwnDevice, Tx};

/// `meta`'s row for what the last identity command made for the server, until the client confirms
/// its upload (`identity_uploaded`): [`Kept`], as the command's reply, in JSON.
const KEPT_IDENTITY: &str = "kept_identity";

/// Room for a kept identity's JSON besides its blobs: its buffer is sized ahead, so no copy of the
/// recovery key is left behind as it grows.
const KEPT_ROOM: usize = 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatedIdentity {
    #[serde(with = "b64")]
    identity_key: Vec<u8>,
    #[serde(with = "b64")]
    certificate: Vec<u8>,
    #[serde(with = "b64")]
    pub(super) device_list: Vec<u8>,
    #[serde(
        serialize_with = "secret_text",
        deserialize_with = "super::recover::secret_text"
    )]
    recovery_key: Zeroizing<String>,
    #[serde(with = "b64")]
    wrapped_backup_key: Vec<u8>,
    #[serde(with = "b64")]
    encrypted_identity: Vec<u8>,
}

/// What an identity command made for the server, kept until the client confirms its upload, so
/// the command run again hands it out again: its recovery key is in no other place.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Kept {
    pub(super) created: CreatedIdentity,
    /// A rotation's: the backup keys before the new one, sealed with it.
    #[serde(default, with = "b64::option", skip_serializing_if = "Option::is_none")]
    pub(super) wrapped_previous_backup_keys: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) rotation: Option<KeptRotation>,
}

/// A rotation's devices it removed, in order, and what its transfers carry of the identity
/// before: the rotating device's certificate and the user's list.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeptRotation {
    pub(super) removed: Vec<Uuid>,
    #[serde(with = "b64")]
    pub(super) sender: Vec<u8>,
    #[serde(with = "b64")]
    pub(super) previous_list: Vec<u8>,
}

/// Keeps what an identity command made for the server, in place of anything kept before.
pub(super) fn keep(tx: &Tx<'_>, kept: &Kept) -> Result<(), Error> {
    let rotation = kept.rotation.as_ref().map_or(0, |rotation| {
        rotation.sender.len() + rotation.previous_list.len() + rotation.removed.len() * 40
    });
    let blobs = kept.created.certificate.len()
        + kept.created.device_list.len()
        + kept.created.wrapped_backup_key.len()
        + kept.created.encrypted_identity.len()
        + kept
            .wrapped_previous_backup_keys
            .as_ref()
            .map_or(0, Vec::len)
        + rotation;
    let mut row = Zeroizing::new(Vec::with_capacity(KEPT_ROOM + blobs * 2));
    serde_json::to_writer(&mut *row, kept)
        .map_err(|_| Error::Internal("the kept identity couldn't be written".into()))?;
    meta_put(tx, KEPT_IDENTITY, &row)
}

/// What the last identity command made, while the client hasn't confirmed its upload.
pub(super) fn kept(tx: &Tx<'_>) -> Result<Option<Kept>, Error> {
    let Some(row) = meta_get(tx, KEPT_IDENTITY)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    serde_json::from_slice(&row)
        .map(Some)
        .map_err(|_| Error::Internal("the kept identity is malformed".into()))
}

/// The server took what the last identity command made: its kept copy, the recovery key with it,
/// goes (wiped: the database deletes securely). Nothing kept is `not_found` (`upload`).
pub(crate) fn identity_uploaded(tx: &mut Tx<'_>) -> Result<Empty, Error> {
    let deleted = tx
        .conn()
        .execute("DELETE FROM meta WHERE key = ?1", [KEPT_IDENTITY])?;
    if deleted == 0 {
        return Err(not_found("upload"));
    }
    Ok(Empty {})
}

/// The identity, on this device: it certifies the device, starts the device list at version 1, and
/// a backup key wrapped by a new recovery key encrypts it. The reply is kept until the client
/// confirms its upload (`identity_uploaded`), and the command run again until then answers it
/// again; after it, `exists`.
pub(crate) fn create_identity(tx: &mut Tx<'_>) -> Result<CreatedIdentity, Error> {
    let own = tx.own_device()?;
    if meta_get(tx, IDENTITY_KEY)?.is_some() {
        return match kept(tx)? {
            Some(Kept {
                created,
                rotation: None,
                ..
            }) => Ok(created),
            _ => Err(Error::Exists {
                what: "identity".into(),
            }),
        };
    }
    let (created, _) = new_identity(tx, &own, vec![own.device])?;
    keep(
        tx,
        &Kept {
            created: created.clone(),
            wrapped_previous_backup_keys: None,
            rotation: None,
        },
    )?;
    Ok(created)
}

/// A new identity for this device's user, in place of any the device had: it certifies the device
/// and signs `devices` as the user's list, from version 1, and a new backup key, wrapped by a new
/// recovery key, encrypts it. The reply, and the new backup key.
pub(super) fn new_identity(
    tx: &Tx<'_>,
    own: &OwnDevice,
    devices: Vec<Uuid>,
) -> Result<(CreatedIdentity, Zeroizing<Vec<u8>>), Error> {
    let rand = tx.provider().rand();
    let secret = random(rand, 32)?;
    let secret = thirty_two(&secret)?;
    let identity = Identity::from_secret(secret);

    let signature_key = own
        .signer
        .public()
        .try_into()
        .map_err(|_| Error::Internal("the device's signature key isn't 32 bytes".into()))?;
    let hpke_key = own
        .hpke
        .public
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal("the device's HPKE key isn't 32 bytes".into()))?;
    let certificate =
        DeviceCertificate::new(own.user, own.device, signature_key, hpke_key, unix_ms(tx)?)
            .sign(&identity.signer)
            .map_err(signing)?;
    let device_list = DeviceList::new(own.user, identity.public, 1, devices)
        .sign(&identity.signer)
        .map_err(signing)?;

    let backup = random(rand, 32)?;
    let backup_key = thirty_two(&backup)?;
    let recovery_key = recovery::generate(rand)?;
    let wrapped_backup_key = recovery::wrap_backup_key(
        rand,
        &*recovery::parse(&recovery_key)?,
        own.user,
        backup_key,
    )?;
    let encrypted_identity = recovery::encrypt_identity(rand, backup_key, own.user, secret)?;

    tx.conn()
        .execute("UPDATE device SET certificate = ?1", [&certificate])?;
    meta_put(tx, IDENTITY_KEY, &identity.public)?;
    meta_put(tx, IDENTITY_SECRET, secret)?;
    meta_put(tx, DEVICE_LIST, &device_list)?;
    meta_put(tx, BACKUP_KEY, backup_key)?;
    let created = CreatedIdentity {
        identity_key: identity.public.to_vec(),
        certificate,
        device_list,
        recovery_key,
        wrapped_backup_key,
        encrypted_identity,
    };
    Ok((created, backup))
}

#[derive(Serialize)]
pub(crate) struct SignedList {
    #[serde(with = "b64")]
    device_list: Vec<u8>,
}

/// The user's device list without `remove`, signed under the next version.
pub(crate) fn sign_device_list(tx: &mut Tx<'_>, remove: &[Uuid]) -> Result<SignedList, Error> {
    let identity = tx.own_identity()?.ok_or_else(|| not_found("identity"))?;
    let user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    let current = tx
        .device_list_of(user)?
        .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
    if remove.iter().any(|device| !current.contains(*device)) {
        return Err(not_found("device"));
    }
    let version = current
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Internal("the device list's version is at its end".into()))?;
    let devices = current
        .devices
        .iter()
        .copied()
        .filter(|device| !remove.contains(device))
        .collect();
    let device_list = DeviceList::new(user, identity.public, version, devices)
        .sign(&identity.signer)
        .map_err(signing)?;
    meta_put(tx, DEVICE_LIST, &device_list)?;
    Ok(SignedList { device_list })
}

fn thirty_two(bytes: &[u8]) -> Result<&[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Internal("a key isn't 32 bytes".into()))
}

fn signing(_: openmls_traits::signatures::SignerError) -> Error {
    Error::Internal("the identity couldn't sign".into())
}

fn secret_text<S: Serializer>(text: &Zeroizing<String>, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(text)
}
