//! The user's identity: made on their first device, it signs each device's certificate and the
//! list of their devices.

use duvet_e2e_rules::{DeviceCertificate, DeviceList};
use openmls_traits::OpenMlsProvider;
use serde::{Serialize, Serializer};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_KEY, IDENTITY_SECRET, Identity, meta_get, meta_put,
    not_found, random, recovery, unix_ms,
};
use crate::protocol::b64;
use crate::{Error, OwnDevice, Tx};

#[derive(Serialize)]
pub(crate) struct CreatedIdentity {
    #[serde(with = "b64")]
    identity_key: Vec<u8>,
    #[serde(with = "b64")]
    certificate: Vec<u8>,
    #[serde(with = "b64")]
    device_list: Vec<u8>,
    #[serde(serialize_with = "secret_text")]
    recovery_key: Zeroizing<String>,
    #[serde(with = "b64")]
    wrapped_backup_key: Vec<u8>,
    #[serde(with = "b64")]
    encrypted_identity: Vec<u8>,
}

/// The identity, on this device: it certifies the device, starts the device list at version 1, and
/// a backup key wrapped by a new recovery key encrypts it. The recovery key is in the reply alone.
pub(crate) fn create_identity(tx: &mut Tx<'_>) -> Result<CreatedIdentity, Error> {
    let own = tx.own_device()?;
    if meta_get(tx, IDENTITY_KEY)?.is_some() {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    Ok(new_identity(tx, &own, vec![own.device])?.0)
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
