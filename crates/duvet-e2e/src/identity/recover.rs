//! A new device of the user's, recovered with the recovery key: it opens the backup key the server
//! keeps, which the recovery key wraps, and with the backup key the identity, then certifies itself
//! and signs the user's next device list, with itself on it.

use std::fmt;

use duvet_e2e_rules::{DeviceCertificate, DeviceList, RuleViolation};
use openmls_traits::signatures::SignerError;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

use super::rotate::{keep_previous, opened_previous};
use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_KEY, IDENTITY_SECRET, Identity, invalid, meta_put, recovery,
    unix_ms,
};
use crate::protocol::b64;
use crate::{Error, Tx};

#[derive(Debug, Deserialize)]
pub(crate) struct Recover {
    /// As the person typed it.
    #[serde(deserialize_with = "secret_text")]
    recovery_key: Zeroizing<String>,
    /// What the server keeps for the user: the backup key the recovery key wraps, and the
    /// identity the backup key encrypts.
    #[serde(with = "b64")]
    wrapped_backup_key: Vec<u8>,
    #[serde(with = "b64")]
    encrypted_identity: Vec<u8>,
    /// The user's latest device list, as the server serves it.
    #[serde(with = "b64")]
    device_list: Vec<u8>,
    /// The backup keys from before the current one, sealed with it, which the server keeps beside
    /// the wrapped backup key once the user changed keys (`rotate_keys`): with them, this device
    /// opens the backup's segments those keys encrypted.
    #[serde(default, with = "b64::option")]
    wrapped_previous_backup_keys: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub(crate) struct Recovered {
    #[serde(with = "b64")]
    certificate: Vec<u8>,
    #[serde(with = "b64")]
    device_list: Vec<u8>,
}

/// This device takes the user's identity with the recovery key, certifies itself with it, and signs
/// the next version of the user's list with itself added: the certificate and the list are for the
/// server. It keeps the backup keys from before the current one, when the server gives them. A key
/// that doesn't open what the server keeps, earlier keys that don't open with the backup key for
/// this user, or a list the identity didn't sign, change nothing.
pub(crate) fn recover(tx: &mut Tx<'_>, request: Recover) -> Result<Recovered, Error> {
    let own = tx.own_device()?;
    if tx.own_identity_key()?.is_some() {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    let recovery_key = recovery::parse(&request.recovery_key)?;
    let backup_key =
        recovery::unwrap_backup_key(&recovery_key, own.user, &request.wrapped_backup_key)?;
    let secret = recovery::decrypt_identity(&backup_key, own.user, &request.encrypted_identity)?;
    let previous = request
        .wrapped_previous_backup_keys
        .as_deref()
        .map(|sealed| opened_previous(sealed, own.user, &backup_key))
        .transpose()?;
    let identity = Identity::from_secret(&secret);

    let current =
        DeviceList::verify(&request.device_list, &identity.public).map_err(
            |error| match error {
                RuleViolation::InvalidSignature => Error::InvalidSignature {
                    what: "device_list".into(),
                },
                _ => invalid("device_list", "the device list is malformed"),
            },
        )?;
    if current.user != own.user {
        return Err(rule("wrong_user"));
    }
    let version = current
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Internal("the device list's version is at its end".into()))?;
    let mut devices = current.devices;
    devices.push(own.device);

    let certificate = DeviceCertificate::new(
        own.user,
        own.device,
        thirty_two(own.signer.public())?,
        thirty_two(&own.hpke.public)?,
        unix_ms(tx)?,
    )
    .sign(&identity.signer)
    .map_err(signing)?;
    let device_list = DeviceList::new(own.user, identity.public, version, devices)
        .sign(&identity.signer)
        .map_err(signing)?;
    install(
        tx,
        &secret,
        &identity.public,
        &certificate,
        &device_list,
        &backup_key,
    )?;
    if let Some(keys) = &previous {
        keep_previous(tx, own.user, &*backup_key, keys)?;
    }
    Ok(Recovered {
        certificate,
        device_list,
    })
}

/// This device's identity from now on, recovered or transferred: the identity's secret and public
/// key, the device's certificate, the user's device list and the backup key. Whatever approval was
/// under way has nothing left to bring.
pub(super) fn install(
    tx: &Tx<'_>,
    secret: &[u8; 32],
    public: &[u8; 32],
    certificate: &[u8],
    device_list: &[u8],
    backup_key: &[u8; 32],
) -> Result<(), Error> {
    tx.conn()
        .execute("UPDATE device SET certificate = ?1", [certificate])?;
    meta_put(tx, IDENTITY_KEY, public)?;
    meta_put(tx, IDENTITY_SECRET, secret)?;
    meta_put(tx, DEVICE_LIST, device_list)?;
    meta_put(tx, BACKUP_KEY, backup_key)?;
    tx.conn().execute("DELETE FROM approvals", [])?;
    Ok(())
}

/// A change the rules of identities don't allow, by name.
pub(super) fn rule(name: &str) -> Error {
    Error::RuleViolation { rule: name.into() }
}

pub(super) fn signing(_: SignerError) -> Error {
    Error::Internal("the identity couldn't sign".into())
}

pub(super) fn thirty_two(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Internal("a key isn't 32 bytes".into()))
}

/// A secret the command holds as text, read into memory that's wiped as it drops.
pub(super) fn secret_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    struct Text;

    impl Visitor<'_> for Text {
        type Value = Zeroizing<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a recovery key")
        }

        fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
            Ok(Zeroizing::new(text.to_owned()))
        }
    }

    deserializer.deserialize_str(Text)
}
