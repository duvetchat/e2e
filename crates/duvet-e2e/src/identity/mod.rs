//! The user's identity and this device: its keys, its certificate and the user's device list, the
//! other users' identities this device pinned, and the key packages it hands out.

mod approval;
mod certificates;
mod contacts;
mod device;
// The plan's layout: create_identity and sign_device_list are in identity/identity.rs.
#[allow(clippy::module_inception)]
mod identity;
mod recover;
pub mod recovery;
mod rotate;

pub(crate) use approval::{
    ApprovalAccept, ApprovalCheck, ApprovalConfirm, ApprovalFromQr, ApprovalOffer, ApprovalReceive,
    ApprovalReveal, Enrolled, TRANSFER as APPROVAL_TRANSFER, approval_accept, approval_begin,
    approval_check, approval_confirm, approval_from_qr, approval_offer, approval_receive,
    approval_reveal, receive_transfer,
};
pub(crate) use certificates::{keep_certificates, keep_earlier_identity};
pub(crate) use contacts::{device_list_uploaded, observe_user, safety_number, verify_user};
pub(crate) use device::{create_device, key_packages};
pub(crate) use identity::{create_identity, identity_uploaded, sign_device_list, waiting_upload};
pub(crate) use recover::{Recover, recover};
pub(crate) use rotate::{
    ROTATION_TRANSFER, Transferred, receive_rotation, renewed_at, reset_identity, rotate_keys,
};

use duvet_e2e_rules::DeviceList;
use openmls::prelude::{BasicCredential, CredentialWithKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::HpkeKeyPair;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{Error, Tx};

/// `meta`'s rows for the identity: its public key and its secret (the Ed25519 seed), the user's
/// latest device list, and the backup key the recovery key wraps.
pub(crate) const IDENTITY_KEY: &str = "identity_key";
pub(crate) const IDENTITY_SECRET: &str = "identity_secret";
pub(crate) const DEVICE_LIST: &str = "device_list";
pub(crate) const BACKUP_KEY: &str = "backup_key";

/// This installation's device: who it belongs to, and its keys.
pub struct OwnDevice {
    pub user: Uuid,
    pub device: Uuid,
    /// The Ed25519 key that signs its leaves, kept in OpenMLS's storage.
    pub signer: SignatureKeyPair,
    /// Its certificate, signed by the user's identity; none until the device has the identity.
    pub certificate: Option<Vec<u8>>,
    /// Its X25519 key, for the messages devices send each other.
    pub hpke: HpkeKeyPair,
}

impl OwnDevice {
    /// Its MLS credential: its certificate as a basic credential, with its signature key.
    pub fn credential(&self) -> Result<CredentialWithKey, Error> {
        let certificate = self
            .certificate
            .clone()
            .ok_or_else(|| not_found("identity"))?;
        Ok(CredentialWithKey {
            credential: BasicCredential::new(certificate).into(),
            signature_key: self.signer.public().into(),
        })
    }
}

/// The user's identity as this device holds it: the key that signs their devices' certificates
/// and their device list.
pub(crate) struct Identity {
    pub(crate) public: [u8; 32],
    pub(crate) signer: SignatureKeyPair,
}

impl Identity {
    /// The identity whose Ed25519 secret (its 32-byte seed) is `secret`.
    pub(crate) fn from_secret(secret: &[u8; 32]) -> Identity {
        let public = ed25519_dalek::SigningKey::from_bytes(secret)
            .verifying_key()
            .to_bytes();
        let signer =
            SignatureKeyPair::from_raw(SignatureScheme::ED25519, secret.to_vec(), public.to_vec());
        Identity { public, signer }
    }
}

struct DeviceRow {
    user: Vec<u8>,
    device: Vec<u8>,
    signature_key: Vec<u8>,
    hpke_public: Vec<u8>,
    hpke_private: Zeroizing<Vec<u8>>,
    certificate: Option<Vec<u8>>,
}

impl Tx<'_> {
    /// This installation's device and its keys.
    pub fn own_device(&self) -> Result<OwnDevice, Error> {
        let row = self
            .conn()
            .query_row(
                "SELECT user_id, device_id, signature_key, hpke_public, hpke_private, certificate \
                 FROM device",
                [],
                |row| {
                    Ok(DeviceRow {
                        user: row.get(0)?,
                        device: row.get(1)?,
                        signature_key: row.get(2)?,
                        hpke_public: row.get(3)?,
                        hpke_private: Zeroizing::new(row.get(4)?),
                        certificate: row.get(5)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| not_found("device"))?;
        let hpke = HpkeKeyPair {
            private: row.hpke_private.as_slice().into(),
            public: row.hpke_public,
        };
        let signer = SignatureKeyPair::read(
            self.provider().storage(),
            &row.signature_key,
            SignatureScheme::ED25519,
        )
        .ok_or_else(|| Error::Internal("the device's signature key isn't stored".into()))?;
        Ok(OwnDevice {
            user: stored_uuid(&row.user)?,
            device: stored_uuid(&row.device)?,
            signer,
            certificate: row.certificate,
            hpke,
        })
    }

    /// `user`'s identity key: this device's own for its user, else the one `observe_user` pinned.
    pub fn identity_of(&self, user: Uuid) -> Result<Option<[u8; 32]>, Error> {
        if self.own_user()? == Some(user) {
            return self.own_identity_key();
        }
        let key: Option<Vec<u8>> = self
            .conn()
            .query_row(
                "SELECT identity_key FROM contacts WHERE user_id = ?1",
                [user.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        key.map(|key| stored_key(&key)).transpose()
    }

    /// `user`'s latest device list this device accepted, verified again with their identity.
    pub fn device_list_of(&self, user: Uuid) -> Result<Option<DeviceList>, Error> {
        let stored: Option<(Vec<u8>, Vec<u8>)> = if self.own_user()? == Some(user) {
            match (self.own_identity_key()?, meta_get(self, DEVICE_LIST)?) {
                (Some(key), Some(list)) => Some((key.to_vec(), list)),
                _ => None,
            }
        } else {
            self.conn()
                .query_row(
                    "SELECT identity_key, device_list FROM contacts WHERE user_id = ?1",
                    [user.as_bytes().as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
        };
        let Some((key, list)) = stored else {
            return Ok(None);
        };
        DeviceList::verify(&list, &stored_key(&key)?)
            .map(Some)
            .map_err(|_| Error::Internal("a stored device list doesn't verify".into()))
    }

    /// The user this installation's device belongs to.
    pub(crate) fn own_user(&self) -> Result<Option<Uuid>, Error> {
        let user: Option<Vec<u8>> = self
            .conn()
            .query_row("SELECT user_id FROM device", [], |row| row.get(0))
            .optional()?;
        user.map(|user| stored_uuid(&user)).transpose()
    }

    pub(crate) fn own_identity_key(&self) -> Result<Option<[u8; 32]>, Error> {
        meta_get(self, IDENTITY_KEY)?
            .map(|key| stored_key(&key))
            .transpose()
    }

    /// The identity's signing key, once this device has the identity.
    pub(crate) fn own_identity(&self) -> Result<Option<Identity>, Error> {
        let Some(secret) = meta_get(self, IDENTITY_SECRET)?.map(Zeroizing::new) else {
            return Ok(None);
        };
        let secret: &[u8; 32] = secret
            .as_slice()
            .try_into()
            .map_err(|_| Error::Internal("the stored identity is malformed".into()))?;
        let identity = Identity::from_secret(secret);
        if Some(identity.public) != self.own_identity_key()? {
            return Err(Error::Internal(
                "the stored identity doesn't match its key".into(),
            ));
        }
        Ok(Some(identity))
    }
}

pub(crate) fn meta_get(tx: &Tx<'_>, key: &str) -> Result<Option<Vec<u8>>, Error> {
    Ok(tx
        .conn()
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

pub(crate) fn meta_put(tx: &Tx<'_>, key: &str, value: &[u8]) -> Result<(), Error> {
    tx.conn().execute(
        "INSERT INTO meta (key, value) VALUES (?1, ?2) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

/// `len` random bytes from OpenMLS's provider, wiped as they drop.
pub(crate) fn random(rand: &impl OpenMlsRand, len: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    rand.random_vec(len)
        .map(Zeroizing::new)
        .map_err(|_| Error::Internal("no randomness".into()))
}

/// The time of the command, in Unix milliseconds, for a signed object.
pub(crate) fn unix_ms(tx: &Tx<'_>) -> Result<u64, Error> {
    u64::try_from(tx.now()).map_err(|_| Error::Internal("the clock is before 1970".into()))
}

pub(crate) fn to_cbor(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out)
        .map_err(|_| Error::Internal("a CBOR value couldn't be written".into()))?;
    Ok(out)
}

/// Exactly one CBOR value, nested `CBOR_DEPTH` levels at most, and nothing after it.
pub(crate) fn from_cbor<T: DeserializeOwned>(mut bytes: &[u8]) -> Option<T> {
    let value =
        ciborium::de::from_reader_with_recursion_limit(&mut bytes, duvet_e2e_rules::CBOR_DEPTH)
            .ok()?;
    bytes.is_empty().then_some(value)
}

pub(crate) fn not_found(what: &str) -> Error {
    Error::NotFound { what: what.into() }
}

/// A field the command holds that the core can't take. The message is fixed: it never quotes the value.
pub(crate) fn invalid(field: &str, message: &'static str) -> Error {
    Error::BadCommand {
        message,
        field: Some(field.into()),
    }
}

pub(crate) fn stored_uuid(bytes: &[u8]) -> Result<Uuid, Error> {
    Uuid::from_slice(bytes).map_err(|_| Error::Internal("a stored ID is malformed".into()))
}

pub(crate) fn stored_key(bytes: &[u8]) -> Result<[u8; 32], Error> {
    bytes
        .try_into()
        .map_err(|_| Error::Internal("a stored key is malformed".into()))
}
