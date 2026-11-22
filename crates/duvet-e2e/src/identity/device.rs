//! This device's keys, and the key packages it hands out so others can add it to their groups.

use duvet_e2e_rules::{SUITE, leaf_capabilities};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};
use openmls::prelude::{KeyPackage, KeyPackageBundle, KeyPackageRef, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::storage::StorageProvider;
use rusqlite::params;
use serde::Serialize;
use uuid::Uuid;

use super::random;
use crate::protocol::b64;
use crate::{Error, SqlStorageError, Tx};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// The single-use key packages a device keeps published, besides its one of last resort.
const SINGLE_USE: usize = 100;
/// A key package with less than this left is replaced.
const RENEW_BEFORE_MS: i64 = 14 * DAY_MS;
/// The server's queue keeps a welcome this long, so a key package's private keys stay this long
/// after its end, for a welcome sent just before it.
const QUEUE_KEEPS_MS: i64 = 45 * DAY_MS;

#[derive(Serialize)]
pub(crate) struct CreatedDevice {
    #[serde(with = "b64")]
    signature_key: Vec<u8>,
    #[serde(with = "b64")]
    hpke_key: Vec<u8>,
}

/// This installation's device: an Ed25519 key for its leaves, kept in OpenMLS's storage, and an
/// X25519 key for the messages devices send each other.
pub(crate) fn create_device(
    tx: &mut Tx<'_>,
    user: Uuid,
    device: Uuid,
) -> Result<CreatedDevice, Error> {
    let exists: bool = tx
        .conn()
        .query_row("SELECT EXISTS (SELECT 1 FROM device)", [], |row| row.get(0))?;
    if exists {
        return Err(Error::Exists {
            what: "device".into(),
        });
    }
    let provider = tx.provider();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
        .map_err(|_| Error::Internal("the device's signature key couldn't be made".into()))?;
    signer.store(provider.storage()).map_err(storage)?;
    let ikm = random(provider.rand(), 32)?;
    let hpke = provider
        .crypto()
        .derive_hpke_keypair(SUITE.hpke_config(), &ikm)
        .map_err(|_| Error::Internal("the device's HPKE key couldn't be made".into()))?;
    tx.conn().execute(
        "INSERT INTO device (id, user_id, device_id, signature_key, hpke_public, hpke_private, \
         created_at) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            user.as_bytes().as_slice(),
            device.as_bytes().as_slice(),
            signer.public(),
            hpke.public,
            &*hpke.private,
            tx.now(),
        ],
    )?;
    Ok(CreatedDevice {
        signature_key: signer.to_public_vec(),
        hpke_key: hpke.public,
    })
}

#[derive(Serialize)]
pub(crate) struct KeyPackages {
    key_packages: Vec<Published>,
}

#[derive(Serialize)]
struct Published {
    /// Its reference (RFC 9420's `KeyPackageRef`).
    #[serde(with = "b64")]
    id: Vec<u8>,
    /// The `KeyPackage`, TLS-encoded.
    #[serde(with = "b64")]
    data: Vec<u8>,
    expires_at: i64,
    last_resort: bool,
}

/// The key packages to publish: enough new ones that 100 single-use ones and one of last resort
/// have 14 days or more left. A welcome uses up a single-use key package, and OpenMLS deletes it,
/// so only those still in its storage count. Their lifetime is OpenMLS's default, 84 days.
pub(crate) fn key_packages(tx: &mut Tx<'_>) -> Result<KeyPackages, Error> {
    let own = tx.own_device()?;
    let credential = own.credential()?;
    let now = tx.now();
    let provider = tx.provider();

    let mut stored: Vec<Vec<u8>> = Vec::new();
    for hash_ref in tx
        .conn()
        .prepare("SELECT hash_ref FROM key_packages")?
        .query_map([], |row| row.get(0))?
    {
        stored.push(hash_ref?);
    }
    let (mut single_use, mut last_resorts) = (0, 0);
    for hash_ref in stored {
        let key_ref = key_package_ref(&hash_ref)?;
        let bundle: Option<KeyPackageBundle> =
            provider.storage().key_package(&key_ref).map_err(storage)?;
        let Some(bundle) = bundle else {
            // A welcome used it up.
            forget(tx, &hash_ref)?;
            continue;
        };
        let key_package = bundle.key_package();
        let expires_at = expires_at(key_package)?;
        if expires_at.saturating_add(QUEUE_KEEPS_MS) < now {
            provider
                .storage()
                .delete_key_package(&key_ref)
                .map_err(storage)?;
            forget(tx, &hash_ref)?;
        } else if expires_at.saturating_sub(now) >= RENEW_BEFORE_MS
            && key_package.leaf_node().credential() == &credential.credential
        {
            if key_package.last_resort() {
                last_resorts += 1;
            } else {
                single_use += 1;
            }
        }
    }

    let wanted = std::iter::repeat_n(false, SINGLE_USE.saturating_sub(single_use))
        .chain(std::iter::repeat_n(true, usize::from(last_resorts == 0)));
    let mut published = Vec::new();
    for last_resort in wanted {
        let mut builder = KeyPackage::builder().leaf_node_capabilities(leaf_capabilities());
        if last_resort {
            builder = builder.mark_as_last_resort();
        }
        let bundle = builder
            .build(SUITE, provider, &own.signer, credential.clone())
            .map_err(|error| Error::Internal(format!("a key package couldn't be made: {error}")))?;
        let key_package = bundle.key_package();
        let id = key_package
            .hash_ref(provider.crypto())
            .map_err(|_| Error::Internal("a key package's reference couldn't be made".into()))?
            .as_slice()
            .to_vec();
        let expires_at = expires_at(key_package)?;
        tx.conn().execute(
            "INSERT INTO key_packages (hash_ref, expires_at, last_resort, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![id, expires_at, last_resort, now],
        )?;
        let data = key_package
            .tls_serialize_detached()
            .map_err(|_| Error::Internal("a key package couldn't be encoded".into()))?;
        published.push(Published {
            id,
            data,
            expires_at,
            last_resort,
        });
    }
    Ok(KeyPackages {
        key_packages: published,
    })
}

/// The end of a key package's lifetime, in Unix milliseconds.
fn expires_at(key_package: &KeyPackage) -> Result<i64, Error> {
    i64::try_from(key_package.life_time().not_after())
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| Error::Internal("a key package's lifetime is out of range".into()))
}

/// The `KeyPackageRef` whose bytes are `hash_ref`, as OpenMLS's storage keys it.
fn key_package_ref(hash_ref: &[u8]) -> Result<KeyPackageRef, Error> {
    let encoded = VLBytes::new(hash_ref.to_vec())
        .tls_serialize_detached()
        .map_err(|_| Error::Internal("a key package reference couldn't be encoded".into()))?;
    KeyPackageRef::tls_deserialize_exact_bytes(&encoded)
        .map_err(|_| Error::Internal("a stored key package reference is malformed".into()))
}

fn forget(tx: &Tx<'_>, hash_ref: &[u8]) -> Result<(), Error> {
    tx.conn()
        .execute("DELETE FROM key_packages WHERE hash_ref = ?1", [hash_ref])?;
    Ok(())
}

fn storage(error: SqlStorageError) -> Error {
    Error::Storage(error.to_string())
}
