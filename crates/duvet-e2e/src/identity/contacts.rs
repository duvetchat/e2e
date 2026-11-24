//! Other users' identities: pinned the first time they're seen, their device lists kept current,
//! and checked by the people themselves with the safety number.

use duvet_e2e_rules::{DeviceCertificate, DeviceList, RuleViolation};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::{
    DEVICE_LIST, from_cbor, invalid, keep_certificates, meta_get, meta_put, not_found, stored_key,
    to_cbor,
};
use crate::messages::Empty;
use crate::protocol::b64;
use crate::{Error, Tx};

const SAFETY_NUMBER_LABEL: &[u8] = b"duvet safety number v1";

/// `meta`'s row for this device's own user's list as the server is known to hold it: the client
/// confirmed its upload (`device_list_uploaded`), or the server served it.
const LIST_ON_SERVER: &str = "device_list_on_server";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum State {
    /// Seen for the first time: pinned.
    New,
    /// The identity pinned, with the same list or a newer one.
    Same,
    /// Another identity than the one pinned, which it replaces: their contacts are told.
    Changed,
    /// Not taken: `reason` says why.
    Rejected,
}

#[derive(Serialize)]
pub(crate) struct Observation {
    state: State,
    /// Whether the person verified the identity now pinned.
    verified: bool,
    /// With `changed`: whether the person had verified the identity it replaced.
    #[serde(skip_serializing_if = "Option::is_none")]
    was_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

/// A user as pinned: their identity, their latest list, and whether the person verified them.
struct Pinned {
    identity_key: [u8; 32],
    list: DeviceList,
    verified: bool,
}

/// What the server says of `user`: their identity, their device list and their devices'
/// certificates. The identity is pinned the first time; then a newer list of the same identity
/// replaces the old one, and another identity replaces the pinned one, which is kept.
pub(crate) fn observe_user(
    tx: &mut Tx<'_>,
    user: Uuid,
    identity_key: &[u8],
    device_list: &[u8],
    certificates: &[Vec<u8>],
) -> Result<Observation, Error> {
    let identity_key: [u8; 32] = identity_key
        .try_into()
        .map_err(|_| invalid("identity_key", "the identity key isn't 32 bytes"))?;
    let list = DeviceList::verify(device_list, &identity_key).map_err(|error| {
        refused(
            error,
            "device_list",
            "device_list",
            "the device list is malformed",
        )
    })?;
    let signed = || certificates.iter().map(Vec::as_slice);
    let certificates = certificates
        .iter()
        .map(|certificate| {
            DeviceCertificate::verify(certificate, &identity_key).map_err(|error| {
                refused(
                    error,
                    "certificate",
                    "certificates",
                    "a certificate is malformed",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let version = i64::try_from(list.version)
        .map_err(|_| invalid("device_list", "the device list's version is out of range"))?;

    // The client observed the user anew: what `apply` asked about them was looked at. But not for
    // this device's own user under an identity it doesn't hold (a rotation whose transfer it hasn't
    // taken yet): those asks stay open, and the queue waits for the transfer instead of blocking.
    let own = tx.own_user()? == Some(user);
    if !own || tx.own_identity_key()? == Some(identity_key) {
        tx.conn().execute(
            "UPDATE observe_asks SET observed = 1 WHERE user_id = ?1",
            [user.as_bytes().as_slice()],
        )?;
    }

    let pinned = if own {
        let key = tx
            .own_identity_key()?
            .ok_or_else(|| not_found("identity"))?;
        let list = tx
            .device_list_of(user)?
            .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
        Some(Pinned {
            identity_key: key,
            list,
            // A device trusts its own user's identity: it holds it.
            verified: true,
        })
    } else {
        pinned(tx, user)?
    };
    let verified = pinned.as_ref().is_some_and(|pinned| pinned.verified);
    let rejected = |reason| {
        Ok(Observation {
            state: State::Rejected,
            verified,
            was_verified: None,
            reason: Some(reason),
        })
    };

    if list.user != user || certificates.iter().any(|c| c.user != user) {
        return rejected("wrong_user");
    }
    if certificates.iter().any(|c| !list.contains(c.device)) {
        return rejected("unlisted_device");
    }

    let Some(pinned) = pinned else {
        tx.conn().execute(
            "INSERT INTO contacts (user_id, identity_key, device_list, list_version, verified, \
             updated_at) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
            params![
                user.as_bytes().as_slice(),
                identity_key.as_slice(),
                device_list,
                version,
                tx.now()
            ],
        )?;
        keep_certificates(tx, user, signed(), true)?;
        return Ok(Observation {
            state: State::New,
            verified: false,
            was_verified: None,
            reason: None,
        });
    };

    if pinned.identity_key == identity_key {
        if list.version < pinned.list.version {
            return rejected("older_list");
        }
        // This device's own list, of a version the server holds another of, which the identity
        // signed: the server's compare-and-set chose that one, and this one's upload never landed.
        // Once the server is known to hold this device's list (the client confirmed its upload, or
        // the server served it), another of that version is a conflict.
        let lost = own
            && list.version == pinned.list.version
            && !on_server(tx, &identity_key, &pinned.list)?;
        if !list.accepts_after(Some(&pinned.list)) && !lost {
            return rejected("conflicting_list");
        }
        if own {
            meta_put(tx, DEVICE_LIST, device_list)?;
            meta_put(tx, LIST_ON_SERVER, device_list)?;
        } else {
            tx.conn().execute(
                "UPDATE contacts SET device_list = ?2, list_version = ?3, updated_at = ?4 \
                 WHERE user_id = ?1",
                params![user.as_bytes().as_slice(), device_list, version, tx.now()],
            )?;
        }
        keep_certificates(tx, user, signed(), false)?;
        return Ok(Observation {
            state: State::Same,
            verified,
            was_verified: None,
            reason: None,
        });
    }

    // This device holds its own user's identity, which no list from the server replaces.
    if own {
        return rejected("not_own_identity");
    }
    // The pinned identity joins the ones the user had; the new one, if it was one of them, leaves.
    tx.conn().execute(
        "INSERT INTO contact_identities (user_id, identity_key, replaced_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (user_id, identity_key) DO UPDATE SET replaced_at = excluded.replaced_at",
        params![
            user.as_bytes().as_slice(),
            pinned.identity_key.as_slice(),
            tx.now()
        ],
    )?;
    tx.conn().execute(
        "DELETE FROM contact_identities WHERE user_id = ?1 AND identity_key = ?2",
        params![user.as_bytes().as_slice(), identity_key.as_slice()],
    )?;
    tx.conn().execute(
        "UPDATE contacts SET identity_key = ?2, device_list = ?3, list_version = ?4, \
         verified = 0, updated_at = ?5 WHERE user_id = ?1",
        params![
            user.as_bytes().as_slice(),
            identity_key.as_slice(),
            device_list,
            version,
            tx.now()
        ],
    )?;
    keep_certificates(tx, user, signed(), true)?;
    Ok(Observation {
        state: State::Changed,
        verified: false,
        was_verified: Some(pinned.verified),
        reason: None,
    })
}

/// Whether the server is known to hold `list`, this device's own user's list, under
/// `identity_key`.
fn on_server(tx: &Tx<'_>, identity_key: &[u8; 32], list: &DeviceList) -> Result<bool, Error> {
    Ok(meta_get(tx, LIST_ON_SERVER)?
        .and_then(|held| DeviceList::verify(&held, identity_key).ok())
        .is_some_and(|held| held == *list))
}

/// The client's word that the server took its upload of the list this device holds for its own
/// user, of `version` (as `sign_device_list`, `recover` or an approval made it): from then on, no
/// other list of that version replaces it. `not_found` `upload` when the list this device holds is
/// of another version (a newer one replaced it since).
pub(crate) fn device_list_uploaded(tx: &mut Tx<'_>, version: u64) -> Result<Empty, Error> {
    let user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    let held = tx
        .device_list_of(user)?
        .ok_or_else(|| not_found("identity"))?;
    if held.version != version {
        return Err(not_found("upload"));
    }
    let bytes = meta_get(tx, DEVICE_LIST)?.ok_or_else(|| not_found("identity"))?;
    meta_put(tx, LIST_ON_SERVER, &bytes)?;
    Ok(Empty {})
}

fn pinned(tx: &Tx<'_>, user: Uuid) -> Result<Option<Pinned>, Error> {
    let row: Option<(Vec<u8>, Vec<u8>, bool)> = tx
        .conn()
        .query_row(
            "SELECT identity_key, device_list, verified FROM contacts WHERE user_id = ?1",
            [user.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((identity_key, list, verified)) = row else {
        return Ok(None);
    };
    let identity_key = stored_key(&identity_key)?;
    let list = DeviceList::verify(&list, &identity_key)
        .map_err(|_| Error::Internal("a stored device list doesn't verify".into()))?;
    Ok(Some(Pinned {
        identity_key,
        list,
        verified,
    }))
}

/// A signed object that doesn't verify: `invalid_signature`, or `bad_command` when it isn't one.
fn refused(error: RuleViolation, what: &str, field: &str, malformed: &'static str) -> Error {
    match error {
        RuleViolation::InvalidSignature => Error::InvalidSignature { what: what.into() },
        _ => invalid(field, malformed),
    }
}

#[derive(Serialize)]
pub(crate) struct SafetyNumber {
    digits: String,
    #[serde(with = "b64")]
    qr: Vec<u8>,
}

/// The number two people compare to check each other's identity, and the QR one scans from the
/// other's screen. Both see the same.
pub(crate) fn safety_number(tx: &mut Tx<'_>, user: Uuid) -> Result<SafetyNumber, Error> {
    let (own, theirs) = pair(tx, user)?;
    Ok(SafetyNumber {
        digits: digits(own, theirs),
        qr: to_cbor(&safety_qr(own, theirs))?,
    })
}

#[derive(Serialize)]
pub(crate) struct Verified {
    verified: bool,
}

/// Marks `user` verified: with the QR their screen shows, when it holds the identities this
/// device pinned, or without one, when the person compared the digits. A QR of the same two users
/// with other identities says the pin is wrong, and the user is no longer verified.
pub(crate) fn verify_user(
    tx: &mut Tx<'_>,
    user: Uuid,
    qr: Option<&[u8]>,
) -> Result<Verified, Error> {
    let (own, theirs) = pair(tx, user)?;
    let verified = match qr {
        None => true,
        Some(qr) => {
            let mut scanned: SafetyQr = from_cbor(qr)
                .filter(|qr: &SafetyQr| qr.v == 1 && qr.users.len() == 2)
                .ok_or_else(|| invalid("qr", "the QR isn't a safety number's"))?;
            scanned.users.sort_by_key(|entry| entry.user);
            let expected = safety_qr(own, theirs);
            let same_users = scanned
                .users
                .iter()
                .map(|entry| entry.user)
                .eq(expected.users.iter().map(|entry| entry.user));
            if !same_users {
                // Another pair's QR: it says nothing of this one.
                return Ok(Verified { verified: false });
            }
            scanned.users == expected.users
        }
    };
    tx.conn().execute(
        "UPDATE contacts SET verified = ?2 WHERE user_id = ?1",
        params![user.as_bytes().as_slice(), verified],
    )?;
    Ok(Verified { verified })
}

/// The safety QR: `{v: 1, users: [{user, identity_key}]}`, the two users in order.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SafetyQr {
    v: u32,
    users: Vec<QrEntry>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QrEntry {
    user: Uuid,
    #[serde(with = "serde_bytes")]
    identity_key: Vec<u8>,
}

type Person = (Uuid, [u8; 32]);

/// This device's user and `user`, each with the identity this device holds or pinned.
fn pair(tx: &Tx<'_>, user: Uuid) -> Result<(Person, Person), Error> {
    let own_user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    if own_user == user {
        return Err(invalid("user_id", "the user is this device's own"));
    }
    let own_key = tx
        .own_identity_key()?
        .ok_or_else(|| not_found("identity"))?;
    let their_key = tx
        .identity_of(user)?
        .ok_or_else(|| Error::NeedsIdentities {
            users: vec![user.to_string()],
        })?;
    Ok(((own_user, own_key), (user, their_key)))
}

fn ordered(a: Person, b: Person) -> (Person, Person) {
    if a.0 <= b.0 { (a, b) } else { (b, a) }
}

fn safety_qr(a: Person, b: Person) -> SafetyQr {
    let (first, second) = ordered(a, b);
    SafetyQr {
        v: 1,
        users: [first, second]
            .into_iter()
            .map(|(user, identity_key)| QrEntry {
                user,
                identity_key: identity_key.to_vec(),
            })
            .collect(),
    }
}

/// The 60 digits, the lower user's half first, in 12 groups of 5.
fn digits(a: Person, b: Person) -> String {
    let (first, second) = ordered(a, b);
    let mut digits = String::with_capacity(71);
    for (at, digit) in (half(first) + &half(second)).chars().enumerate() {
        if at > 0 && at % 5 == 0 {
            digits.push(' ');
        }
        digits.push(digit);
    }
    digits
}

/// A user's half of the number: SHA-256("duvet safety number v1" || user || identity key), its
/// first 15 bytes modulo 10^30, in 30 digits.
fn half((user, identity_key): Person) -> String {
    let digest = Sha256::new()
        .chain_update(SAFETY_NUMBER_LABEL)
        .chain_update(user.as_bytes())
        .chain_update(identity_key)
        .finalize();
    let mut value = [0u8; 16];
    value[1..].copy_from_slice(&digest[..15]);
    format!("{:030}", u128::from_be_bytes(value) % 10u128.pow(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safety_number_digits_are_the_formats() {
        // Computed apart from the core, from the format: SHA-256 of the label, the user and the
        // key, its first 15 bytes as a big-endian number modulo 10^30, the lower user first.
        let a = (
            Uuid::from_u128(0x0193a1b2_c3d4_7e5f_8a6b_7c8d9e0f1a2b),
            std::array::from_fn(|i| i as u8),
        );
        let b = (
            Uuid::from_u128(0x0193a1b2_c3d4_7e5f_8a6b_000000000001),
            std::array::from_fn(|i| 0xff - i as u8),
        );
        let expected = "02644 98738 31289 55883 56272 73681 86162 82950 01892 45686 92306 73116";
        assert_eq!(digits(a, b), expected);
        assert_eq!(digits(b, a), expected);
    }
}
