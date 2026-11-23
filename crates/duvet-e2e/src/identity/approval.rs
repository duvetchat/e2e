//! A new device of the user's, approved by another of the user's devices, one that has the
//! identity. The approver certifies the new device, signs the user's next device list with it on
//! it, and sends it the transfer: the identity, the backup key, the new device's certificate, the
//! list and the approver's own certificate, encrypted to a key the new device drew for that
//! attempt alone (X25519) and signed by the approver's device, as a direct message of type
//! `approval.transfer`. An attempt draws two such keys, one for each way.
//!
//! - **By QR**, the QR holds the new device as it asks to be certified (its user, its ID, its
//!   signature and HPKE keys) and the QR's key. It never passes through the server, so only the
//!   device that scans it can encrypt to that key, and the new device takes a transfer sealed to it
//!   from whichever approver that is.
//! - **By the notice**, all of it passes through the server, and the person compares a code on
//!   both screens. A hash commitment, as in ZRTP, leaves a server in the middle one try at making
//!   the two codes match:
//!   1. the new device sends its request and the commitment, SHA-256("duvet approval commit v1"
//!      || key || nonce), with its other key and 32 random bytes as the nonce, and keeps both;
//!   2. the approver answers with its offer: its certificate, and 32 random bytes of its own (the
//!      same commitment again gets the same offer);
//!   3. only then does the new device reveal the key and the nonce, which the approver holds to
//!      the commitment;
//!   4. both show 6 digits: the first 8 bytes of SHA-256("duvet approval code v1" || key ||
//!      nonce || the approver's certificate || the new device's user, ID, signature key and HPKE
//!      key || the approver's nonce), as a big-endian number, modulo 10^6.
//!
//!   The code covers what each side acts on: the key the approver encrypts to and the keys it
//!   certifies, and the approver the new device trusts. A server in the middle commits to its
//!   side's key before the approver's nonce is out, and picks the offer it hands the new device
//!   before the new device's key is: either way, the codes match once in a million.
//!
//!   The reveal sends the key through the server, which can seal to it too, after an offer of its
//!   own. So the new device takes a transfer sealed to that key only once the person typed on it
//!   the code the approver shows (`approval_accept`), and only from that approver.
//!
//! An attempt's state lasts 10 minutes by the core's clock, in `approvals`: the new device's
//! (`new`) from `approval_begin`, the approver's (`approver`) from `approval_offer`. Each device
//! has one at a time: a new attempt replaces the one before.

use std::fmt;

use duvet_e2e_rules::{DeviceCertificate, DeviceList, SUITE};
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use rusqlite::{OptionalExtension, params};
use serde::de::{self, DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::recover::{install, rule, signing, thirty_two};
use super::{
    BACKUP_KEY, DEVICE_LIST, IDENTITY_SECRET, Identity, OwnDevice, from_cbor, invalid, meta_get,
    meta_put, not_found, random, to_cbor, unix_ms,
};
use crate::protocol::b64;
use crate::{DirectMessage, Error, Tx};

/// The type of the direct message an approver sends the new device.
pub(crate) const TRANSFER: &str = "approval.transfer";

const COMMIT_LABEL: &[u8] = b"duvet approval commit v1";
const CODE_LABEL: &[u8] = b"duvet approval code v1";

/// How long an attempt's state lasts.
const LIFETIME_MS: i64 = 10 * 60 * 1000;

/// The roles of `approvals`' rows: this device asks to be approved, or approves another.
const NEW: &str = "new";
const APPROVER: &str = "approver";

/// Room for a state's or a transfer's fixed parts, besides its certificates and list: its buffer
/// is sized ahead, so no copy of a secret is left behind as it grows.
const FIXED_PARTS: usize = 512;

/// A new device as it asks to be certified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Asked {
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    hpke_key: [u8; 32],
}

impl Asked {
    fn of(own: &OwnDevice) -> Result<Asked, Error> {
        Ok(Asked {
            user: own.user,
            device: own.device,
            signature_key: thirty_two(own.signer.public())?,
            hpke_key: thirty_two(&own.hpke.public)?,
        })
    }
}

/// The QR: `{v: 1, user, device, signature_key, hpke_key, key}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qr {
    v: u32,
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    hpke_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    key: [u8; 32],
}

/// What the new device sends first, by the notice: `{v: 1, user, device, signature_key, hpke_key,
/// hash}`, the hash being the commitment to the key and the nonce.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commitment {
    v: u32,
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    hpke_key: [u8; 32],
    #[serde(with = "serde_bytes")]
    hash: [u8; 32],
}

/// The approver's answer: `{v: 1, hash, certificate, nonce}`, the hash naming the commitment it
/// answers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    v: u32,
    #[serde(with = "serde_bytes")]
    hash: [u8; 32],
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: [u8; 32],
}

/// What the commitment hid: `{v: 1, key, nonce}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reveal {
    v: u32,
    #[serde(with = "serde_bytes")]
    key: [u8; 32],
    #[serde(with = "serde_bytes")]
    nonce: [u8; 32],
}

/// The transfer's payload: `{v: 1, identity, backup_key, certificate, device_list, approver}`.
/// `identity` is the identity's 32-byte secret, `certificate` the new device's, `approver` the
/// sending device's.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    v: u32,
    identity: Secret,
    backup_key: Secret,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    approver: Vec<u8>,
}

/// What an offer holds of its approver: its certificate and its nonce.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Answer {
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: [u8; 32],
}

/// 32 public bytes, alone in a field.
#[derive(Clone, Copy, Serialize, Deserialize)]
struct Bytes32(#[serde(with = "serde_bytes")] [u8; 32]);

/// The new device's attempt: the QR's key's secret; the commitment's key, its private and public
/// parts, and the nonce the commitment hides; the approver's answer once an offer came; and
/// whether the person typed here that approver's code.
#[derive(Serialize, Deserialize)]
struct Attempt {
    qr: Secret,
    secret: Secret,
    #[serde(with = "serde_bytes")]
    key: [u8; 32],
    #[serde(with = "serde_bytes")]
    nonce: [u8; 32],
    answer: Option<Answer>,
    accepted: bool,
}

/// The approver's attempt: the device it would approve, the commitment, its own answer, and what a
/// reveal that held to the commitment settled.
#[derive(Serialize, Deserialize)]
struct Approving {
    asked: Asked,
    #[serde(with = "serde_bytes")]
    hash: [u8; 32],
    answer: Answer,
    held: Option<Held>,
}

/// What a reveal that held to the commitment settled: the key the transfer is sealed to, and the
/// code both screens show.
#[derive(Serialize, Deserialize)]
struct Held {
    key: Bytes32,
    code: String,
}

/// 32 secret bytes, a key, wiped as they drop.
struct Secret(Zeroizing<[u8; 32]>);

impl Secret {
    fn copy(bytes: &[u8]) -> Result<Secret, Error> {
        let mut secret = Zeroizing::new([0u8; 32]);
        if bytes.len() != secret.len() {
            return Err(Error::Internal("a key isn't 32 bytes".into()));
        }
        secret.copy_from_slice(bytes);
        Ok(Secret(secret))
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0[..])
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ThirtyTwo;

        impl Visitor<'_> for ThirtyTwo {
            type Value = Secret;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("32 bytes")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Secret, E> {
                Secret::copy(bytes).map_err(|_| E::invalid_length(bytes.len(), &self))
            }
        }

        deserializer.deserialize_bytes(ThirtyTwo)
    }
}

#[derive(Serialize)]
pub(crate) struct Begun {
    #[serde(with = "b64")]
    qr: Vec<u8>,
    #[serde(with = "b64")]
    commitment: Vec<u8>,
}

/// A new attempt at having this device approved: a key for the QR to show, and another the
/// commitment hides, both drawn for it alone. The attempt before it, if any, is over.
pub(crate) fn approval_begin(tx: &mut Tx<'_>) -> Result<Begun, Error> {
    let own = tx.own_device()?;
    if tx.own_identity_key()?.is_some() {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    let asked = Asked::of(&own)?;
    let (qr_key, qr_secret) = attempt_key(tx)?;
    let (key, secret) = attempt_key(tx)?;
    let nonce = thirty_two(&random(tx.provider().rand(), 32)?)?;
    let hash = commitment_hash(&key, &nonce);

    let qr = to_cbor(&Qr {
        v: 1,
        user: asked.user,
        device: asked.device,
        signature_key: asked.signature_key,
        hpke_key: asked.hpke_key,
        key: qr_key,
    })?;
    let commitment = to_cbor(&Commitment {
        v: 1,
        user: asked.user,
        device: asked.device,
        signature_key: asked.signature_key,
        hpke_key: asked.hpke_key,
        hash,
    })?;
    let attempt = Attempt {
        qr: qr_secret,
        secret,
        key,
        nonce,
        answer: None,
        accepted: false,
    };
    store(
        tx,
        NEW,
        &hash,
        tx.now().saturating_add(LIFETIME_MS),
        &to_secret_cbor(&attempt, FIXED_PARTS)?,
    )?;
    Ok(Begun { qr, commitment })
}

/// An X25519 key drawn for one attempt: its public part and its secret.
fn attempt_key(tx: &Tx<'_>) -> Result<([u8; 32], Secret), Error> {
    let provider = tx.provider();
    let pair = provider
        .crypto()
        .derive_hpke_keypair(SUITE.hpke_config(), &random(provider.rand(), 32)?)
        .map_err(|_| Error::Internal("the attempt's key couldn't be made".into()))?;
    Ok((thirty_two(&pair.public)?, Secret::copy(&pair.private)?))
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalOffer {
    #[serde(with = "b64")]
    commitment: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Offered {
    #[serde(with = "b64")]
    offer: Vec<u8>,
}

/// The approver's answer to a new device's commitment: its certificate, and a nonce of its own
/// drawn for this attempt. It approves only a device of its own user that isn't on the user's
/// list yet. The approver's attempt before it, if any, is over; but the commitment of the attempt
/// under way, sent again (the same request and hash), gets the same offer, its nonce included, so
/// sending a commitment again is no new try at the code.
pub(crate) fn approval_offer(tx: &mut Tx<'_>, request: ApprovalOffer) -> Result<Offered, Error> {
    let commitment: Commitment = from_cbor(&request.commitment)
        .filter(|commitment: &Commitment| commitment.v == 1)
        .ok_or_else(|| invalid("commitment", "the commitment isn't an approval's"))?;
    let asked = Asked {
        user: commitment.user,
        device: commitment.device,
        signature_key: commitment.signature_key,
        hpke_key: commitment.hpke_key,
    };
    let approver = Approver::of(tx)?;
    approver.may_approve(&asked)?;
    if let Some((_, _, approving)) = current::<Approving>(tx, APPROVER)?
        && approving.hash == commitment.hash
        && approving.asked == asked
    {
        return Ok(Offered {
            offer: offer_of(&approving.hash, &approving.answer)?,
        });
    }
    let answer = Answer {
        certificate: approver.certificate,
        nonce: thirty_two(&random(tx.provider().rand(), 32)?)?,
    };
    let offer = offer_of(&commitment.hash, &answer)?;
    let capacity = FIXED_PARTS + answer.certificate.len();
    let approving = Approving {
        asked,
        hash: commitment.hash,
        answer,
        held: None,
    };
    store(
        tx,
        APPROVER,
        &commitment.hash,
        tx.now().saturating_add(LIFETIME_MS),
        &to_secret_cbor(&approving, capacity)?,
    )?;
    Ok(Offered { offer })
}

/// The offer that answers the commitment `hash` with `answer`.
fn offer_of(hash: &[u8; 32], answer: &Answer) -> Result<Vec<u8>, Error> {
    to_cbor(&Offer {
        v: 1,
        hash: *hash,
        certificate: answer.certificate.clone(),
        nonce: answer.nonce,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalReveal {
    #[serde(with = "b64")]
    offer: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Revealed {
    #[serde(with = "b64")]
    reveal: Vec<u8>,
    code: String,
}

/// The new device's answer to the approver's offer: the key and the nonce its commitment hid, and
/// the code to compare with the approver's. An attempt takes the first offer: the same one again
/// gets the same answer, and another one `exists`.
pub(crate) fn approval_reveal(tx: &mut Tx<'_>, request: ApprovalReveal) -> Result<Revealed, Error> {
    let own = tx.own_device()?;
    let (id, expires_at, mut attempt) = under_way::<Attempt>(tx, NEW)?;
    let offer: Offer = from_cbor(&request.offer)
        .filter(|offer: &Offer| offer.v == 1)
        .ok_or_else(|| invalid("offer", "the offer isn't an approval's"))?;
    if offer.hash[..] != id[..] {
        // An answer to another attempt.
        return Err(not_found("approval"));
    }
    // The approver is another device of this device's user. Its certificate's signature is for the
    // identity the transfer brings to check.
    let approver = DeviceCertificate::read_unverified(&offer.certificate)
        .map_err(|_| invalid("offer", "the offer's certificate is malformed"))?;
    if approver.user != own.user {
        return Err(rule("wrong_user"));
    }
    if approver.device == own.device {
        return Err(rule("wrong_device"));
    }
    let answer = Answer {
        certificate: offer.certificate,
        nonce: offer.nonce,
    };
    match &attempt.answer {
        Some(taken) if *taken != answer => {
            return Err(Error::Exists {
                what: "offer".into(),
            });
        }
        Some(_) => {}
        None => {
            let capacity = FIXED_PARTS + answer.certificate.len();
            attempt.answer = Some(answer.clone());
            store(
                tx,
                NEW,
                &id,
                expires_at,
                &to_secret_cbor(&attempt, capacity)?,
            )?;
        }
    }
    let code = code_digits(
        &attempt.key,
        &attempt.nonce,
        &answer.certificate,
        &Asked::of(&own)?,
        &answer.nonce,
    );
    let reveal = to_cbor(&Reveal {
        v: 1,
        key: attempt.key,
        nonce: attempt.nonce,
    })?;
    Ok(Revealed { reveal, code })
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalAccept {
    code: String,
}

#[derive(Serialize)]
pub(crate) struct Accepted {}

/// The person typed on this device the code the approver shows, and it's this device's: from now
/// on the transfer sealed to the key the reveal disclosed counts, from that approver alone. Another
/// code is `rule_violation` (`code_mismatch`), and leaves the attempt as it was. Before the attempt
/// took an offer, there's no code (`not_found`, `code`).
pub(crate) fn approval_accept(tx: &mut Tx<'_>, request: ApprovalAccept) -> Result<Accepted, Error> {
    let own = tx.own_device()?;
    let (id, expires_at, mut attempt) = under_way::<Attempt>(tx, NEW)?;
    let answer = attempt.answer.as_ref().ok_or_else(|| not_found("code"))?;
    let code = code_digits(
        &attempt.key,
        &attempt.nonce,
        &answer.certificate,
        &Asked::of(&own)?,
        &answer.nonce,
    );
    if !same_code(&code, &request.code) {
        return Err(rule("code_mismatch"));
    }
    let capacity = FIXED_PARTS + answer.certificate.len();
    if !attempt.accepted {
        attempt.accepted = true;
        store(
            tx,
            NEW,
            &id,
            expires_at,
            &to_secret_cbor(&attempt, capacity)?,
        )?;
    }
    Ok(Accepted {})
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalCheck {
    #[serde(with = "b64")]
    reveal: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Checked {
    code: String,
}

/// The approver holds the new device's reveal to the commitment, and gives the code to compare with
/// the new device's. A reveal that doesn't hold is `invalid_signature` (`reveal`), and leaves the
/// attempt as it was.
pub(crate) fn approval_check(tx: &mut Tx<'_>, request: ApprovalCheck) -> Result<Checked, Error> {
    let (id, expires_at, mut approving) = under_way::<Approving>(tx, APPROVER)?;
    let reveal: Reveal = from_cbor(&request.reveal)
        .filter(|reveal: &Reveal| reveal.v == 1)
        .ok_or_else(|| invalid("reveal", "the reveal isn't an approval's"))?;
    if commitment_hash(&reveal.key, &reveal.nonce) != approving.hash {
        return Err(Error::InvalidSignature {
            what: "reveal".into(),
        });
    }
    let code = code_digits(
        &reveal.key,
        &reveal.nonce,
        &approving.answer.certificate,
        &approving.asked,
        &approving.answer.nonce,
    );
    if approving.held.is_none() {
        approving.held = Some(Held {
            key: Bytes32(reveal.key),
            code: code.clone(),
        });
        let capacity = FIXED_PARTS + approving.answer.certificate.len();
        store(
            tx,
            APPROVER,
            &id,
            expires_at,
            &to_secret_cbor(&approving, capacity)?,
        )?;
    }
    Ok(Checked { code })
}

#[derive(Serialize)]
pub(crate) struct Approved {
    #[serde(with = "b64")]
    certificate: Vec<u8>,
    #[serde(with = "b64")]
    device_list: Vec<u8>,
    #[serde(with = "b64")]
    transfer: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalConfirm {
    code: String,
}

/// The person saw both codes match, and confirms with the code they compared: the approver
/// certifies the new device, signs the user's next list with it on it, and seals the transfer to
/// the attempt's key. The certificate and the list are for the server, the transfer for the new
/// device's inbox. A code that isn't the current attempt's confirms nothing (`not_found`, `code`):
/// a notice taken after the person read the code has replaced the attempt they compared. Nor does
/// one before a reveal held to the commitment, when no code could have matched.
pub(crate) fn approval_confirm(
    tx: &mut Tx<'_>,
    request: ApprovalConfirm,
) -> Result<Approved, Error> {
    let (_, _, approving) = under_way::<Approving>(tx, APPROVER)?;
    let key = approving
        .held
        .as_ref()
        .filter(|held| same_code(&held.code, &request.code))
        .map(|held| held.key)
        .ok_or_else(|| not_found("code"))?;
    tx.conn()
        .execute("DELETE FROM approvals WHERE role = ?1", [APPROVER])?;
    approve(tx, &approving.asked, &key.0)
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalFromQr {
    #[serde(with = "b64")]
    qr: Vec<u8>,
}

/// The approver scanned the new device's QR: as `approval_confirm`, for the device and the key the
/// QR shows.
pub(crate) fn approval_from_qr(
    tx: &mut Tx<'_>,
    request: ApprovalFromQr,
) -> Result<Approved, Error> {
    let qr: Qr = from_cbor(&request.qr)
        .filter(|qr: &Qr| qr.v == 1)
        .ok_or_else(|| invalid("qr", "the QR isn't an approval's"))?;
    let asked = Asked {
        user: qr.user,
        device: qr.device,
        signature_key: qr.signature_key,
        hpke_key: qr.hpke_key,
    };
    approve(tx, &asked, &qr.key)
}

/// This device as an approver: it has the identity, its certificate and the user's list.
struct Approver {
    own: OwnDevice,
    identity: Identity,
    certificate: Vec<u8>,
    list: DeviceList,
}

impl Approver {
    fn of(tx: &Tx<'_>) -> Result<Approver, Error> {
        let own = tx.own_device()?;
        let identity = tx.own_identity()?.ok_or_else(|| not_found("identity"))?;
        let certificate = own.certificate.clone().ok_or_else(|| {
            Error::Internal("the device has the identity but no certificate".into())
        })?;
        let list = tx
            .device_list_of(own.user)?
            .ok_or_else(|| Error::Internal("the identity has no device list".into()))?;
        Ok(Approver {
            own,
            identity,
            certificate,
            list,
        })
    }

    /// Whether this device may approve `asked`: a device of its own user, not on the list yet. This
    /// device must be on it, as the new device will check.
    fn may_approve(&self, asked: &Asked) -> Result<(), Error> {
        if asked.user != self.own.user {
            return Err(rule("wrong_user"));
        }
        if asked.device == self.own.device || self.list.contains(asked.device) {
            return Err(Error::Exists {
                what: "device".into(),
            });
        }
        if !self.list.contains(self.own.device) {
            return Err(rule("device_not_listed"));
        }
        Ok(())
    }
}

/// Certifies `asked`, signs the user's next list with it, and seals the transfer to `key`.
fn approve(tx: &Tx<'_>, asked: &Asked, key: &[u8; 32]) -> Result<Approved, Error> {
    let approver = Approver::of(tx)?;
    approver.may_approve(asked)?;
    let secret = meta_get(tx, IDENTITY_SECRET)?
        .map(Zeroizing::new)
        .ok_or_else(|| not_found("identity"))?;
    let backup_key = meta_get(tx, BACKUP_KEY)?
        .map(Zeroizing::new)
        .ok_or_else(|| not_found("backup_key"))?;

    let certificate = DeviceCertificate::new(
        asked.user,
        asked.device,
        asked.signature_key,
        asked.hpke_key,
        unix_ms(tx)?,
    )
    .sign(&approver.identity.signer)
    .map_err(signing)?;
    let version = approver
        .list
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Internal("the device list's version is at its end".into()))?;
    let mut devices = approver.list.devices.clone();
    devices.push(asked.device);
    let device_list = DeviceList::new(
        approver.own.user,
        approver.identity.public,
        version,
        devices,
    )
    .sign(&approver.identity.signer)
    .map_err(signing)?;
    meta_put(tx, DEVICE_LIST, &device_list)?;

    let capacity = FIXED_PARTS + certificate.len() + device_list.len() + approver.certificate.len();
    let payload = to_secret_cbor(
        &Transfer {
            v: 1,
            identity: Secret::copy(&secret)?,
            backup_key: Secret::copy(&backup_key)?,
            certificate: certificate.clone(),
            device_list: device_list.clone(),
            approver: approver.certificate.clone(),
        },
        capacity,
    )?;
    let transfer = DirectMessage::seal(
        tx.provider(),
        &approver.own.signer,
        approver.own.device,
        asked.device,
        key,
        TRANSFER,
        &payload,
    )?;
    Ok(Approved {
        certificate,
        device_list,
        transfer,
    })
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApprovalReceive {
    #[serde(with = "b64")]
    transfer: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Enrolled {
    #[serde(with = "b64")]
    identity_key: Vec<u8>,
    #[serde(with = "b64")]
    certificate: Vec<u8>,
}

/// The transfer an approver sent this device, as `receive_direct` takes it.
pub(crate) fn approval_receive(
    tx: &mut Tx<'_>,
    request: ApprovalReceive,
) -> Result<Enrolled, Error> {
    let (kind, _) = DirectMessage::header(&request.transfer)?;
    if kind != TRANSFER {
        return Err(invalid(
            "transfer",
            "the message isn't an approval's transfer",
        ));
    }
    receive_transfer(tx, &request.transfer)
}

/// The transfer an approver sent this device, for its attempt under way. It counts only if it holds
/// up: sealed to one of the attempt's keys, and signed by the device whose certificate it carries;
/// and the identity it brings signs that certificate, this device's own, and the user's list with
/// both devices on it. Sealed to the QR's key, it comes from the device that scanned the QR. Sealed
/// to the key the reveal disclosed, it counts only once the person typed here the approver's code
/// (`not_found`, `code`, until then), and only from that approver. Then this device has the
/// identity, its certificate, the list and the backup key.
pub(crate) fn receive_transfer(tx: &Tx<'_>, message: &[u8]) -> Result<Enrolled, Error> {
    let own = tx.own_device()?;
    if tx.own_identity_key()?.is_some() {
        return Err(Error::Exists {
            what: "identity".into(),
        });
    }
    let (_, _, attempt) = under_way::<Attempt>(tx, NEW)?;
    let provider = tx.provider();

    // The sender's certificate is inside: read it, then open the message as every direct message
    // is opened, verified with the key that certificate holds. The key that opens it tells the way
    // it came.
    let (_, from) = DirectMessage::header(message)?;
    let (secret, peeked, only_from) =
        match DirectMessage::peek(provider, &attempt.qr.0[..], own.device, message) {
            Ok(peeked) => (&attempt.qr, peeked, None),
            Err(Error::DecryptFailed { .. }) => {
                let peeked =
                    DirectMessage::peek(provider, &attempt.secret.0[..], own.device, message)?;
                let answer = attempt
                    .answer
                    .as_ref()
                    .filter(|_| attempt.accepted)
                    .ok_or_else(|| not_found("code"))?;
                (&attempt.secret, peeked, Some(answer))
            }
            Err(error) => return Err(error),
        };
    let claimed = read_transfer(&peeked)?;
    let sender_key = DeviceCertificate::read_unverified(&claimed.approver)
        .ok()
        .and_then(|certificate| <[u8; 32]>::try_from(certificate.signature_key.as_slice()).ok())
        .ok_or_else(unreadable)?;
    let (_, payload) = DirectMessage::open(
        provider,
        &secret.0[..],
        own.device,
        from,
        &sender_key,
        message,
    )?;
    let transfer = read_transfer(&payload)?;
    if transfer.approver != claimed.approver {
        return Err(unreadable());
    }
    // By the notice, only the approver whose code the person typed here.
    if let Some(answer) = only_from
        && transfer.approver != answer.certificate
    {
        return Err(Error::InvalidSignature {
            what: "transfer".into(),
        });
    }

    // The identity it brings certifies its sender and this device, and signs the user's list with
    // both on it.
    let identity = Identity::from_secret(&transfer.identity.0);
    let approver = certified(&transfer.approver, &identity.public)?;
    if approver.user != own.user {
        return Err(rule("wrong_user"));
    }
    if approver.device != from {
        return Err(rule("wrong_device"));
    }
    let list = DeviceList::verify(&transfer.device_list, &identity.public).map_err(|_| {
        Error::InvalidSignature {
            what: "device_list".into(),
        }
    })?;
    if list.user != own.user {
        return Err(rule("wrong_user"));
    }
    if !list.contains(own.device) || !list.contains(approver.device) {
        return Err(rule("device_not_listed"));
    }
    let certificate = certified(&transfer.certificate, &identity.public)?;
    let asked = Asked::of(&own)?;
    if certificate.user != own.user {
        return Err(rule("wrong_user"));
    }
    if certificate.device != own.device
        || certificate.signature_key[..] != asked.signature_key[..]
        || certificate.hpke_key[..] != asked.hpke_key[..]
    {
        return Err(rule("wrong_device"));
    }

    install(
        tx,
        &transfer.identity.0,
        &identity.public,
        &transfer.certificate,
        &transfer.device_list,
        &transfer.backup_key.0,
    )?;
    Ok(Enrolled {
        identity_key: identity.public.to_vec(),
        certificate: transfer.certificate,
    })
}

/// SHA-256("duvet approval commit v1" || key || nonce).
fn commitment_hash(key: &[u8; 32], nonce: &[u8; 32]) -> [u8; 32] {
    let digest = Sha256::new()
        .chain_update(COMMIT_LABEL)
        .chain_update(key)
        .chain_update(nonce)
        .finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest[..]);
    hash
}

/// The 6 digits both screens show: the first 8 bytes of SHA-256("duvet approval code v1" || key ||
/// nonce || the approver's certificate || the new device's user, ID, signature key and HPKE key ||
/// the approver's nonce), as a big-endian number modulo 10^6. The certificate is the one part of
/// variable length, and what follows it has a fixed one, so no two inputs read alike.
fn code_digits(
    key: &[u8; 32],
    nonce: &[u8; 32],
    certificate: &[u8],
    asked: &Asked,
    approver_nonce: &[u8; 32],
) -> String {
    let digest = Sha256::new()
        .chain_update(CODE_LABEL)
        .chain_update(key)
        .chain_update(nonce)
        .chain_update(certificate)
        .chain_update(asked.user.as_bytes())
        .chain_update(asked.device.as_bytes())
        .chain_update(asked.signature_key)
        .chain_update(asked.hpke_key)
        .chain_update(approver_nonce)
        .finalize();
    let mut first = [0u8; 8];
    first.copy_from_slice(&digest[..8]);
    format!("{:06}", u64::from_be_bytes(first) % 1_000_000)
}

/// Whether `typed` is `code`, compared in constant time.
fn same_code(code: &str, typed: &str) -> bool {
    // ponytail: std's black_box keeps the fold from ending early, best effort as `subtle`'s own
    // is; `subtle::ConstantTimeEq` if a build ever branches on it.
    let differ = code
        .bytes()
        .zip(typed.bytes())
        .fold(0u8, |differ, (a, b)| std::hint::black_box(differ | (a ^ b)));
    differ == 0 && code.len() == typed.len()
}

/// The attempt of `role` under way, with its row's ID and the time it ends. One 10 minutes old is
/// gone (`not_found`, `approval`).
fn under_way<T: DeserializeOwned>(tx: &Tx<'_>, role: &str) -> Result<(Vec<u8>, i64, T), Error> {
    current(tx, role)?.ok_or_else(|| not_found("approval"))
}

/// The attempt of `role` under way, if there's one.
fn current<T: DeserializeOwned>(
    tx: &Tx<'_>,
    role: &str,
) -> Result<Option<(Vec<u8>, i64, T)>, Error> {
    forget_ended(tx)?;
    let row: Option<(Vec<u8>, i64, Vec<u8>)> = tx
        .conn()
        .query_row(
            "SELECT id, expires_at, state FROM approvals WHERE role = ?1",
            [role],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let Some((id, expires_at, state)) = row else {
        return Ok(None);
    };
    let state = Zeroizing::new(state);
    let state = from_secret_cbor(&state)
        .ok_or_else(|| Error::Internal("a stored approval is malformed".into()))?;
    Ok(Some((id, expires_at, state)))
}

/// Keeps `state` as the attempt of `role`, in place of any other, until `expires_at`.
fn store(tx: &Tx<'_>, role: &str, id: &[u8], expires_at: i64, state: &[u8]) -> Result<(), Error> {
    forget_ended(tx)?;
    tx.conn()
        .execute("DELETE FROM approvals WHERE role = ?1", [role])?;
    tx.conn().execute(
        "INSERT INTO approvals (id, role, state, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, role, state, expires_at],
    )?;
    Ok(())
}

/// Attempts are over once 10 minutes old.
fn forget_ended(tx: &Tx<'_>) -> Result<(), Error> {
    tx.conn()
        .execute("DELETE FROM approvals WHERE expires_at <= ?1", [tx.now()])?;
    Ok(())
}

/// `value` in CBOR, written into a buffer sized ahead, which is wiped as it drops: for what holds
/// secrets.
fn to_secret_cbor(value: &impl Serialize, capacity: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::with_capacity(capacity));
    ciborium::into_writer(value, &mut *out)
        .map_err(|_| Error::Internal("a CBOR value couldn't be written".into()))?;
    Ok(out)
}

/// Exactly one CBOR value, read through a scratch buffer that's wiped after: for what holds secrets.
fn from_secret_cbor<T: DeserializeOwned>(mut bytes: &[u8]) -> Option<T> {
    let mut scratch = Zeroizing::new([0u8; 4096]);
    let value = ciborium::de::from_reader_with_buffer(&mut bytes, &mut scratch[..]).ok()?;
    bytes.is_empty().then_some(value)
}

fn read_transfer(payload: &[u8]) -> Result<Transfer, Error> {
    from_secret_cbor(payload)
        .filter(|transfer: &Transfer| transfer.v == 1)
        .ok_or_else(unreadable)
}

/// A certificate, once the transfer's identity verifies it.
fn certified(signed: &[u8], identity_key: &[u8; 32]) -> Result<DeviceCertificate, Error> {
    DeviceCertificate::verify(signed, identity_key).map_err(|_| Error::InvalidSignature {
        what: "certificate".into(),
    })
}

/// A transfer that opens but isn't one.
fn unreadable() -> Error {
    Error::DecryptFailed {
        kind: "transfer".into(),
    }
}
