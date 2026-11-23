//! The messages one device sends another through the server's inbox: what an approving device
//! hands a new one, the new identity a rotation hands the devices that stay, or the key of a shared
//! history package.
//!
//! Each is encrypted with HPKE to the receiving device's key, in base mode with the HPKE of
//! Duvet's suite, then signed by the sending device: base mode doesn't say who wrote, and anyone
//! holding the receiver's public key, the server included, could write to it.
//!
//! `receive_direct` takes each message the inbox hands over, by its type.

use duvet_e2e_rules::{DIRECT_MESSAGE, RuleViolation, SUITE, sign, verify};
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::HpkeCiphertext;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::{self, from_cbor, to_cbor};
use crate::protocol::b64;
use crate::{Error, Tx};

/// The largest direct message, sealed and signed: 64 KiB.
pub const MAX_DIRECT: usize = 64 * 1024;

/// HPKE's info: the same words as the signature's label.
const INFO: &[u8] = DIRECT_MESSAGE.as_bytes();

/// What the sending device signs: `{v: 1, from, to, type, enc, ct}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    v: u32,
    from: Uuid,
    to: Uuid,
    #[serde(rename = "type")]
    kind: String,
    /// HPKE's encapsulated key.
    #[serde(with = "serde_bytes")]
    enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

/// A message between two devices, sealed to one and signed by the other.
pub struct DirectMessage;

impl DirectMessage {
    /// `payload`, a message of type `kind` from device `from` to device `to`: encrypted to `to`'s
    /// HPKE key, `to_hpke`, then signed by `signer`, the key of `from`. A message over 64 KiB
    /// gives `too_large`.
    pub fn seal(
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        from: Uuid,
        to: Uuid,
        to_hpke: &[u8; 32],
        kind: &str,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if payload.len() > MAX_DIRECT {
            return Err(too_large());
        }
        let sealed = provider
            .crypto()
            .hpke_seal(
                SUITE.hpke_config(),
                to_hpke,
                INFO,
                &associated(from, to, kind),
                payload,
            )
            .map_err(|_| Error::Internal("a direct message couldn't be encrypted".into()))?;
        let body = to_cbor(&Body {
            v: 1,
            from,
            to,
            kind: kind.to_owned(),
            enc: sealed.kem_output.as_slice().to_vec(),
            ct: sealed.ciphertext.as_slice().to_vec(),
        })?;
        let message = sign(DIRECT_MESSAGE, body, signer)
            .map_err(|_| Error::Internal("a direct message couldn't be signed".into()))?;
        if message.len() > MAX_DIRECT {
            return Err(too_large());
        }
        Ok(message)
    }

    /// The type and the payload of `bytes`, a message from device `from` to this one,
    /// `own_device`. It must be signed by `from`, whose key is `verify_with`, and name it as its
    /// sender, or it gives `invalid_signature`. One that isn't to this device or doesn't open with
    /// `hpke_secret` gives `decrypt_failed`, and one over 64 KiB `too_large`, before it's read.
    pub fn open(
        provider: &impl OpenMlsProvider,
        hpke_secret: &[u8],
        own_device: Uuid,
        from: Uuid,
        verify_with: &[u8; 32],
        bytes: &[u8],
    ) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
        if bytes.len() > MAX_DIRECT {
            return Err(too_large());
        }
        let body = verify(DIRECT_MESSAGE, bytes, verify_with).map_err(|error| match error {
            RuleViolation::InvalidSignature => forged(),
            _ => unreadable(),
        })?;
        let body = from_cbor::<Body>(&body)
            .filter(|body| body.v == 1)
            .ok_or_else(unreadable)?;
        if body.from != from {
            return Err(forged());
        }
        decrypt(provider, hpke_secret, own_device, body)
    }

    /// The type of `bytes` and the device it names as its sender, as it says before anything about
    /// it is verified: what tells how to open it.
    pub(crate) fn header(bytes: &[u8]) -> Result<(String, Uuid), Error> {
        let body = unverified(bytes)?;
        Ok((body.kind, body.from))
    }

    /// The payload of `bytes`, a message to this device, `own_device`, decrypted with `hpke_secret`
    /// but not verified: only to read the certificate of the device that says it sent it, where the
    /// message itself is the one place that certificate is (an approval's transfer). Nothing in it
    /// counts until `open` verifies the message with the key that certificate holds.
    pub(crate) fn peek(
        provider: &impl OpenMlsProvider,
        hpke_secret: &[u8],
        own_device: Uuid,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let (_, payload) = decrypt(provider, hpke_secret, own_device, unverified(bytes)?)?;
        Ok(payload)
    }
}

/// A signed object's body, its signature not checked.
#[derive(Deserialize)]
struct Unverified {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
}

/// The body of `bytes`, a direct message, read without checking its signature.
fn unverified(bytes: &[u8]) -> Result<Body, Error> {
    if bytes.len() > MAX_DIRECT {
        return Err(too_large());
    }
    let signed: Unverified = from_cbor(bytes).ok_or_else(unreadable)?;
    from_cbor::<Body>(&signed.body)
        .filter(|body| body.v == 1)
        .ok_or_else(unreadable)
}

/// The type and the payload of `body`, a message to this device, `own_device`, decrypted with
/// `hpke_secret`.
fn decrypt(
    provider: &impl OpenMlsProvider,
    hpke_secret: &[u8],
    own_device: Uuid,
    body: Body,
) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
    if body.to != own_device {
        return Err(unreadable());
    }
    let sealed = HpkeCiphertext {
        kem_output: body.enc.into(),
        ciphertext: body.ct.into(),
    };
    let payload = provider
        .crypto()
        .hpke_open(
            SUITE.hpke_config(),
            &sealed,
            hpke_secret,
            INFO,
            &associated(body.from, own_device, &body.kind),
        )
        .map_err(|_| unreadable())?;
    Ok((body.kind, Zeroizing::new(payload)))
}

/// `receive_direct`: a message another device sent this one, as its inbox hands it over.
#[derive(Debug, Deserialize)]
pub(crate) struct ReceiveDirect {
    #[serde(with = "b64")]
    message: Vec<u8>,
    /// The sending device's certificate, for the types whose sender this device knows no other way.
    /// An approval's transfer carries its sender's certificate itself: for it, this isn't read.
    #[serde(default, with = "b64::option")]
    #[allow(dead_code)]
    from_certificate: Option<Vec<u8>>,
    /// The identity the server serves for this device's own user now, which a rotation's transfer
    /// must bring.
    #[serde(default, with = "b64::option")]
    identity_key: Option<Vec<u8>>,
}

/// What a direct message brought, by its type.
#[derive(Serialize)]
#[serde(tag = "type")]
pub(crate) enum Received {
    /// An approver's transfer: this device has its user's identity now.
    #[serde(rename = "approval.transfer")]
    ApprovalTransfer(identity::Enrolled),
    /// A rotation's transfer: this device has its user's new identity now.
    #[serde(rename = "rotation.transfer")]
    RotationTransfer(identity::Transferred),
}

/// A message from another device, taken by its type. A type this core doesn't read is
/// `bad_command` (`message`).
pub(crate) fn receive_direct(tx: &mut Tx<'_>, request: ReceiveDirect) -> Result<Received, Error> {
    let (kind, _) = DirectMessage::header(&request.message)?;
    match kind.as_str() {
        identity::APPROVAL_TRANSFER => Ok(Received::ApprovalTransfer(identity::receive_transfer(
            tx,
            &request.message,
            None,
        )?)),
        identity::ROTATION_TRANSFER => Ok(Received::RotationTransfer(identity::receive_rotation(
            tx,
            &request.message,
            request.identity_key.as_deref(),
        )?)),
        _ => Err(Error::BadCommand {
            message: "the message is of a type this core doesn't read",
            field: Some("message".into()),
        }),
    }
}

/// HPKE's associated data: `from || to || type`.
fn associated(from: Uuid, to: Uuid, kind: &str) -> Vec<u8> {
    [from.as_bytes().as_slice(), to.as_bytes(), kind.as_bytes()].concat()
}

fn too_large() -> Error {
    Error::TooLarge {
        limit: MAX_DIRECT as u64,
    }
}

/// Not signed by the device it names as its sender.
fn forged() -> Error {
    Error::InvalidSignature {
        what: "direct message".into(),
    }
}

fn unreadable() -> Error {
    Error::DecryptFailed {
        kind: "direct".into(),
    }
}
