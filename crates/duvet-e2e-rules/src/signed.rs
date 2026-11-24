//! Signed objects: `{body, sig}` in CBOR, whose Ed25519 signature covers `label || 0x00 || body`.
//! The signature is checked before the body is read, so nobody has to encode a body again to check it.

use ed25519_dalek::{Signature, VerifyingKey};
use openmls_traits::signatures::{Signer, SignerError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::RuleViolation;

pub const DEVICE_CERTIFICATE: &str = "duvet device certificate v1";
pub const DEVICE_LIST: &str = "duvet device list v1";
pub const LEAVE: &str = "duvet leave v1";
pub const DIRECT_MESSAGE: &str = "duvet direct message v1";
pub const HISTORY_SHARE: &str = "duvet history share v1";
pub const DEVICE_BIND: &str = "duvet device bind v1";

#[derive(Serialize, Deserialize)]
struct Signed {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

/// Signs `body` under `label`: the signed object's bytes.
pub fn sign(label: &str, body: Vec<u8>, signer: &impl Signer) -> Result<Vec<u8>, SignerError> {
    let sig = signer.sign(&message(label, &body))?;
    Ok(encode(&Signed { body, sig }))
}

/// The body of a signed object, once its signature under `label` verifies with `key`.
pub fn verify(label: &str, signed: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, RuleViolation> {
    let signed: Signed = decode(signed)?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| RuleViolation::InvalidSignature)?;
    let sig = Signature::from_slice(&signed.sig).map_err(|_| RuleViolation::InvalidSignature)?;
    key.verify_strict(&message(label, &signed.body), &sig)
        .map_err(|_| RuleViolation::InvalidSignature)?;
    Ok(signed.body)
}

/// The body of a signed object, not verified: only to learn whose key verifies it.
pub fn body_unverified(signed: &[u8]) -> Result<Vec<u8>, RuleViolation> {
    decode::<Signed>(signed).map(|signed| signed.body)
}

fn message(label: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(label.len() + 1 + body.len());
    message.extend_from_slice(label.as_bytes());
    message.push(0);
    message.extend_from_slice(body);
    message
}

pub(crate) fn encode(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR into a Vec doesn't fail");
    out
}

/// Decodes exactly one CBOR value, nested `CBOR_DEPTH` levels at most: anything after it is
/// malformed.
pub(crate) fn decode<T: DeserializeOwned>(mut bytes: &[u8]) -> Result<T, RuleViolation> {
    let value = ciborium::de::from_reader_with_recursion_limit(&mut bytes, crate::CBOR_DEPTH)
        .map_err(|_| RuleViolation::Malformed)?;
    if bytes.is_empty() {
        Ok(value)
    } else {
        Err(RuleViolation::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CBOR_DEPTH;

    /// `depth` arrays, each in the one before.
    fn nested(depth: usize) -> Vec<u8> {
        [vec![0x81; depth - 1], vec![0x80]].concat()
    }

    #[test]
    fn nesting_past_the_limit_is_malformed() {
        assert!(decode::<ciborium::Value>(&nested(CBOR_DEPTH)).is_ok());
        let deeper = decode::<ciborium::Value>(&nested(CBOR_DEPTH + 1));
        assert!(matches!(deeper, Err(RuleViolation::Malformed)));
    }
}
