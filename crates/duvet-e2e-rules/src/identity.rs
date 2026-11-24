//! What a user's identity signs (its devices' certificates and its device list), and what a device
//! signs as it leaves a conversation.

use openmls_traits::signatures::{Signer, SignerError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::RuleViolation;
use crate::signed::{self, decode, encode};

/// A device's certificate: its keys, signed by its user's identity. A leaf's credential carries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCertificate {
    pub v: u32,
    pub user: Uuid,
    pub device: Uuid,
    /// The device's Ed25519 key, which signs its leaves.
    #[serde(with = "serde_bytes")]
    pub signature_key: Vec<u8>,
    /// The device's X25519 key, for the messages devices send each other.
    #[serde(with = "serde_bytes")]
    pub hpke_key: Vec<u8>,
    /// Unix milliseconds.
    pub created: u64,
}

impl DeviceCertificate {
    pub fn new(
        user: Uuid,
        device: Uuid,
        signature_key: [u8; 32],
        hpke_key: [u8; 32],
        created: u64,
    ) -> Self {
        Self {
            v: 1,
            user,
            device,
            signature_key: signature_key.into(),
            hpke_key: hpke_key.into(),
            created,
        }
    }

    /// Signs the certificate with its user's identity.
    pub fn sign(&self, identity: &impl Signer) -> Result<Vec<u8>, SignerError> {
        signed::sign(signed::DEVICE_CERTIFICATE, encode(self), identity)
    }

    /// The certificate, once its signature verifies with `identity_key`.
    pub fn verify(signed: &[u8], identity_key: &[u8; 32]) -> Result<Self, RuleViolation> {
        let body = signed::verify(signed::DEVICE_CERTIFICATE, signed, identity_key)?;
        Self::read(&body)
    }

    /// The certificate, not verified: only to learn whose identity verifies it, or the device of
    /// a leaf already in a group, whose certificate was verified as it joined.
    pub fn read_unverified(signed: &[u8]) -> Result<Self, RuleViolation> {
        Self::read(&signed::body_unverified(signed)?)
    }

    fn read(body: &[u8]) -> Result<Self, RuleViolation> {
        let certificate: Self = decode(body)?;
        let well_formed = certificate.v == 1
            && certificate.signature_key.len() == 32
            && certificate.hpke_key.len() == 32;
        if well_formed {
            Ok(certificate)
        } else {
            Err(RuleViolation::Malformed)
        }
    }
}

/// A user's devices, signed by their identity. A newer version replaces an older one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceList {
    pub v: u32,
    pub user: Uuid,
    #[serde(with = "serde_bytes")]
    pub identity_key: Vec<u8>,
    pub version: u64,
    /// In order, each once.
    pub devices: Vec<Uuid>,
}

impl DeviceList {
    pub fn new(user: Uuid, identity_key: [u8; 32], version: u64, mut devices: Vec<Uuid>) -> Self {
        devices.sort_unstable();
        devices.dedup();
        Self {
            v: 1,
            user,
            identity_key: identity_key.into(),
            version,
            devices,
        }
    }

    pub fn sign(&self, identity: &impl Signer) -> Result<Vec<u8>, SignerError> {
        signed::sign(signed::DEVICE_LIST, encode(self), identity)
    }

    /// The list, once its signature verifies with `identity_key`, which it must also name.
    pub fn verify(signed: &[u8], identity_key: &[u8; 32]) -> Result<Self, RuleViolation> {
        let body = signed::verify(signed::DEVICE_LIST, signed, identity_key)?;
        let list: Self = decode(&body)?;
        let ordered = list.devices.windows(2).all(|pair| pair[0] < pair[1]);
        if list.v == 1 && list.identity_key == identity_key && ordered {
            Ok(list)
        } else {
            Err(RuleViolation::Malformed)
        }
    }

    /// Whether this list may replace `previous`: a higher version, or the same one again.
    pub fn accepts_after(&self, previous: Option<&DeviceList>) -> bool {
        match previous {
            None => true,
            Some(previous) => self.version > previous.version || self == previous,
        }
    }

    pub fn contains(&self, device: Uuid) -> bool {
        self.devices.binary_search(&device).is_ok()
    }
}

/// A device's word that a session is its own (decision 13): the session's random challenge, with
/// the device's user, ID and HPKE key, signed by the device's own key. It needs no certificate, so
/// a device binds its HPKE key itself from its first session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindProof {
    pub v: u32,
    pub user: Uuid,
    pub device: Uuid,
    #[serde(with = "serde_bytes")]
    pub hpke_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub challenge: Vec<u8>,
}

impl BindProof {
    pub fn new(user: Uuid, device: Uuid, hpke_key: [u8; 32], challenge: [u8; 32]) -> Self {
        Self {
            v: 1,
            user,
            device,
            hpke_key: hpke_key.into(),
            challenge: challenge.into(),
        }
    }

    /// Signs the proof with the device's key.
    pub fn sign(&self, device: &impl Signer) -> Result<Vec<u8>, SignerError> {
        signed::sign(signed::DEVICE_BIND, encode(self), device)
    }

    /// The proof, once it verifies with `signature_key`, the device's.
    pub fn verify(signed: &[u8], signature_key: &[u8; 32]) -> Result<Self, RuleViolation> {
        let proof: Self = decode(&signed::verify(signed::DEVICE_BIND, signed, signature_key)?)?;
        if proof.v == 1 && proof.hpke_key.len() == 32 && proof.challenge.len() == 32 {
            Ok(proof)
        } else {
            Err(RuleViolation::Malformed)
        }
    }
}

/// A user's word that they leave a conversation, signed by one of their devices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaveStatement {
    pub v: u32,
    pub user: Uuid,
    pub conversation: Uuid,
    pub generation: u32,
    pub epoch: u64,
    pub device: Uuid,
}

impl LeaveStatement {
    pub fn new(user: Uuid, conversation: Uuid, generation: u32, epoch: u64, device: Uuid) -> Self {
        Self {
            v: 1,
            user,
            conversation,
            generation,
            epoch,
            device,
        }
    }

    /// Signs the statement with the device's key.
    pub fn sign(&self, device: &impl Signer) -> Result<Vec<u8>, SignerError> {
        signed::sign(signed::LEAVE, encode(self), device)
    }

    /// The statement, once it verifies with the key of `certificate`, whose device it must name.
    pub fn verify(signed: &[u8], certificate: &DeviceCertificate) -> Result<Self, RuleViolation> {
        let key: &[u8; 32] = certificate
            .signature_key
            .as_slice()
            .try_into()
            .map_err(|_| RuleViolation::Malformed)?;
        let statement: Self = decode(&signed::verify(signed::LEAVE, signed, key)?)?;
        let theirs = statement.user == certificate.user && statement.device == certificate.device;
        if statement.v == 1 && theirs {
            Ok(statement)
        } else {
            Err(RuleViolation::InvalidSignature)
        }
    }

    /// The statement, not verified: only to learn whose device verifies it.
    pub fn read_unverified(signed: &[u8]) -> Result<Self, RuleViolation> {
        decode(&signed::body_unverified(signed)?)
    }
}
