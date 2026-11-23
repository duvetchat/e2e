//! The decoders the core keeps private, for the fuzz targets in `fuzz/`, with the `fuzzing` feature
//! alone: what it reads from the server, or from a member through it, before anything else checks
//! it. The public ones (`Envelope::decode`, `parts::open_part`, `DirectMessage::open`, the rules'
//! signed objects and the validator) the targets call themselves.

use openmls_traits::OpenMlsProvider;
use uuid::Uuid;

use crate::messages::Record;
use crate::{DirectMessage, Error};

/// A direct message's type and the device it names as its sender, read before anything is checked.
pub fn direct_header(bytes: &[u8]) -> Result<(String, Uuid), Error> {
    DirectMessage::header(bytes)
}

/// A direct message to `own_device`, opened with `hpke_secret` and not verified, as a new device
/// reads its approver's transfer.
pub fn direct_peek(
    provider: &impl OpenMlsProvider,
    hpke_secret: &[u8],
    own_device: Uuid,
    bytes: &[u8],
) -> Result<(), Error> {
    DirectMessage::peek(provider, hpke_secret, own_device, bytes).map(drop)
}

/// A backup segment's header, read before its key.
pub fn segment_header(data: &[u8]) -> Result<(), Error> {
    crate::backup::read_segment(data)
}

/// The records a segment's plaintext inflates to, `limit` bytes of them at most.
pub fn segment_records(deflated: &[u8], limit: usize) -> Result<Vec<Record>, Error> {
    crate::backup::records_in(deflated, limit)
}

/// A history package's body, read once its signature verified.
pub fn package_body(signed: &[u8]) -> Result<(), Error> {
    crate::history::read_package_body(signed)
}

/// A package key's payload, as its direct message carries it.
pub fn package_key(payload: &[u8]) -> Result<(), Error> {
    crate::history::read_key_payload(payload)
}

/// The records a package holds, read as an import reads them, and kept nowhere: how many.
pub fn package_records(deflated: &[u8]) -> Result<usize, Error> {
    crate::history::read_records(deflated, |_| Ok(true))
}
