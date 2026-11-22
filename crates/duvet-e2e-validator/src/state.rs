//! A group's state between requests: the map OpenMLS's in-memory storage keeps, in CBOR. It's a map
//! of byte strings to byte strings, in key order, so one state always encodes the same.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use openmls_memory_storage::MemoryStorage;
use serde::{Serialize, Serializer};
use serde_bytes::{ByteBuf, Bytes};

use crate::{BAD_REQUEST, Refusal, decode, encode};

/// The start of the keys openmls_memory_storage 0.6.0 keeps a group's proposals under.
const QUEUED_PROPOSAL: &[u8] = b"QueuedProposal";

pub(crate) fn export(storage: &MemoryStorage) -> Result<Vec<u8>, Refusal> {
    let values = storage
        .values
        .read()
        .map_err(|_| Refusal::internal("the state's lock is poisoned"))?;
    let sorted = Sorted(
        values
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect(),
    );
    encode(&sorted).ok_or_else(|| Refusal::internal("the state doesn't encode"))
}

pub(crate) fn import(state: &[u8]) -> Result<MemoryStorage, Refusal> {
    let values: BTreeMap<ByteBuf, ByteBuf> = decode(state)
        .ok_or_else(|| Refusal::new(BAD_REQUEST, "the state isn't one the validator made"))?;
    let values: HashMap<Vec<u8>, Vec<u8>> = values
        .into_iter()
        .map(|(key, value)| (key.into_vec(), value.into_vec()))
        .collect();
    Ok(MemoryStorage {
        values: RwLock::new(values),
    })
}

/// Drops the proposals a commit used. A merged commit leaves the group none, but
/// openmls_memory_storage 0.6.0's `clear_proposal_queue` deletes them under the wrong key, so
/// they'd stay in the state for good.
pub(crate) fn drop_used_proposals(storage: &MemoryStorage) -> Result<(), Refusal> {
    storage
        .values
        .write()
        .map_err(|_| Refusal::internal("the state's lock is poisoned"))?
        .retain(|key, _| !key.starts_with(QUEUED_PROPOSAL));
    Ok(())
}

/// The storage's map, sorted, with its keys and values as byte strings.
struct Sorted<'a>(BTreeMap<&'a [u8], &'a [u8]>);

impl Serialize for Sorted<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            self.0
                .iter()
                .map(|(key, value)| (Bytes::new(key), Bytes::new(value))),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_in_key_order() {
        let storage = MemoryStorage::default();
        {
            let mut values = storage.values.write().unwrap();
            values.insert(b"b".to_vec(), vec![2; 3]);
            values.insert(b"a".to_vec(), Vec::new());
            values.insert(vec![0xff; 40], vec![0; 300]);
        }
        let state = export(&storage).unwrap();
        // A map of three, its byte-string keys in order: "a", "b", then the 40 bytes.
        assert_eq!(&state[..3], &[0xa3, 0x41, b'a']);
        let again = import(&state).unwrap();
        assert_eq!(
            *again.values.read().unwrap(),
            *storage.values.read().unwrap()
        );
        assert_eq!(export(&again).unwrap(), state);
    }

    #[test]
    fn anything_else_is_refused() {
        for state in [&b""[..], &[0x01, 0x02], &[0xa1, 0x41, b'a']] {
            assert!(import(state).is_err());
        }
    }

    #[test]
    fn used_proposals_go() {
        let storage = MemoryStorage::default();
        {
            let mut values = storage.values.write().unwrap();
            values.insert(b"QueuedProposal{...}\x00\x01".to_vec(), vec![1]);
            values.insert(b"ProposalQueueRefs{...}\x00\x01".to_vec(), vec![2]);
            values.insert(b"Tree{...}\x00\x01".to_vec(), vec![3]);
        }
        drop_used_proposals(&storage).unwrap();
        let mut keys: Vec<Vec<u8>> = storage.values.read().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                b"ProposalQueueRefs{...}\x00\x01".to_vec(),
                b"Tree{...}\x00\x01".to_vec()
            ]
        );
    }
}
