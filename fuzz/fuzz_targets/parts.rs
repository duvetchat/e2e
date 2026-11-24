//! A part of an attachment or of a history package, as the bucket hands it over: only what its
//! file's key sealed at its place opens, and only there.
#![no_main]

use duvet_e2e::parts::{open_part, seal_part};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

const KEY: [u8; 32] = [7; 32];
const ID: Uuid = Uuid::from_bytes([9; 16]);

// The part's index in the input's first 8 bytes, whether it's the last in the 9th, then its bytes.
fuzz_target!(|data: &[u8]| {
    let Some((place, bytes)) = data.split_first_chunk::<9>() else {
        return;
    };
    let (index, last) = (
        u64::from_be_bytes(place[..8].try_into().unwrap()),
        place[8] & 1 == 1,
    );
    // What the server made opens nowhere: only the key's holder seals a part.
    assert!(open_part(&KEY, ID, index, last, bytes).is_err());
    // The same bytes sealed at a place open there, and only there.
    let sealed = seal_part(&KEY, ID, index, last, bytes);
    assert_eq!(open_part(&KEY, ID, index, last, &sealed).unwrap(), bytes);
    assert!(open_part(&KEY, ID, index, !last, &sealed).is_err());
    assert!(open_part(&KEY, ID, index ^ 1, last, &sealed).is_err());
    assert!(open_part(&KEY, Uuid::nil(), index, last, &sealed).is_err());
});
