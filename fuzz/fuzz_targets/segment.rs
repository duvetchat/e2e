//! A segment of the user's backup, as the server keeps it: its header read before its key, and the
//! records its plaintext inflates to.
#![no_main]

use duvet_e2e::fuzzing::{segment_header, segment_records};
use libfuzzer_sys::fuzz_target;

/// ponytail: 1 MiB instead of the 256 MiB a segment may inflate to, so each input takes
/// milliseconds; past either, the refusal is the same.
const LIMIT: usize = 1 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = segment_header(data);
    let _ = segment_records(data, LIMIT);
});
