//! A member's history package and its key, as an import reads them: the key's payload, the
//! package's body once its signature verified, and the records its body inflates to.
#![no_main]

use duvet_e2e::fuzzing::{package_body, package_key, package_records};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = package_key(data);
    let _ = package_body(data);
    let _ = package_records(data);
});
