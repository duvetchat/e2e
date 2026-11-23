//! A request to the API's validator, as devices' commits reach it: every request gets one answer
//! the API can read.
#![no_main]

use duvet_e2e_validator::{Response, validate_bytes};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let response = validate_bytes(data);
    let _: Response = ciborium::from_reader(response.as_slice()).expect("a response in CBOR");
});
