//! A request to the API's validator, as devices' commits reach it: every request gets one answer
//! the API can read.
//!
//! The group's state in a request is the API's own, the validator's last answer, which the API
//! keeps and hands back: a request with a state the validator didn't make isn't one the API sends.
//! openmls_memory_storage 0.6.0 unwraps what it stores, so such a state panics in the storage
//! (`a_state_the_validator_didnt_make_is_answered`, in the validator's tests). A request whose state
//! isn't the seed's, a state the validator made, is skipped.
#![no_main]

use std::sync::OnceLock;

use duvet_e2e_validator::{Request, Response, validate_bytes};
use libfuzzer_sys::fuzz_target;

/// The state in `fuzz/seeds/validator_input/commit`, which the validator made.
fn made() -> &'static [u8] {
    static STATE: OnceLock<Vec<u8>> = OnceLock::new();
    STATE.get_or_init(|| {
        let seed: Request =
            ciborium::from_reader(&include_bytes!("../seeds/validator_input/commit")[..])
                .expect("the seed is a request");
        seed.state.expect("with a state").into_vec()
    })
}

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = ciborium::from_reader::<Request, _>(data)
        && request
            .state
            .as_deref()
            .is_some_and(|state| state != made())
    {
        return;
    }
    let response = validate_bytes(data);
    let _: Response = ciborium::from_reader(response.as_slice()).expect("a response in CBOR");
});
