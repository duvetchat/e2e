//! An envelope, as a message's plaintext holds it once MLS opens it: what decodes encodes back to
//! itself.
#![no_main]

use duvet_e2e::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(envelope) = Envelope::decode(data) {
        let again = envelope.encode().expect("a decoded envelope encodes");
        assert_eq!(Envelope::decode(&again).expect("and decodes"), envelope);
    }
});
