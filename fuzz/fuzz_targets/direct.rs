//! A direct message, as a device's inbox hands it over: its header read before anything checks it,
//! its payload opened unverified (an approval's transfer), and the message opened and verified;
//! then the same bytes as the body a device signed, read past the signature.
#![no_main]

use duvet_e2e::DirectMessage;
use duvet_e2e::fuzzing::{direct_header, direct_peek};
use duvet_e2e_rules::{DIRECT_MESSAGE, SUITE, sign};
use libfuzzer_sys::fuzz_target;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{HpkeKeyPair, SignatureScheme};
use uuid::Uuid;

const OWN: Uuid = Uuid::from_bytes([1; 16]);
const FROM: Uuid = Uuid::from_bytes([2; 16]);

/// This device's keys, and the key of the device that signs.
struct Keys {
    provider: OpenMlsRustCrypto,
    hpke: HpkeKeyPair,
    signer: SignatureKeyPair,
    public: [u8; 32],
}

thread_local! {
    static KEYS: Keys = {
        let provider = OpenMlsRustCrypto::default();
        let hpke = provider
            .crypto()
            .derive_hpke_keypair(SUITE.hpke_config(), &[3; 32])
            .unwrap();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let public = signer.public().try_into().unwrap();
        Keys { provider, hpke, signer, public }
    };
}

fuzz_target!(|data: &[u8]| {
    KEYS.with(|keys| {
        let open = |bytes: &[u8]| {
            let _ = direct_header(bytes);
            let _ = direct_peek(&keys.provider, &keys.hpke.private, OWN, bytes);
            let _ = DirectMessage::open(
                &keys.provider,
                &keys.hpke.private,
                OWN,
                FROM,
                &keys.public,
                bytes,
            );
        };
        open(data);
        open(&sign(DIRECT_MESSAGE, data.to_vec(), &keys.signer).unwrap());
    });
});
