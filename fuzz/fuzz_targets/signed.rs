//! The signed objects (certificates, device lists, leave statements, and the bodies of direct
//! messages and history packages) and a commit's authenticated data, as the server serves them: read
//! unverified as the core reads them to learn whose key verifies them, verified with a key that
//! didn't sign them, then the input's bytes after its first as a body their signer signed (the
//! first byte picks the label), read past the signature.
#![no_main]

use duvet_e2e_rules::{
    CommitAad, DEVICE_CERTIFICATE, DEVICE_LIST, DIRECT_MESSAGE, DeviceCertificate, DeviceList,
    HISTORY_SHARE, LEAVE, LeaveStatement, sign, verify,
};
use libfuzzer_sys::fuzz_target;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::types::SignatureScheme;
use uuid::Uuid;

const LABELS: [&str; 5] = [
    DEVICE_CERTIFICATE,
    DEVICE_LIST,
    LEAVE,
    DIRECT_MESSAGE,
    HISTORY_SHARE,
];

// The signer the seeds in `fuzz/seeds/signed/` were made with (`write_fuzz_seeds`, in
// `crates/duvet-e2e/tests/seeds.rs`): the Ed25519 key from the seed `[0x5e; 32]`.
thread_local! {
    static SIGNER: (SignatureKeyPair, [u8; 32]) = {
        let seed = [0x5e; 32];
        let public = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let signer =
            SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
        (signer, public)
    };
}

fuzz_target!(|data: &[u8]| {
    let _ = DeviceCertificate::read_unverified(data);
    let _ = LeaveStatement::read_unverified(data);
    let _ = CommitAad::statements(data);
    SIGNER.with(|(signer, public)| {
        let _ = DeviceList::verify(data, public);
        let Some((&which, body)) = data.split_first() else {
            return;
        };
        let label = LABELS[usize::from(which) % LABELS.len()];
        let signed = sign(label, body.to_vec(), signer).unwrap();
        assert_eq!(verify(label, &signed, public).unwrap(), body);
        match label {
            DEVICE_CERTIFICATE => drop(DeviceCertificate::verify(&signed, public)),
            DEVICE_LIST => drop(DeviceList::verify(&signed, public)),
            LEAVE => {
                let device = DeviceCertificate::new(Uuid::nil(), Uuid::nil(), *public, [0; 32], 0);
                drop(LeaveStatement::verify(&signed, &device));
            }
            _ => {}
        }
    });
});
