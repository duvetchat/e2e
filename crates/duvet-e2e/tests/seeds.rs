//! The fuzz targets' seeds, `fuzz/seeds/<target>/`: one or two valid inputs of each format, which
//! the fuzzers start from besides their corpus, so they get past each format's first checks. Made by
//! `write_fuzz_seeds`, ignored: run it again when a format changes.

mod support;

use std::path::PathBuf;

use duvet_e2e::history::{Header, ShareKind};
use duvet_e2e::messages::{Record, RecordKind};
use duvet_e2e::{Attachment, DirectMessage, Envelope, ThumbnailRef};
use duvet_e2e_rules::{
    DeviceCertificate, DeviceList, Entry, Kind, LeaveStatement, MemberList, SUITE,
};
use openmls::prelude::{OpenMlsProvider, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use serde::Serialize;
use serde_bytes::ByteBuf;
use serde_json::json;
use support::*;
use uuid::Uuid;
use zeroize::Zeroizing;

// The keys the `direct` and `signed` targets hold (fuzz/fuzz_targets/direct.rs and signed.rs):
// the receiving device's HPKE key derived from `[3; 32]`, the sender's Ed25519 key from `[0x5e; 32]`.
const OWN: Uuid = Uuid::from_bytes([1; 16]);
const FROM: Uuid = Uuid::from_bytes([2; 16]);
const SIGNER: [u8; 32] = [0x5e; 32];

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn signer() -> SignatureKeyPair {
    let public = ed25519_dalek::SigningKey::from_bytes(&SIGNER)
        .verifying_key()
        .to_bytes();
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, SIGNER.to_vec(), public.to_vec())
}

#[test]
#[ignore = "writes the fuzz targets' seeds"]
fn write_fuzz_seeds() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds");
    let write = |target: &str, name: &str, bytes: &[u8]| {
        let dir = root.join(target);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    };
    let (user, device, conversation) = (Uuid::from_bytes([4; 16]), FROM, Uuid::from_bytes([5; 16]));

    // envelope: a message with a file, an edit, a deletion.
    let file = Attachment {
        id: Uuid::from_bytes([6; 16]),
        key: Zeroizing::new([7; 32]),
        sha256: [8; 32],
        name: "plan.pdf".into(),
        content_type: "application/pdf".into(),
        size: 48_213,
        width: Some(640),
        height: Some(480),
        duration_ms: None,
        waveform: None,
        thumbnail: None,
        thumbnail_ref: Some(ThumbnailRef {
            id: Uuid::from_bytes([9; 16]),
            key: Zeroizing::new([10; 32]),
            sha256: [11; 32],
            size: 9_000,
        }),
    };
    let message = Envelope::Message {
        text: Some("the plan".into()),
        attachments: vec![file],
    };
    write("envelope", "message", &message.encode().unwrap());
    let edit = Envelope::Edit {
        message_id: Uuid::from_bytes([12; 16]),
        text: "the plan, v2".into(),
    };
    write("envelope", "edit", &edit.encode().unwrap());
    let delete = Envelope::Delete {
        message_id: Uuid::from_bytes([12; 16]),
    };
    write("envelope", "delete", &delete.encode().unwrap());

    // parts: a part's place (its index in 8 bytes, whether it's the last in 1), then its bytes.
    write(
        "parts",
        "last",
        &[&[0; 8][..], &[1][..], &b"the file's last part"[..]].concat(),
    );
    write(
        "parts",
        "whole",
        &[&7u64.to_be_bytes()[..], &[0][..], &[0x55; 64][..]].concat(),
    );

    // The records a segment or a package holds, deflated.
    let record = Record {
        kind: RecordKind::Message,
        id: Uuid::from_bytes([12; 16]),
        seq: 3,
        user,
        device,
        sent: 1_795_456_679_081,
        envelope: message.encode().unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let records = miniz_oxide::deflate::compress_to_vec(&cbor(&vec![record]), 6);

    // segment: a segment's header, then its records.
    #[derive(Serialize)]
    struct Segment<'a> {
        v: u32,
        key_id: ByteBuf,
        user: Uuid,
        conversation: Uuid,
        day: &'a str,
        complete: bool,
        nonce: ByteBuf,
        ct: ByteBuf,
    }
    let segment = Segment {
        v: 1,
        key_id: ByteBuf::from(vec![13; 8]),
        user,
        conversation,
        day: "2026-11-21",
        complete: true,
        nonce: ByteBuf::from(vec![14; 12]),
        ct: ByteBuf::from(vec![15; 48]),
    };
    write("segment", "segment", &cbor(&segment));
    write("segment", "records", &records);

    // history: a package key's payload, a package's body, its records.
    #[derive(Serialize)]
    struct KeyPayload {
        v: u32,
        share: Uuid,
        conversation: Uuid,
        key: ByteBuf,
    }
    let key = KeyPayload {
        v: 1,
        share: Uuid::from_bytes([16; 16]),
        conversation,
        key: ByteBuf::from(vec![17; 32]),
    };
    write("history", "key", &cbor(&key));
    #[derive(Serialize)]
    struct Body {
        v: u32,
        header: Header,
        records: ByteBuf,
    }
    let header = Header {
        kind: ShareKind::Share,
        conversation,
        user,
        device,
        to: Uuid::from_bytes([18; 16]),
    };
    let body = Body {
        v: 1,
        header,
        records: ByteBuf::from(records.clone()),
    };
    write("history", "body", &cbor(&body));
    write("history", "records", &records);

    // direct: a package key's message, sealed to the target's device and signed by its sender.
    let provider = OpenMlsRustCrypto::default();
    let hpke = provider
        .crypto()
        .derive_hpke_keypair(SUITE.hpke_config(), &[3; 32])
        .unwrap();
    let to_hpke: [u8; 32] = hpke.public.try_into().unwrap();
    let sealed = DirectMessage::seal(
        &provider,
        &signer(),
        FROM,
        OWN,
        &to_hpke,
        "history.key",
        &cbor(&key),
    )
    .unwrap();
    write("direct", "history_key", &sealed);

    // signed: a signed certificate as the server serves it, then each body after the byte that
    // picks its label (0 a certificate, 1 a device list, 2 a leave statement).
    let identity = signer();
    let certificate = DeviceCertificate::new(user, device, [19; 32], [20; 32], 1_795_456_679_081);
    write(
        "signed",
        "certificate",
        &certificate.sign(&identity).unwrap(),
    );
    write(
        "signed",
        "certificate_body",
        &[&[0][..], &cbor(&certificate)[..]].concat(),
    );
    let list = DeviceList::new(user, [21; 32], 2, vec![device, Uuid::from_bytes([22; 16])]);
    write(
        "signed",
        "device_list_body",
        &[&[1][..], &cbor(&list)[..]].concat(),
    );
    let leave = LeaveStatement::new(user, conversation, 0, 3, device);
    write(
        "signed",
        "leave_body",
        &[&[2][..], &cbor(&leave)[..]].concat(),
    );

    // member_list: a group's list of two members.
    let entries = vec![
        Entry {
            user,
            generation: 0,
            epoch: 1,
        },
        Entry {
            user: Uuid::from_bytes([23; 16]),
            generation: 0,
            epoch: 4,
        },
    ];
    write(
        "member_list",
        "group",
        &cbor(&MemberList::new(Kind::Group, Some(user), entries)),
    );

    // validator_input: a member's commit on the group's state, as the API asks the validator.
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, mut a1, _b1) = group(&mut server, a, b);
    let refresh = ok(
        &mut a1.core,
        json!({"cmd": "refresh", "conversation_id": conversation}),
    );
    let request = server.commit_request(
        conversation,
        &bytes(&refresh["commit"]),
        &bytes(&refresh["group_info"]),
    );
    write("validator_input", "commit", &request);
}
