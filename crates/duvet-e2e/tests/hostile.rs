//! What a device reads that the server made hostile, or a member through it (Review Focus 4): CBOR
//! nested 10 000 levels deep, or declaring 4 GiB it doesn't hold, in each format a device reads from
//! the server or a member; a ciphertext over 32 KiB; a history package that inflates to 1 GiB; and
//! a package's parts beyond what a package holds. Each is refused, or for the ciphertext kept unread,
//! in less than a second and holding less than 64 MiB while it's read.
//!
//! A binary of its own, its tests one at a time: the counting allocator measures the whole binary.

mod bombs;
mod memory;
mod support;

use std::time::{Duration, Instant};

use bombs::{dense_bomb, record_head};
use duvet_e2e::history::{MAX_PACKAGE, MAX_RECORD};
use duvet_e2e::messages::{Record, RecordKind};
use duvet_e2e::{Clock, Core, DirectMessage, Envelope, Error};
use duvet_e2e_rules::{DeviceCertificate, HISTORY_SHARE, sign};
use duvet_e2e_validator::{Response, validate_bytes};
use memory::{MIB, ONE_AT_A_TIME, peak_during};
use serde_json::{Value, json};
use support::*;

const GIB: u64 = 1 << 30;

/// CBOR none of the formats takes: arrays, maps (each under a key no format has) and tags nested
/// 10 000 levels deep; and a byte string, a text, an array and a map that each declare 4 GiB, and
/// hold 16 bytes.
fn hostile_cbor() -> Vec<(&'static str, Vec<u8>)> {
    let nested = |level: &[u8], last: u8| [level.repeat(10_000), vec![last]].concat();
    // A major type's header with its length in the 8 bytes after it.
    let declared = |major: u8| {
        [
            vec![major << 5 | 27],
            (4 * GIB).to_be_bytes().to_vec(),
            vec![0; 16],
        ]
        .concat()
    };
    vec![
        ("arrays nested 10 000 deep", nested(&[0x81], 0x80)),
        ("maps nested 10 000 deep", nested(&[0xa1, 0x61, b'x'], 0xa0)),
        ("tags nested 10 000 deep", nested(&[0xc6], 0x00)),
        ("a byte string declaring 4 GiB", declared(2)),
        ("a text declaring 4 GiB", declared(3)),
        ("an array declaring 4 GiB of items", declared(4)),
        ("a map declaring 4 GiB of entries", declared(5)),
    ]
}

/// What `read` returns. It must end in less than a second, holding less than 64 MiB beyond what was
/// held as it began, SQLite's included.
fn bounded<T>(what: &str, read: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let (out, held, sqlite) = peak_during(read);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(1), "{what} took {took:?}");
    assert!(
        held + sqlite < 64 * MIB,
        "{what} held {} MiB",
        (held + sqlite) / MIB
    );
    out
}

/// The error of `command` on `core`, within the bounds, whose code must be `code`.
fn refused(core: &mut Core, what: &str, command: &str, code: &str) -> Value {
    let reply = bounded(what, || core.handle(command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["error"]["code"], code, "{what}: {reply}");
    reply["error"].clone()
}

#[test]
fn hostile_inputs_are_bounded() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let (conversation, mut a1, mut b1) = group(&mut server, a, b);
    // A new device of B's on its way in, which B1 is approving.
    let mut b2 = server.bare_device(b);
    let begun = ok(&mut b2.core, json!({"cmd": "approval_begin"}));
    ok(
        &mut b1.core,
        json!({"cmd": "approval_offer", "commitment": begun["commitment"]}),
    );
    // A new device of C's, recovering the identity C's first device made.
    let (_c1, identity) = server.first_device(c);
    let mut c2 = server.bare_device(c);
    let recover = json!({
        "cmd": "recover",
        "recovery_key": identity["recovery_key"],
        "wrapped_backup_key": identity["wrapped_backup_key"],
        "encrypted_identity": identity["encrypted_identity"],
        "device_list": identity["device_list"],
    });
    let observed = server.observed(a);
    let from_a1 = certificate(&server, a, a1.id);
    let b1_hpke: [u8; 32] =
        DeviceCertificate::read_unverified(&bytes(&json!(certificate(&server, b, b1.id))))
            .unwrap()
            .hpke_key
            .try_into()
            .unwrap();

    for (shape, cbor) in hostile_cbor() {
        let data = b64(&cbor);
        let what = |reader: &str| format!("{shape}, as {reader}");

        // From the server, unsigned, or read before any signature is checked: by B1, then by the
        // new device B1 approves.
        let to_b1 = [
            (
                "a direct message",
                json!({"cmd": "receive_direct", "message": data}),
                "decrypt_failed",
            ),
            (
                "a device list",
                json!({
                    "cmd": "observe_user",
                    "user_id": a,
                    "identity_key": observed["identity_key"],
                    "device_list": data,
                }),
                "bad_command",
            ),
            (
                "a certificate",
                json!({
                    "cmd": "observe_user",
                    "user_id": a,
                    "identity_key": observed["identity_key"],
                    "device_list": observed["device_list"],
                    "certificates": [data],
                }),
                "bad_command",
            ),
            (
                "a backup segment",
                json!({"cmd": "backup_import", "data": data}),
                "bad_command",
            ),
            (
                "an approval's commitment",
                json!({"cmd": "approval_offer", "commitment": data}),
                "bad_command",
            ),
            (
                "an approval's reveal",
                json!({"cmd": "approval_check", "reveal": data}),
                "bad_command",
            ),
            (
                "an approval's QR",
                json!({"cmd": "approval_from_qr", "qr": data}),
                "bad_command",
            ),
            (
                "a safety number's QR",
                json!({"cmd": "verify_user", "user_id": a, "qr": data}),
                "bad_command",
            ),
        ];
        for (reader, command, code) in to_b1 {
            refused(&mut b1.core, &what(reader), &command.to_string(), code);
        }
        let to_b2 = [
            (
                "an approval's transfer",
                json!({"cmd": "approval_receive", "transfer": data}),
                "decrypt_failed",
            ),
            (
                "an approval's offer",
                json!({"cmd": "approval_reveal", "offer": data}),
                "bad_command",
            ),
        ];
        for (reader, command, code) in to_b2 {
            refused(&mut b2.core, &what(reader), &command.to_string(), code);
        }
        for field in [
            "wrapped_backup_key",
            "encrypted_identity",
            "wrapped_previous_backup_keys",
            "device_list",
        ] {
            let mut command = recover.clone();
            command[field] = json!(data);
            let error = refused(
                &mut c2.core,
                &what(&format!("recover's {field}")),
                &command.to_string(),
                "bad_command",
            );
            assert_eq!(error["field"], field);
        }

        // From a member, through the server: what MLS opens, a package's key in a direct message,
        // the package's body and its records.
        let error = bounded(&what("an envelope"), || Envelope::decode(&cbor)).unwrap_err();
        assert_eq!(error.code(), "decrypt_failed", "{}", what("an envelope"));
        let key = a1
            .core
            .transaction(|tx| {
                let own = tx.own_device()?;
                DirectMessage::seal(
                    tx.provider(),
                    &own.signer,
                    own.device,
                    b1.id,
                    &b1_hpke,
                    "history.key",
                    &cbor,
                )
            })
            .unwrap();
        let command = json!({
            "cmd": "receive_direct",
            "message": b64(&key),
            "from_certificate": from_a1,
        });
        refused(
            &mut b1.core,
            &what("a package's key"),
            &command.to_string(),
            "decrypt_failed",
        );
        let command = import_package(&server, &mut a1, &mut b1, conversation, |own, _| {
            sign(HISTORY_SHARE, cbor.clone(), &own.signer)
                .map_err(|_| Error::Internal("unsigned".into()))
        });
        refused(&mut b1.core, &what("a package"), &command, "decrypt_failed");
        let records = [&[0x81][..], &cbor].concat();
        let deflated = miniz_oxide::deflate::compress_to_vec(&records, 6);
        let command = import_of(&server, &mut a1, &mut b1, conversation, &deflated);
        refused(
            &mut b1.core,
            &what("a package's record"),
            &command,
            "decrypt_failed",
        );

        // The API's validator, which reads what devices send.
        let response = bounded(&what("the validator's request"), || validate_bytes(&cbor));
        let response: Response = ciborium::from_reader(response.as_slice()).unwrap();
        let code = response.error.map(|failure| failure.code);
        assert_eq!(code.as_deref(), Some("bad_request"), "{shape}");
    }

    // The command itself, nested 10 000 levels deep.
    let nested = format!(
        r#"{{"cmd":"receive_direct","message":{}"AA=="{}}}"#,
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    refused(
        &mut b1.core,
        "a command nested 10 000 deep",
        &nested,
        "bad_command",
    );

    // A message's ciphertext of 33 KiB, which the queue brings: kept as waiting, unread.
    let seq = server.chats[&conversation].queue.len() as u64 + 1;
    let command = json!({
        "cmd": "apply",
        "conversation_id": conversation,
        "entries": [{
            "seq": seq,
            "kind": "message",
            "data": b64(&[0x55; 33 * 1024]),
            "message_id": new_id(),
            "sender_user": a,
            "sender_device": a1.id,
            "sent_at": server.clock.now_ms(),
        }],
    })
    .to_string();
    let reply = bounded("a ciphertext of 33 KiB", || b1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    let result = &reply["ok"]["results"][0];
    assert_eq!(result["result"], "undecryptable", "{reply}");
    assert_eq!(result["reason"], "too_large", "{reply}");

    // A package of 1 MiB whose one record inflates to 1 GiB, as dense as DEFLATE makes it: refused
    // once the record passes what a record can be. The other shape, records each as big as a
    // message's, is bounded by task 13's `MAX_RECORDS` instead, 256 MiB inflated and one record held
    // at a time (`decompression_bomb_is_too_large`, `history_memory`), not by one second: each
    // record is imported until then. The bombs are DEFLATE streams made by hand: a check first that
    // one inflates as meant.
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(&dense_bomb(b"xy", 2)).unwrap(),
        [b"xy".as_slice(), &[0; 2 << 20]].concat()
    );
    let record = Record {
        kind: RecordKind::Message,
        id: new_id(),
        seq: 100,
        user: a,
        device: a1.id,
        sent: 1_000,
        envelope: Vec::new(),
        shared_by: None,
        reply_to: None,
    };
    let head = [&[0x81][..], &record_head(&record, GIB)].concat();
    let deflated = dense_bomb(&head, 1024);
    assert!(deflated.len() < 2 * MIB, "{} bytes", deflated.len());
    let command = import_of(&server, &mut a1, &mut b1, conversation, &deflated);
    let error = refused(
        &mut b1.core,
        "a package that inflates to 1 GiB",
        &command,
        "too_large",
    );
    assert_eq!(error["limit"], MAX_RECORD);

    // The package's parts as the server hands them over, past what a package holds: more than
    // 64 MiB in all, and more parts than 64 MiB makes. Neither is decoded before it's refused.
    let share = serde_json::from_str::<Value>(&command).unwrap()["share_id"].clone();
    let part = "A".repeat(4 * (MAX_PACKAGE / 3 + 1));
    let command = format!(r#"{{"cmd":"history_import","share_id":{share},"parts":["{part}"]}}"#);
    drop(part);
    let error = refused(
        &mut b1.core,
        "a package's parts of over 64 MiB",
        &command,
        "too_large",
    );
    assert_eq!(error["limit"], MAX_PACKAGE);
    let command = json!({
        "cmd": "history_import",
        "share_id": share,
        "parts": vec!["AAAA"; 100_000],
    })
    .to_string();
    let error = refused(
        &mut b1.core,
        "a package of 100 000 parts",
        &command,
        "too_large",
    );
    assert_eq!(error["limit"], MAX_PACKAGE);
}
