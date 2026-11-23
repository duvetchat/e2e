//! The memory a package's import, a share and a catch-up take, as a global allocator counts what
//! this test binary holds: a binary of its own, its tests one at a time, so nothing else allocates
//! while one measures. SQLite's own allocations go through its allocator, not this one; SQLite
//! counts them itself, and the tests read that count too.

mod bombs;
mod memory;
mod support;

use bombs::{bomb, record_head};
use duvet_e2e::Envelope;
use duvet_e2e::history;
use duvet_e2e::messages::{Record, RecordKind};
use memory::{MIB, ONE_AT_A_TIME, peak_during};
use serde_json::{Value, json};
use support::*;
use uuid::Uuid;

/// `count` messages of A1's of 4 KiB each, sent a millisecond apart: what deflates to little.
fn messages_of_a(a: Uuid, a1: &TestDevice, count: u64) -> Vec<Record> {
    let envelope = Envelope::Message {
        text: Some("x".repeat(4096)),
        attachments: Vec::new(),
    }
    .encode()
    .unwrap();
    (0..count)
        .map(|n| Record {
            kind: RecordKind::Message,
            id: new_id(),
            seq: 100 + n,
            user: a,
            device: a1.id,
            sent: 1_000 + n,
            envelope: envelope.clone(),
            shared_by: None,
            reply_to: None,
        })
        .collect()
}

#[test]
fn an_import_holds_one_record_at_a_time() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, mut a1, mut b1) = group(&mut server, a, b);

    // A1 seals 24 MiB of records, which deflate to little, and B1 takes its key.
    let records = messages_of_a(a, &a1, 6144);
    let mut cbor = Vec::new();
    ciborium::into_writer(&records, &mut cbor).unwrap();
    let deflated = miniz_oxide::deflate::compress_to_vec(&cbor, 1);
    drop((records, cbor));
    let command = import_of(&server, &mut a1, &mut b1, conversation, &deflated);

    // The import reads them one at a time: it never holds them all.
    let (reply, peak, _) = peak_during(|| b1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"]["imported"], 6144, "{reply}");
    assert!(peak < 8 * MIB, "the import held {} MiB at once", peak / MIB);
}

#[test]
fn an_import_refuses_a_record_bigger_than_a_message() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, mut a1, mut b1) = group(&mut server, a, b);

    // A1 signs a package of under 2 MiB whose one record inflates to 255 MiB: an envelope no
    // message could have, though the whole stays under the cap on what a package inflates to.
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
    let zeros = 255 * MIB as u64;
    let head = record_head(&record, zeros);
    let deflated = bomb([(&[0x81][..], 0), (head.as_slice(), zeros)]);
    assert!(deflated.len() < 2 * MIB, "{} bytes", deflated.len());
    let command = import_of(&server, &mut a1, &mut b1, conversation, &deflated);

    // B1 refuses the record once it passes what a record can be, holding little of it.
    let (reply, peak, _) = peak_during(|| b1.core.handle(&command));
    assert!(peak < 8 * MIB, "the import held {} MiB at once", peak / MIB);
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["error"]["code"], "too_large", "{reply}");
    assert_eq!(reply["error"]["limit"], history::MAX_RECORD);
}

#[test]
fn a_share_holds_one_record_at_a_time() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, mut a1, _b1) = group(&mut server, a, b);

    // A1 has 24 MiB of a conversation's history.
    let records = messages_of_a(a, &a1, 6144);
    let kept = a1
        .core
        .transaction(|tx| duvet_e2e::messages::import(tx, conversation, &records, None))
        .unwrap();
    assert_eq!(kept, 6144);
    drop(records);
    let command = json!({
        "cmd": "history_share",
        "conversation_id": conversation,
        "to_user": b,
        "range": "all",
        "devices": certificates(&server, b).iter().map(|signed| b64(signed)).collect::<Vec<_>>(),
    })
    .to_string();

    // Sharing all of it reads the records one at a time, in an order SQLite doesn't sort, and
    // deflates them as they're written.
    let (reply, peak, sqlite) = peak_during(|| a1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"]["truncated"], false, "{reply}");
    assert!(peak < 8 * MIB, "the share held {} MiB at once", peak / MIB);
    assert!(sqlite < 8 * MIB, "SQLite held {} MiB at once", sqlite / MIB);
}

#[test]
fn a_catch_up_holds_one_record_at_a_time() {
    let _one = ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, mut a1, _b1) = group(&mut server, a, b);

    // A1 has 24 MiB of messages of its own, all noted for B.
    let records = messages_of_a(a, &a1, 6144);
    a1.core
        .transaction(|tx| {
            duvet_e2e::messages::import(tx, conversation, &records, None)?;
            tx.conn().execute(
                "INSERT INTO deviceless (conversation_id, user_id, message) \
                 SELECT conversation_id, ?1, id FROM messages WHERE conversation_id = ?2",
                rusqlite::params![b.as_bytes().as_slice(), conversation.as_bytes().as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
    drop(records);
    let command = json!({
        "cmd": "catch_up",
        "conversation_id": conversation,
        "user_id": b,
        "devices": certificates(&server, b).iter().map(|signed| b64(signed)).collect::<Vec<_>>(),
    })
    .to_string();

    // The catch-up reads them as a share does.
    let (reply, peak, sqlite) = peak_during(|| a1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"]["truncated"], false, "{reply}");
    assert!(
        peak < 8 * MIB,
        "the catch-up held {} MiB at once",
        peak / MIB
    );
    assert!(sqlite < 8 * MIB, "SQLite held {} MiB at once", sqlite / MIB);
}
