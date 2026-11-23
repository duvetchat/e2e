//! The memory a package's import and a share take, as a global allocator counts what this test
//! binary holds: a binary of its own, its tests one at a time, so nothing else allocates while one
//! measures. SQLite's own allocations go through its allocator, not this one.

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use duvet_e2e::Envelope;
use duvet_e2e::history::{self, Header, ShareKind};
use duvet_e2e::messages::{Record, RecordKind};
use duvet_e2e_rules::{DeviceCertificate, Kind};
use serde_json::{Value, json};
use support::*;
use uuid::Uuid;

/// What this binary holds now, and the most it held since the last measure began.
static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every call goes to the system's allocator as it came; the counters only watch.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller of `alloc` promised.
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            grew(layout.size());
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: as the caller of `dealloc` promised.
        unsafe { System.dealloc(block, layout) };
        HELD.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: as the caller of `realloc` promised.
        let moved = unsafe { System.realloc(block, layout, size) };
        if !moved.is_null() {
            if size > layout.size() {
                grew(size - layout.size());
            } else {
                HELD.fetch_sub(layout.size() - size, Relaxed);
            }
        }
        moved
    }
}

fn grew(bytes: usize) {
    let held = HELD.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(held, Relaxed);
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// One test at a time: each measures the whole binary.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

const MIB: usize = 1024 * 1024;

/// What `f` returns, and the most held at once while it ran beyond what was held as it began.
fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let base = HELD.load(Relaxed);
    PEAK.store(base, Relaxed);
    let out = f();
    (out, PEAK.load(Relaxed).saturating_sub(base))
}

/// A group of A and B, a device each, both in it: its conversation and the devices.
fn group(server: &mut FakeServer, a: Uuid, b: Uuid) -> (Uuid, TestDevice, TestDevice) {
    let mut devices = [a, b].map(|user| server.device(user));
    for device in &mut devices {
        server.publish(device);
    }
    for device in &mut devices {
        server.introduce(device);
    }
    let [mut a1, mut b1] = devices;
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    let create = server.create_group(conversation);
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    (conversation, a1, b1)
}

/// The certificates of `user`'s devices as the server serves them.
fn certificates(server: &FakeServer, user: Uuid) -> Vec<Vec<u8>> {
    server.observed(user)["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect()
}

/// The certificate of `user`'s `device`, in base64.
fn certificate(server: &FakeServer, user: Uuid, device: Uuid) -> String {
    let found = certificates(server, user)
        .into_iter()
        .find(|signed| DeviceCertificate::read_unverified(signed).unwrap().device == device)
        .expect("the device's certificate");
    b64(&found)
}

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
    let devices = certificates(&server, b);
    let sealed = a1
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let header = Header {
                kind: ShareKind::Share,
                conversation,
                user: a,
                device: own.device,
                to: b,
            };
            let package = history::package(&own.signer, &header, &deflated)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    let from = certificate(&server, a, a1.id);
    let key = json!({
        "cmd": "receive_direct",
        "message": shared["keys"][0]["message"],
        "from_certificate": from,
    });
    ok(&mut b1.core, key);
    let command = json!({
        "cmd": "history_import",
        "share_id": shared["share_id"],
        "parts": shared["parts"],
    })
    .to_string();

    // The import reads them one at a time: it never holds them all.
    let (reply, peak) = peak_during(|| b1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"]["imported"], 6144, "{reply}");
    assert!(peak < 8 * MIB, "the import held {} MiB at once", peak / MIB);
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

    // Sharing all of it reads the records one at a time, and deflates them as they're written.
    let (reply, peak) = peak_during(|| a1.core.handle(&command));
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["ok"]["truncated"], false, "{reply}");
    assert!(peak < 8 * MIB, "the share held {} MiB at once", peak / MIB);
}
