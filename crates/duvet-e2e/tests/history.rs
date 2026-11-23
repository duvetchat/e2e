//! Shared history and catch-ups through `Core::handle`, against a fake of the API: a member shares
//! what its device has of a conversation with a newer member, and a sender passes a member whose
//! devices couldn't read what it sent while they had none. Either is one package, signed by the
//! sending device and sealed in parts under a key that goes to each of the recipient's devices by
//! the channel between devices; the recipient takes the key (`receive_direct`), then the package
//! (`history_import`), whose messages show as shared by the sender.

mod bombs;
mod support;

use bombs::{bomb, record_head};
use duvet_e2e::history::{self, Header, MAX_PACKAGE, MAX_RECORDS, Range, ShareKind};
use duvet_e2e::messages::{Record, RecordKind};
use duvet_e2e::parts::{open_part, seal_part};
use duvet_e2e::{Clock, DirectMessage, Envelope, MAX_ENVELOPE};
use duvet_e2e_rules::{DeviceCertificate, Kind};
use openmls::prelude::SignatureScheme;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_json::{Value, json};
use support::*;
use uuid::Uuid;

/// New devices for `users`, one per entry, with key packages published, every device knowing
/// every user.
fn new_devices<const N: usize>(server: &mut FakeServer, users: [Uuid; N]) -> [TestDevice; N] {
    let mut devices = users.map(|user| server.device(user));
    for device in &mut devices {
        server.publish(device);
    }
    for device in &mut devices {
        server.introduce(device);
    }
    devices
}

/// `creator` makes the group of `conversation`, as the API has it, and the server takes it.
fn start(server: &mut FakeServer, creator: &mut TestDevice, conversation: Uuid) {
    let command = server.create_group(conversation);
    server
        .commit(creator, conversation, command)
        .expect("the server takes epoch 0");
}

/// A group of the two users, each with one device in it.
fn group_of(server: &mut FakeServer, users: [Uuid; 2]) -> (Uuid, [TestDevice; 2]) {
    let [a, b] = users;
    let [mut a1, mut b1] = new_devices(server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    (conversation, [a1, b1])
}

/// `add_members` for `user`, with the key packages of their devices.
fn adding(server: &mut FakeServer, conversation: Uuid, user: Uuid) -> Value {
    let claimed = server.claim(&[user]);
    json!({
        "cmd": "add_members",
        "conversation_id": conversation,
        "users": [{"user_id": user, "key_packages": claimed[user.to_string().as_str()]}],
    })
}

fn apply(conversation: Uuid, entries: &[Value]) -> Value {
    json!({"cmd": "apply", "conversation_id": conversation, "entries": entries})
}

/// `device` encrypts `text` under a new nonce, without posting it yet: the nonce and the
/// ciphertext.
fn encrypted(device: &mut TestDevice, conversation: Uuid, text: &str) -> (String, Vec<u8>) {
    let nonce = new_id().to_string();
    let reply = ok(
        &mut device.core,
        json!({
            "cmd": "encrypt",
            "conversation_id": conversation,
            "nonce": nonce,
            "envelope": {"text": text},
        }),
    );
    (nonce, bytes(&reply["ciphertext"]))
}

/// `device` posts what it encrypted under `nonce`, and hears the API's answer: the message's ID.
fn post(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    (nonce, ciphertext): (String, Vec<u8>),
) -> Uuid {
    let (message_id, seq) = server.post_message(device, conversation, &nonce, ciphertext, &[]);
    ok(
        &mut device.core,
        json!({
            "cmd": "sent",
            "conversation_id": conversation,
            "nonce": nonce,
            "message_id": message_id,
            "seq": seq,
        }),
    );
    message_id
}

/// `device` writes `text` to `conversation`: the message's ID.
fn say(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid, text: &str) -> Uuid {
    let message = encrypted(device, conversation, text);
    post(server, device, conversation, message)
}

/// The messages of `conversation` as `device` shows them, newest first.
fn messages_of(device: &mut TestDevice, conversation: Uuid) -> Vec<Value> {
    let page = ok(
        &mut device.core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
    );
    page["messages"].as_array().unwrap().clone()
}

fn ids(shown: &[Value]) -> Vec<Uuid> {
    shown
        .iter()
        .map(|message| message["message_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// The certificates of `user`'s devices as the server serves them, in base64: what a share's
/// `devices` takes.
fn certificates(server: &FakeServer, user: Uuid) -> Value {
    server.observed(user)["certificates"].clone()
}

/// The same certificates, as bytes.
fn certificate_bytes(server: &FakeServer, user: Uuid) -> Vec<Vec<u8>> {
    certificates(server, user)
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect()
}

/// The certificate of `user`'s `device` as the server serves it, in base64.
fn certificate(server: &FakeServer, user: Uuid, device: Uuid) -> String {
    certificates(server, user)
        .as_array()
        .unwrap()
        .iter()
        .map(|certificate| certificate.as_str().unwrap().to_owned())
        .find(|certificate| {
            let signed = bytes(&json!(certificate));
            DeviceCertificate::read_unverified(&signed).unwrap().device == device
        })
        .expect("the device's certificate")
}

/// The HPKE key of `user`'s `device`, from its certificate.
fn hpke_key(server: &FakeServer, user: Uuid, device: Uuid) -> [u8; 32] {
    let signed = bytes(&json!(certificate(server, user, device)));
    DeviceCertificate::read_unverified(&signed)
        .unwrap()
        .hpke_key
        .try_into()
        .unwrap()
}

/// The server puts each key of a share's reply in its device's inbox.
fn post_keys(server: &mut FakeServer, shared: &Value) {
    for key in shared["keys"].as_array().unwrap() {
        let device: Uuid = key["device_id"].as_str().unwrap().parse().unwrap();
        server.post(device, bytes(&key["message"]));
    }
}

fn receive_direct(message: &[u8], from_certificate: &str) -> Value {
    json!({"cmd": "receive_direct", "message": b64(message), "from_certificate": from_certificate})
}

/// `device` takes what waits in its inbox, from the device whose certificate is `from`: the
/// replies, each `ok` or `error`.
fn take_inbox(server: &mut FakeServer, device: &mut TestDevice, from: &str) -> Vec<Value> {
    server
        .inbox(device.id)
        .iter()
        .map(|message| run(&mut device.core, &receive_direct(message, from)))
        .collect()
}

fn import(shared: &Value) -> Value {
    json!({"cmd": "history_import", "share_id": shared["share_id"], "parts": shared["parts"]})
}

/// What a refusal says: its code, and its extra field when it has one.
fn refusal(error: &Value) -> Value {
    let extra = ["rule", "what", "field", "kind", "limit"]
        .into_iter()
        .find_map(|field| error.get(field).cloned())
        .unwrap_or(Value::Null);
    json!([error["code"], extra])
}

/// Text deflate can't shrink much: `len` letters from a small generator seeded by `seed`.
fn noise(seed: u64, len: usize) -> String {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            char::from(b'a' + (state % 26) as u8)
        })
        .collect()
}

#[test]
fn history_share_week() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let (conversation, [mut a1, mut c1]) = group_of(&mut server, [a, c]);
    let mut b1 = server.device(b);
    server.publish(&mut b1);
    server.introduce(&mut b1);
    server.introduce(&mut a1);
    server.introduce(&mut c1);

    // A and C talk for ten days before B comes in. C edits a message of theirs the ninth day.
    let old = say(&mut server, &mut a1, conversation, "hace diez días");
    server.clock.advance(5 * DAY_MS);
    let five = say(&mut server, &mut c1, conversation, "hace cinco días");
    server.clock.advance(4 * DAY_MS);
    let yesterday = say(&mut server, &mut a1, conversation, "ayer");
    let edited = ok(
        &mut c1.core,
        json!({
            "cmd": "edit",
            "conversation_id": conversation,
            "message_id": five,
            "text": "hace cinco días, editado",
        }),
    );
    server.post_change(
        &c1,
        conversation,
        "edit",
        five,
        bytes(&edited["ciphertext"]),
    );
    server.clock.advance(DAY_MS);
    server.deliver_all(&mut [&mut a1, &mut c1]);

    // A adds B. B1 joins by the welcome, and has nothing from before.
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    assert_eq!(messages_of(&mut b1, conversation), Vec::<Value>::new());

    // A share goes only to a member who isn't A, and only to that member's devices.
    let share = |to: Uuid, devices: Value| {
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": to,
            "range": "week",
            "devices": devices,
        })
    };
    let refused = error(&mut a1.core, share(new_id(), certificates(&server, b)));
    assert_eq!(refusal(&refused), json!(["not_found", "member"]));
    let refused = error(&mut a1.core, share(a, certificates(&server, a)));
    assert_eq!(refusal(&refused), json!(["bad_command", "to_user"]));
    let refused = error(&mut a1.core, share(b, certificates(&server, c)));
    assert_eq!(refusal(&refused), json!(["rule_violation", "wrong_user"]));

    // A1 shares the last week with B: one package, its key sealed to B1.
    let now = server.clock.now_ms();
    let shared = ok(&mut a1.core, share(b, certificates(&server, b)));
    assert_eq!(shared["truncated"], false);
    assert_eq!(shared["start"], json!(now - 7 * DAY_MS));
    // Its ID is a v7 UUID, as the API's are, with the core's time in its first 48 bits.
    let share_id: Uuid = shared["share_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(share_id.get_version_num(), 7);
    let mut millis = [0u8; 8];
    millis[2..].copy_from_slice(&share_id.as_bytes()[..6]);
    assert_eq!(i64::from_be_bytes(millis), now);
    let size: usize = shared["parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|part| bytes(part).len())
        .sum();
    assert_eq!(shared["size"], json!(size));
    let keys = shared["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["device_id"], json!(b1.id));

    // B1 takes the key from its inbox, then the package.
    post_keys(&mut server, &shared);
    let from = certificate(&server, a, a1.id);
    let received = take_inbox(&mut server, &mut b1, &from);
    let received = received[0].get("ok").expect("the key is taken");
    assert_eq!(received["type"], "history.key");
    assert_eq!(received["share_id"], shared["share_id"]);
    assert_eq!(received["conversation_id"], json!(conversation));
    assert_eq!(received["user_id"], json!(a));
    let imported = ok(&mut b1.core, import(&shared));
    assert_eq!(imported["imported"], 2);

    // B1 has the week's messages as A1 had them, each marked as shared by A, and nothing from
    // before the week. C's edit isn't applied: an edit counts only from its author's own package.
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(ids(&shown), [yesterday, five]);
    assert!(!ids(&shown).contains(&old));
    assert_eq!(shown[0]["user_id"], json!(a));
    assert_eq!(shown[0]["text"], "ayer");
    assert_eq!(shown[1]["user_id"], json!(c));
    assert_eq!(shown[1]["text"], "hace cinco días");
    assert_eq!(shown[1]["edited_at"], Value::Null);
    for message in &shown {
        assert_eq!(message["shared_by"], json!(a));
        assert_eq!(message["status"], "ok");
    }

    // Its key went with the import: the same package again is unknown.
    let again = error(&mut b1.core, import(&shared));
    assert_eq!(refusal(&again), json!(["not_found", "share"]));
}

/// How many package keys `device` keeps.
fn keys_kept(device: &mut TestDevice) -> i64 {
    device.rolled_back(|tx| {
        Ok(tx
            .conn()
            .query_row("SELECT count(*) FROM history_keys", [], |row| row.get(0))?)
    })
}

#[test]
fn a_key_goes_once_its_package_is_imported_or_the_server_drops_it() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    let share_all = json!({
        "cmd": "history_share",
        "conversation_id": conversation,
        "to_user": b,
        "range": "all",
        "devices": certificates(&server, b),
    });
    let from = certificate(&server, a, a1.id);

    // B1 takes a key whose package it never imports. 31 days on, when another key comes, the
    // server no longer keeps that package, and its key goes.
    let old = ok(&mut a1.core, share_all.clone());
    post_keys(&mut server, &old);
    take_inbox(&mut server, &mut b1, &from);
    assert_eq!(keys_kept(&mut b1), 1);
    server.clock.advance(31 * DAY_MS);
    let new = ok(&mut a1.core, share_all);
    post_keys(&mut server, &new);
    take_inbox(&mut server, &mut b1, &from);
    assert_eq!(keys_kept(&mut b1), 1);
    let gone = error(&mut b1.core, import(&old));
    assert_eq!(refusal(&gone), json!(["not_found", "share"]));

    // The other is used up by its import.
    ok(&mut b1.core, import(&new));
    assert_eq!(keys_kept(&mut b1), 0);
}

#[test]
fn share_truncates_to_64_mib() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let (conversation, [mut a1, mut c1]) = group_of(&mut server, [a, c]);

    // A1 writes sixteen long messages, a second apart.
    let mut written = Vec::new();
    for seed in 0..16 {
        written.push(say(&mut server, &mut a1, conversation, &noise(seed, 1500)));
        server.clock.advance(1000);
    }
    server.deliver_all(&mut [&mut a1, &mut c1]);

    // B comes in after them.
    let mut b1 = server.device(b);
    server.publish(&mut b1);
    server.introduce(&mut b1);
    server.introduce(&mut a1);
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let devices = certificate_bytes(&server, b);

    // Under the real cap, all of it fits.
    let whole = a1
        .core
        .transaction(|tx| history::share(tx, conversation, b, Range::All, &devices, MAX_PACKAGE))
        .unwrap();
    assert!(!whole.truncated);
    assert_eq!(whole.start, 0);

    // Under a smaller cap, the same function shares what fits of the newest: everything from
    // `start` on, and nothing before it.
    let limit = 6 * 1024;
    let cut = a1
        .core
        .transaction(|tx| history::share(tx, conversation, b, Range::All, &devices, limit))
        .unwrap();
    assert!(cut.truncated);
    assert!(cut.sealed.size <= limit as u64, "{} bytes", cut.sealed.size);
    let size: usize = cut.sealed.parts.iter().map(Vec::len).sum();
    assert_eq!(cut.sealed.size, size as u64);

    let shared = serde_json::to_value(&cut).unwrap();
    post_keys(&mut server, &shared);
    let from = certificate(&server, a, a1.id);
    let received = take_inbox(&mut server, &mut b1, &from);
    assert!(received[0].get("ok").is_some(), "{}", received[0]);
    let imported = ok(&mut b1.core, import(&shared))["imported"]
        .as_u64()
        .unwrap();
    let shown = messages_of(&mut b1, conversation);
    let mut got = ids(&shown);
    got.reverse();
    assert!(
        !got.is_empty() && got.len() < written.len(),
        "{} of {}",
        got.len(),
        written.len()
    );
    assert_eq!(imported, got.len() as u64);
    assert_eq!(got, written[written.len() - got.len()..]);
    for message in &shown {
        assert!(message["sent_at"].as_i64().unwrap() >= cut.start);
    }
    // The newest message left out was sent before `start`.
    let left_out = written[written.len() - got.len() - 1];
    let left_out = messages_of(&mut a1, conversation)
        .into_iter()
        .find(|message| message["message_id"] == json!(left_out))
        .unwrap();
    assert!(left_out["sent_at"].as_i64().unwrap() < cut.start);
}

#[test]
fn share_rejects_a_bad_signature_or_a_stranger() {
    let mut server = FakeServer::new();
    let (a, b, s) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut s1] = new_devices(&mut server, [a, a, b, s]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    say(&mut server, &mut a1, conversation, "lo que B ya tiene");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let devices = certificate_bytes(&server, b);
    let to_b1 = hpke_key(&server, b, b1.id);
    let a1_certificate = certificate(&server, a, a1.id);
    let a2_certificate = certificate(&server, a, a2.id);
    let s1_certificate = certificate(&server, s, s1.id);
    let shown = |device: &mut TestDevice| messages_of(device, conversation);
    let before = shown(&mut b1);
    let share_all = json!({
        "cmd": "history_share",
        "conversation_id": conversation,
        "to_user": b,
        "range": "all",
        "devices": certificates(&server, b),
    });

    // A2 leaves A's list, and B1 sees the new list. A2 still holds A's identity and the group.
    let signed = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &signed["device_list"]);
    assert_ne!(ok(&mut b1.core, server.observed(a))["state"], "rejected");
    let shared = ok(&mut a2.core, share_all.clone());
    let key = bytes(&shared["keys"][0]["message"]);
    // B1 first asks to observe A anew, as its list of A may be old; at the same list, it refuses.
    let asked = error(&mut b1.core, receive_direct(&key, &a2_certificate));
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a]))
    );
    ok(&mut b1.core, server.observed(a));
    let refused = error(&mut b1.core, receive_direct(&key, &a2_certificate));
    assert_eq!(
        refusal(&refused),
        json!(["rule_violation", "device_not_listed"])
    );

    // A device whose certificate another identity signed, as A's.
    let forger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let other_identity = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let forged_device = new_id();
    let forged_certificate = DeviceCertificate::new(
        a,
        forged_device,
        forger.public().try_into().unwrap(),
        [9; 32],
        server.clock.now_ms() as u64,
    )
    .sign(&other_identity)
    .unwrap();
    let provider = OpenMlsRustCrypto::default();
    let key = DirectMessage::seal(
        &provider,
        &forger,
        forged_device,
        b1.id,
        &to_b1,
        "history.key",
        b"a key",
    )
    .unwrap();
    // As an identity B1 hasn't observed yet may have signed it, B1 asks first, then refuses.
    let forged = b64(&forged_certificate);
    let asked = error(&mut b1.core, receive_direct(&key, &forged));
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a]))
    );
    ok(&mut b1.core, server.observed(a));
    let refused = error(&mut b1.core, receive_direct(&key, &forged));
    assert_eq!(
        refusal(&refused),
        json!(["invalid_signature", "certificate"])
    );

    // A1's certificate, on a key another key signed.
    let key = DirectMessage::seal(
        &provider,
        &forger,
        a1.id,
        b1.id,
        &to_b1,
        "history.key",
        b"a key",
    )
    .unwrap();
    let refused = error(&mut b1.core, receive_direct(&key, &a1_certificate));
    assert_eq!(
        refusal(&refused),
        json!(["invalid_signature", "direct message"])
    );

    // A1's key, on a package another key signed: the key is taken, the package isn't.
    let empty = miniz_oxide::deflate::compress_to_vec(&cbor(&Vec::<Record>::new()), 6);
    let header = Header {
        kind: ShareKind::Share,
        conversation,
        user: a,
        device: a1.id,
        to: b,
    };
    let sealed = a1
        .core
        .transaction(|tx| {
            let package = history::package(&forger, &header, &empty)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    post_keys(&mut server, &shared);
    let taken = take_inbox(&mut server, &mut b1, &a1_certificate);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);
    let refused = error(&mut b1.core, import(&shared));
    assert_eq!(
        refusal(&refused),
        json!(["invalid_signature", "history share"])
    );

    // A1's key and A1's signature, on a package whose header says it's of another conversation.
    let sealed = a1
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let elsewhere = Header {
                conversation: new_id(),
                ..header.clone()
            };
            let package = history::package(&own.signer, &elsewhere, &empty)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    post_keys(&mut server, &shared);
    let taken = take_inbox(&mut server, &mut b1, &a1_certificate);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);
    let refused = error(&mut b1.core, import(&shared));
    assert_eq!(
        refusal(&refused),
        json!(["rule_violation", "share_mismatch"])
    );

    // A package from someone who isn't in the conversation: S, whom B1 knows.
    let sealed = s1
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let header = Header {
                kind: ShareKind::Share,
                conversation,
                user: s,
                device: own.device,
                to: b,
            };
            let package = history::package(&own.signer, &header, &empty)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    post_keys(&mut server, &shared);
    let taken = take_inbox(&mut server, &mut b1, &s1_certificate);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);
    let refused = error(&mut b1.core, import(&shared));
    assert_eq!(
        refusal(&refused),
        json!(["rule_violation", "user_not_member"])
    );

    // A1's own share, with a part changed on the way: it doesn't open.
    let shared = ok(&mut a1.core, share_all);
    post_keys(&mut server, &shared);
    let taken = take_inbox(&mut server, &mut b1, &a1_certificate);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);
    let mut tampered = shared.clone();
    let mut part = bytes(&tampered["parts"][0]);
    part[5] ^= 1;
    tampered["parts"][0] = json!(b64(&part));
    let refused = error(&mut b1.core, import(&tampered));
    assert_eq!(refusal(&refused), json!(["decrypt_failed", "history"]));

    // None of it changed what B1 shows; A1's package as it came still opens.
    assert_eq!(shown(&mut b1), before);
    assert_eq!(ok(&mut b1.core, import(&shared))["imported"], 0);
}

#[test]
fn decompression_bomb_is_too_large() {
    // The bombs are DEFLATE streams made by hand: a check that one inflates as meant.
    let parts = [(b"xy".as_slice(), 600), (b"z", 3), (b"w", 0)];
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(&bomb(parts)).unwrap(),
        [b"xy".as_slice(), &[0; 600], b"z", &[0; 3], b"w"].concat()
    );

    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    let devices = certificate_bytes(&server, b);

    // A1 signs a package whose records inflate past 256 MiB: 8300 records, each with an envelope
    // of 32 KiB of zeros, as big as a message's can be.
    let record = Record {
        kind: RecordKind::Message,
        id: new_id(),
        seq: 1,
        user: a,
        device: a1.id,
        sent: 1,
        envelope: Vec::new(),
        shared_by: None,
        reply_to: None,
    };
    let envelope = MAX_ENVELOPE as u64;
    let head = record_head(&record, envelope);
    let count: u64 = 8300;
    let mut list = vec![0x9B]; // an array, its length in 8 bytes
    list.extend(count.to_be_bytes());
    let each = std::iter::repeat_n((head.as_slice(), envelope), count as usize);
    let records = bomb(std::iter::once((list.as_slice(), 0)).chain(each));
    assert!(records.len() < MAX_PACKAGE / 16, "{} bytes", records.len());
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
            let package = history::package(&own.signer, &header, &records)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    post_keys(&mut server, &shared);
    let from = certificate(&server, a, a1.id);
    let taken = take_inbox(&mut server, &mut b1, &from);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);

    // B1 stops inflating at the cap, and imports nothing.
    let refused = error(&mut b1.core, import(&shared));
    assert_eq!(refusal(&refused), json!(["too_large", MAX_RECORDS]));
    assert_eq!(messages_of(&mut b1, conversation), Vec::<Value>::new());
}

/// A group A makes with B, who has no device yet, as A1's client knows: its conversation, the
/// two users, and A1.
fn deviceless_b(server: &mut FakeServer) -> (Uuid, [Uuid; 2], TestDevice) {
    let (a, b) = (new_id(), new_id());
    let [mut a1] = new_devices(server, [a]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "group",
        "owner": a,
        "members": [a, b],
        "key_packages": server.claim(&[a]),
        "external_sender": server.external_sender(),
        "legacy": false,
    });
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver(&mut a1);
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    (conversation, [a, b], a1)
}

/// `user`'s first device, which enters the group of `conversation` by external commit.
fn first_device_joins(server: &mut FakeServer, user: Uuid, conversation: Uuid) -> TestDevice {
    let mut device = server.device(user);
    server.introduce(&mut device);
    let joining = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    });
    server.commit(&mut device, conversation, joining).unwrap();
    device
}

fn catch_up_command(server: &FakeServer, conversation: Uuid, user: Uuid) -> Value {
    json!({
        "cmd": "catch_up",
        "conversation_id": conversation,
        "user_id": user,
        "devices": certificates(server, user),
    })
}

fn delivered(conversation: Uuid, user: Uuid, share_id: &Value) -> Value {
    json!({
        "cmd": "catch_up_delivered",
        "conversation_id": conversation,
        "user_id": user,
        "share_id": share_id,
    })
}

/// Who `device` names as due a catch-up in `conversation`.
fn due(device: &mut TestDevice, conversation: Uuid) -> Value {
    ok(&mut device.core, apply(conversation, &[]))["catch_up_due"].clone()
}

/// `device` takes the key of `shared` from its inbox, from the device whose certificate is `from`,
/// then the package: how many records it imported.
fn take_package(
    server: &mut FakeServer,
    device: &mut TestDevice,
    from: &str,
    shared: &Value,
) -> u64 {
    post_keys(server, shared);
    let taken = take_inbox(server, device, from);
    assert!(
        taken.iter().all(|reply| reply.get("ok").is_some()),
        "{taken:?}"
    );
    ok(&mut device.core, import(shared))["imported"]
        .as_u64()
        .unwrap()
}

#[test]
fn catch_up_delivers_what_was_missed() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);

    // A1 writes twice while B has no device: both are noted for B.
    let first = encrypted(&mut a1, conversation, "para cuando llegues");
    let second = encrypted(&mut a1, conversation, "y esto también");

    // B's first device enters by external commit, and A1's messages reach the API after it,
    // encrypted at the epoch before: B1 can't read them, and shows them as waiting.
    let mut b1 = first_device_joins(&mut server, b, conversation);
    let first = post(&mut server, &mut a1, conversation, first);
    let second = post(&mut server, &mut a1, conversation, second);
    server.deliver(&mut b1);
    let waiting = messages_of(&mut b1, conversation);
    assert_eq!(ids(&waiting), [second, first]);
    for message in &waiting {
        assert_eq!(message["status"], "waiting");
        assert_eq!(message["text"], Value::Null);
    }

    // A1 takes the queue: B1's commit makes B due a catch-up.
    server.introduce(&mut a1);
    let taken = server.deliver(&mut a1);
    assert_eq!(taken[0]["catch_up_due"], json!([b]));

    // A1 makes it, sealed to B1. B stays due until the client says the package is delivered;
    // then nothing is left to catch up.
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    assert_eq!(caught["truncated"], false);
    assert_eq!(caught["keys"].as_array().unwrap().len(), 1);
    assert_eq!(caught["keys"][0]["device_id"], json!(b1.id));
    assert_eq!(due(&mut a1, conversation), json!([b]));
    ok(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(due(&mut a1, conversation), json!([]));
    let nothing = error(&mut a1.core, catch_up_command(&server, conversation, b));
    assert_eq!(refusal(&nothing), json!(["not_found", "catch_up"]));

    // B1 takes the key, then the package: what waited is there, marked as shared by A.
    post_keys(&mut server, &caught);
    let from = certificate(&server, a, a1.id);
    let received = take_inbox(&mut server, &mut b1, &from);
    let received = received[0].get("ok").expect("the key is taken");
    assert_eq!(received["type"], "catch_up.key");
    assert_eq!(received["user_id"], json!(a));
    let imported = ok(&mut b1.core, import(&caught));
    assert_eq!(imported["imported"], 2);
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(ids(&shown), [second, first]);
    assert_eq!(shown[0]["text"], "y esto también");
    assert_eq!(shown[1]["text"], "para cuando llegues");
    for message in &shown {
        assert_eq!(message["status"], "ok");
        assert_eq!(message["user_id"], json!(a));
        assert_eq!(message["shared_by"], json!(a));
    }
}

#[test]
fn no_catch_up_while_the_member_has_no_device() {
    let mut server = FakeServer::new();
    let (conversation, [_, b], mut a1) = deviceless_b(&mut server);
    say(&mut server, &mut a1, conversation, "para después");

    // B sets up a device, which hasn't entered the group: A1's client still counts B as without
    // one, so nothing is sealed to a device that may never come.
    let _b1 = server.device(b);
    server.introduce(&mut a1);
    let refused = error(&mut a1.core, catch_up_command(&server, conversation, b));
    assert_eq!(refusal(&refused), json!(["not_found", "catch_up"]));
}

#[test]
fn a_note_taken_again_outlives_an_older_delivery() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);
    let message = say(&mut server, &mut a1, conversation, "antes de la edición");
    let mut b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));

    // B goes without a device again before that package is delivered, and A1 edits the message:
    // its note is taken again.
    let without = |users: Value| json!({"cmd": "without_devices", "conversation_id": conversation, "users": users});
    ok(&mut a1.core, without(json!([b])));
    let edited = ok(
        &mut a1.core,
        json!({
            "cmd": "edit",
            "conversation_id": conversation,
            "message_id": message,
            "text": "después de la edición",
        }),
    );
    server.post_change(
        &a1,
        conversation,
        "edit",
        message,
        bytes(&edited["ciphertext"]),
    );
    server.deliver(&mut a1);

    // Once B has a device again, the older package's delivery leaves that note: B is due, and the
    // next catch-up carries the edit.
    ok(&mut a1.core, without(json!([])));
    ok(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(due(&mut a1, conversation), json!([b]));
    let next = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from = certificate(&server, a, a1.id);
    take_package(&mut server, &mut b1, &from, &caught);
    take_package(&mut server, &mut b1, &from, &next);
    assert_eq!(
        messages_of(&mut b1, conversation)[0]["text"],
        "después de la edición"
    );
}

#[test]
fn a_forged_share_neither_takes_another_senders_message_nor_outlasts_its_authors() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut c1] = new_devices(&mut server, [a, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "group",
        "owner": a,
        "members": [a, b, c],
        "key_packages": server.claim(&[a, c]),
        "external_sender": server.external_sender(),
        "legacy": false,
    });
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut c1]);
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );

    // A1 writes twice while B has no device; B1 joins, and shows both as waiting, A's.
    let first = encrypted(&mut a1, conversation, "lo que A escribió");
    let second = encrypted(&mut a1, conversation, "y esto también");
    let mut b1 = first_device_joins(&mut server, b, conversation);
    let first = post(&mut server, &mut a1, conversation, first);
    let second = post(&mut server, &mut a1, conversation, second);
    server.introduce(&mut c1);
    server.deliver_all(&mut [&mut b1, &mut c1]);

    // C shares made-up copies: the first as A's, the second as C's own.
    let forged = |id: Uuid, user: Uuid, text: &str| Record {
        kind: duvet_e2e::messages::RecordKind::Message,
        id,
        seq: 1,
        user,
        device: c1.id,
        sent: 1,
        envelope: duvet_e2e::Envelope::Message {
            text: Some(text.into()),
            attachments: Vec::new(),
        }
        .encode()
        .unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let records = vec![forged(first, a, "inventado"), forged(second, c, "también")];
    let deflated = miniz_oxide::deflate::compress_to_vec(&cbor(&records), 6);
    let devices = certificate_bytes(&server, b);
    let sealed = c1
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let header = Header {
                kind: ShareKind::Share,
                conversation,
                user: c,
                device: own.device,
                to: b,
            };
            let package = history::package(&own.signer, &header, &deflated)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let from_c = certificate(&server, c, c1.id);
    let forgery = serde_json::to_value(&sealed).unwrap();
    take_package(&mut server, &mut b1, &from_c, &forgery);

    // The message the API says is A's takes no record of C's: it still waits.
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(ids(&shown), [second, first]);
    assert_eq!(shown[0]["status"], "waiting");

    // A's own catch-up replaces the copy C shared, and fills what waits.
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from_a = certificate(&server, a, a1.id);
    assert_eq!(take_package(&mut server, &mut b1, &from_a, &caught), 2);
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(shown[0]["text"], "y esto también");
    assert_eq!(shown[1]["text"], "lo que A escribió");
    for message in &shown {
        assert_eq!(message["user_id"], json!(a));
        assert_eq!(message["shared_by"], json!(a));
    }
}

#[test]
fn a_lost_catch_up_is_made_again() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);
    let first = say(&mut server, &mut a1, conversation, "uno");
    let second = say(&mut server, &mut a1, conversation, "dos");
    let mut b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    assert_eq!(due(&mut a1, conversation), json!([b]));

    // A1 makes B's catch-up, and its reply is lost before anything is uploaded: nothing is
    // forgotten, and B is still due one.
    ok(&mut a1.core, catch_up_command(&server, conversation, b));
    assert_eq!(due(&mut a1, conversation), json!([b]));

    // The next one carries everything again.
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from = certificate(&server, a, a1.id);
    assert_eq!(take_package(&mut server, &mut b1, &from, &caught), 2);
    assert_eq!(ids(&messages_of(&mut b1, conversation)), [second, first]);
}

#[test]
fn delivered_forgets_only_what_its_package_carried() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);
    let first = say(&mut server, &mut a1, conversation, "uno");
    // Another message waits for the API's answer when the catch-up is made: no catch-up can
    // carry it yet.
    let late = encrypted(&mut a1, conversation, "todavía sin respuesta");
    let mut b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));

    // The late message gets its answer, then the first package is delivered: its message's note
    // goes, the late one's stays, and B is still due.
    let late = post(&mut server, &mut a1, conversation, late);
    ok(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(due(&mut a1, conversation), json!([b]));

    // The same package again, or one this device didn't make, is not found.
    let again = error(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(refusal(&again), json!(["not_found", "share"]));
    let unknown = error(&mut a1.core, delivered(conversation, b, &json!(new_id())));
    assert_eq!(refusal(&unknown), json!(["not_found", "share"]));

    // The next catch-up carries the late message alone; once it's delivered, B is due nothing.
    let next = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from = certificate(&server, a, a1.id);
    assert_eq!(take_package(&mut server, &mut b1, &from, &caught), 1);
    assert_eq!(take_package(&mut server, &mut b1, &from, &next), 1);
    ok(&mut a1.core, delivered(conversation, b, &next["share_id"]));
    assert_eq!(due(&mut a1, conversation), json!([]));
    assert_eq!(ids(&messages_of(&mut b1, conversation)), [late, first]);
}

#[test]
fn a_truncated_catch_up_leaves_the_oldest_for_the_next() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);

    // A1 writes twelve long messages, a second apart, while B has no device.
    let mut written = Vec::new();
    for seed in 0..12 {
        written.push(say(&mut server, &mut a1, conversation, &noise(seed, 1500)));
        server.clock.advance(1000);
    }
    let mut b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let devices = certificate_bytes(&server, b);
    let from = certificate(&server, a, a1.id);

    // Under a smaller cap, the same function's catch-up carries the newest that fit.
    let cut = a1
        .core
        .transaction(|tx| history::catch_up_within(tx, conversation, b, &devices, 6 * 1024))
        .unwrap();
    assert!(cut.truncated);
    let cut = serde_json::to_value(&cut).unwrap();
    let newest = take_package(&mut server, &mut b1, &from, &cut);
    assert!(0 < newest && newest < 12, "{newest} of 12");
    ok(&mut a1.core, delivered(conversation, b, &cut["share_id"]));

    // The oldest stay noted: B is still due, and the next catch-up carries them.
    assert_eq!(due(&mut a1, conversation), json!([b]));
    let rest = a1
        .core
        .transaction(|tx| history::catch_up_within(tx, conversation, b, &devices, MAX_PACKAGE))
        .unwrap();
    assert!(!rest.truncated);
    let rest = serde_json::to_value(&rest).unwrap();
    assert_eq!(
        take_package(&mut server, &mut b1, &from, &rest),
        12 - newest
    );
    ok(&mut a1.core, delivered(conversation, b, &rest["share_id"]));
    assert_eq!(due(&mut a1, conversation), json!([]));

    // B1 has all twelve, in order.
    let mut shown = ids(&messages_of(&mut b1, conversation));
    shown.reverse();
    assert_eq!(shown, written);
}

#[test]
fn package_parts_keep_their_sizes() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    say(&mut server, &mut a1, conversation, "en partes");
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": certificates(&server, b),
        }),
    );
    post_keys(&mut server, &shared);
    let from = certificate(&server, a, a1.id);
    let taken = take_inbox(&mut server, &mut b1, &from);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);

    // The package cut again in parts of other sizes, each sealed in its place under the package's
    // own key (as B1 keeps it), so each would open: B1 refuses them by their sizes.
    let share: Uuid = shared["share_id"].as_str().unwrap().parse().unwrap();
    let key: [u8; 32] = b1
        .rolled_back(|tx| {
            Ok(tx.conn().query_row(
                "SELECT key FROM history_keys WHERE share_id = ?1",
                [share.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )?)
        })
        .try_into()
        .unwrap();
    let parts: Vec<Vec<u8>> = shared["parts"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let last = parts.len() - 1;
    let package: Vec<u8> = parts
        .iter()
        .enumerate()
        .flat_map(|(index, part)| {
            open_part(&key, share, index as u64, index == last, part).unwrap()
        })
        .collect();
    let (head, tail) = package.split_at(package.len() / 2);
    let recut = [
        b64(&seal_part(&key, share, 0, false, head)),
        b64(&seal_part(&key, share, 1, true, tail)),
    ];
    let refused = error(
        &mut b1.core,
        json!({"cmd": "history_import", "share_id": share, "parts": recut}),
    );
    assert_eq!(refusal(&refused), json!(["decrypt_failed", "history"]));

    // As it was cut, it opens.
    ok(&mut b1.core, import(&shared));
}

#[test]
fn parts_over_64_mib_are_too_large() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": certificates(&server, b),
        }),
    );
    post_keys(&mut server, &shared);
    let from = certificate(&server, a, a1.id);
    let taken = take_inbox(&mut server, &mut b1, &from);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);

    // The server hands B1 more than 64 MiB of parts under that package: refused by their size
    // before any opens. 64 MiB itself passes that check, and fails as a part in no place does.
    let parts_of = |len: usize| {
        json!({
            "cmd": "history_import",
            "share_id": shared["share_id"],
            "parts": [b64(&vec![0u8; len])],
        })
    };
    let refused = error(&mut b1.core, parts_of(MAX_PACKAGE + 1));
    assert_eq!(refusal(&refused), json!(["too_large", MAX_PACKAGE]));
    let refused = error(&mut b1.core, parts_of(MAX_PACKAGE));
    assert_eq!(refusal(&refused), json!(["decrypt_failed", "history"]));
}

#[test]
fn a_device_back_after_a_long_absence_asks_before_refusing_a_key() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], _a1) = deviceless_b(&mut server);
    // B's device last observed A while A's list held one device.
    let mut b1 = server.device(b);
    server.introduce(&mut b1);

    // A sets up a second device, which joins the group and writes for B, who has no device there.
    let mut a2 = server.device(a);
    server.publish(&mut a2);
    server.introduce(&mut a2);
    let joining = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    });
    server.commit(&mut a2, conversation, joining).unwrap();
    ok(
        &mut a2.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    let missed = say(&mut server, &mut a2, conversation, "mientras no estabas");

    // B1 comes back and joins, which checks no list: what it knows of A stays as it was.
    let joining = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    });
    server.commit(&mut b1, conversation, joining).unwrap();
    assert_eq!(server.deliver(&mut a2)[0]["catch_up_due"], json!([b]));
    let caught = ok(&mut a2.core, catch_up_command(&server, conversation, b));
    let key = bytes(&caught["keys"][0]["message"]);
    let from = certificate(&server, a, a2.id);

    // B1's list of A doesn't name A2: it asks to observe A, and asks again until it has.
    for _ in 0..2 {
        let asked = error(&mut b1.core, receive_direct(&key, &from));
        assert_eq!(
            (&asked["code"], &asked["users"]),
            (&json!("needs_identities"), &json!([a]))
        );
    }
    ok(&mut b1.core, server.observed(a));
    let taken = ok(&mut b1.core, receive_direct(&key, &from));
    assert_eq!(taken["type"], "catch_up.key");
    assert_eq!(ok(&mut b1.core, import(&caught))["imported"], 1);
    assert_eq!(ids(&messages_of(&mut b1, conversation)), [missed]);
}

/// A package key's payload, as its sender writes it.
fn key_payload(share: Uuid, conversation: Uuid, key: [u8; 32]) -> Vec<u8> {
    use ciborium::Value;
    cbor(&Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(1.into())),
        (
            Value::Text("share".into()),
            Value::Bytes(share.as_bytes().to_vec()),
        ),
        (
            Value::Text("conversation".into()),
            Value::Bytes(conversation.as_bytes().to_vec()),
        ),
        (Value::Text("key".into()), Value::Bytes(key.to_vec())),
    ]))
}

/// `payload` as a package's key from `device` to the device `to`, whose HPKE key is `to_hpke`.
fn key_message(device: &mut TestDevice, to: Uuid, to_hpke: &[u8; 32], payload: &[u8]) -> Vec<u8> {
    device
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let provider = OpenMlsRustCrypto::default();
            DirectMessage::seal(
                &provider,
                &own.signer,
                own.device,
                to,
                to_hpke,
                "history.key",
                payload,
            )
        })
        .unwrap()
}

#[test]
fn a_key_is_refused_without_its_sender_or_against_its_package() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1] = new_devices(&mut server, [a, a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": certificates(&server, b),
        }),
    );
    let key = bytes(&shared["keys"][0]["message"]);
    let a1_certificate = certificate(&server, a, a1.id);

    // Without its sender's certificate; then with A2's, a device on A's list, but not the one the
    // key says sent it.
    let refused = error(
        &mut b1.core,
        json!({"cmd": "receive_direct", "message": b64(&key)}),
    );
    assert_eq!(
        refusal(&refused),
        json!(["bad_command", "from_certificate"])
    );
    let a2_certificate = certificate(&server, a, a2.id);
    let refused = error(&mut b1.core, receive_direct(&key, &a2_certificate));
    assert_eq!(refusal(&refused), json!(["rule_violation", "wrong_device"]));

    // From A1, B1 takes it, and takes it again. Another key A1 signs for the same package, or a
    // payload with a byte after it, it refuses.
    ok(&mut b1.core, receive_direct(&key, &a1_certificate));
    ok(&mut b1.core, receive_direct(&key, &a1_certificate));
    let share: Uuid = shared["share_id"].as_str().unwrap().parse().unwrap();
    let to_b1 = hpke_key(&server, b, b1.id);
    let payload = key_payload(share, conversation, [7; 32]);
    let other = key_message(&mut a1, b1.id, &to_b1, &payload);
    let refused = error(&mut b1.core, receive_direct(&other, &a1_certificate));
    assert_eq!(
        (&refused["code"], &refused["message"]),
        (&json!("exists"), &json!("share exists already"))
    );
    let mut payload = key_payload(new_id(), conversation, [7; 32]);
    payload.push(0);
    let trailed = key_message(&mut a1, b1.id, &to_b1, &payload);
    let refused = error(&mut b1.core, receive_direct(&trailed, &a1_certificate));
    assert_eq!(refusal(&refused), json!(["decrypt_failed", "history"]));
    // The key it took still opens the package.
    ok(&mut b1.core, import(&shared));

    // A key from S, whose identity B1 hasn't observed: it asks to, then takes it.
    let s = new_id();
    let mut s1 = server.device(s);
    server.introduce(&mut s1);
    let devices = certificate_bytes(&server, b);
    let sealed = s1
        .core
        .transaction(|tx| {
            history::seal(
                tx,
                ShareKind::Share,
                conversation,
                b,
                b"a package",
                &devices,
            )
        })
        .unwrap();
    let from_s = certificate(&server, s, s1.id);
    let asked = error(
        &mut b1.core,
        receive_direct(&sealed.keys[0].message, &from_s),
    );
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([s]))
    );
    ok(&mut b1.core, server.observed(s));
    ok(
        &mut b1.core,
        receive_direct(&sealed.keys[0].message, &from_s),
    );
}

#[test]
fn a_package_goes_only_to_devices_its_sender_can_check() {
    let mut server = FakeServer::new();
    let (conversation, [_, b], mut a1) = deviceless_b(&mut server);

    // A1 writes while B has no device. B then sets up two, which A1 hasn't observed, and the API
    // says B has devices now.
    say(&mut server, &mut a1, conversation, "para cuando llegues");
    let mut b1 = server.device(b);
    let b2 = server.device(b);
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": []}),
    );
    let b1_certificate = certificate(&server, b, b1.id);
    let b2_certificate = certificate(&server, b, b2.id);
    // A share and a catch-up for B, sealed to `devices`.
    let packages = |devices: &[&str]| {
        [
            json!({
                "cmd": "history_share",
                "conversation_id": conversation,
                "to_user": b,
                "range": "all",
                "devices": devices,
            }),
            json!({
                "cmd": "catch_up",
                "conversation_id": conversation,
                "user_id": b,
                "devices": devices,
            }),
        ]
    };

    // Neither goes to a device of an identity A1 hasn't observed: it asks to observe B.
    for command in packages(&[b1_certificate.as_str()]) {
        let asked = error(&mut a1.core, command);
        assert_eq!(
            (&asked["code"], &asked["users"]),
            (&json!("needs_identities"), &json!([b]))
        );
    }

    // B2 leaves B's list, and A1 observes B.
    ok(&mut b1.core, server.observed(b));
    let signed = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &signed["device_list"]);
    ok(&mut a1.core, server.observed(b));

    // To no device, or to B1 under two certificates B's identity signed, which give it two keys.
    let identity = b1.rolled_back(|tx| {
        let meta = |key: &str| {
            tx.conn()
                .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
        };
        Ok(SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            meta("identity_secret")?,
            meta("identity_key")?,
        ))
    });
    let signed = bytes(&json!(b1_certificate));
    let signature_key: [u8; 32] = DeviceCertificate::read_unverified(&signed)
        .unwrap()
        .signature_key
        .try_into()
        .unwrap();
    let now = server.clock.now_ms() as u64;
    let rekeyed = DeviceCertificate::new(b, b1.id, signature_key, [5; 32], now)
        .sign(&identity)
        .unwrap();
    let rekeyed = b64(&rekeyed);
    for (devices, message) in [
        (vec![], "a package goes to at least one device"),
        (
            vec![b1_certificate.as_str(), rekeyed.as_str()],
            "a device's certificates give it different keys",
        ),
    ] {
        for command in packages(&devices) {
            let refused = error(&mut a1.core, command);
            assert_eq!(
                (&refused["code"], &refused["field"], &refused["message"]),
                (&json!("bad_command"), &json!("devices"), &json!(message))
            );
        }
    }

    // To a device whose certificate another identity signed, or to B2, no longer on B's list: as
    // what A1 knows of B may be old, it asks to observe B anew first; at the same knowledge, it
    // refuses.
    let forger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let forged = DeviceCertificate::new(
        b,
        new_id(),
        forger.public().try_into().unwrap(),
        [9; 32],
        now,
    )
    .sign(&forger)
    .unwrap();
    for (device, refused) in [
        (b64(&forged), json!(["invalid_signature", "certificate"])),
        (
            b2_certificate,
            json!(["rule_violation", "device_not_listed"]),
        ),
    ] {
        for command in packages(&[device.as_str()]) {
            assert_eq!(error(&mut a1.core, command)["code"], "needs_identities");
        }
        ok(&mut a1.core, server.observed(b));
        for command in packages(&[device.as_str()]) {
            assert_eq!(refusal(&error(&mut a1.core, command)), refused);
        }
    }

    // To B1 alone, both are sealed.
    for command in packages(&[b1_certificate.as_str()]) {
        let sealed = ok(&mut a1.core, command);
        assert_eq!(sealed["keys"][0]["device_id"], json!(b1.id));
    }
}

/// `sharer`'s package of `records` (what deflate gives, or not) for `recipient`'s user, sealed to
/// that user's devices, whose key `recipient` takes: the import of it.
fn package_of(
    server: &mut FakeServer,
    sharer: &mut TestDevice,
    recipient: &mut TestDevice,
    conversation: Uuid,
    records: &[u8],
) -> Value {
    let b = recipient.user;
    let devices = certificate_bytes(server, b);
    let sealed = sharer
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let header = Header {
                kind: ShareKind::Share,
                conversation,
                user: own.user,
                device: own.device,
                to: b,
            };
            let package = history::package(&own.signer, &header, records)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    post_keys(server, &shared);
    let from = certificate(server, sharer.user, sharer.id);
    let taken = take_inbox(server, recipient, &from);
    assert!(taken[0].get("ok").is_some(), "{}", taken[0]);
    import(&shared)
}

#[test]
fn an_import_takes_one_list_of_records_and_nothing_after() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    let record = Record {
        kind: RecordKind::Message,
        id: new_id(),
        seq: 1,
        user: a,
        device: a1.id,
        sent: server.clock.now_ms() as u64,
        envelope: Envelope::Message {
            text: Some("de A".into()),
            attachments: Vec::new(),
        }
        .encode()
        .unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let records = cbor(&vec![record.clone()]);
    let deflate = |bytes: &[u8]| miniz_oxide::deflate::compress_to_vec(bytes, 6);

    // A package of a conversation B1 has no group of.
    let elsewhere = package_of(&mut server, &mut a1, &mut b1, new_id(), &deflate(&records));
    let refused = error(&mut b1.core, elsewhere);
    assert_eq!(refusal(&refused), json!(["not_found", "group"]));

    // The records with a byte after them, or their DEFLATE stream with bytes after it: B1 refuses
    // either whole.
    let mut trailed = records.clone();
    trailed.push(0);
    let mut after = deflate(&records);
    after.extend([0, 1]);
    for stream in [deflate(&trailed), after] {
        let command = package_of(&mut server, &mut a1, &mut b1, conversation, &stream);
        let refused = error(&mut b1.core, command);
        assert_eq!(refusal(&refused), json!(["decrypt_failed", "history"]));
    }
    assert_eq!(messages_of(&mut b1, conversation), Vec::<Value>::new());

    // The records alone, it imports.
    let command = package_of(
        &mut server,
        &mut a1,
        &mut b1,
        conversation,
        &deflate(&records),
    );
    assert_eq!(ok(&mut b1.core, command)["imported"], 1);
    assert_eq!(ids(&messages_of(&mut b1, conversation)), [record.id]);
}

#[test]
fn a_delivery_is_of_one_member_in_one_conversation() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1] = new_devices(&mut server, [a]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "group",
        "owner": a,
        "members": [a, b, c],
        "key_packages": server.claim(&[a]),
        "external_sender": server.external_sender(),
        "legacy": false,
    });
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver(&mut a1);
    let without = |users: &[Uuid]| json!({"cmd": "without_devices", "conversation_id": conversation, "users": users});

    // A1 writes while B and C have no device: the message is noted for each. Then both set up a
    // device, which A1 observes, and the API says they have them now.
    ok(&mut a1.core, without(&[b, c]));
    say(&mut server, &mut a1, conversation, "para los dos");
    server.device(b);
    server.device(c);
    server.introduce(&mut a1);
    ok(&mut a1.core, without(&[]));
    let for_b = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let for_c = ok(&mut a1.core, catch_up_command(&server, conversation, c));

    // B's catch-up, confirmed for C, or in another conversation, is unknown, and forgets nothing.
    for (conversation, user) in [(conversation, c), (new_id(), b)] {
        let refused = error(
            &mut a1.core,
            delivered(conversation, user, &for_b["share_id"]),
        );
        assert_eq!(refusal(&refused), json!(["not_found", "share"]));
    }
    let mut both = [b, c];
    both.sort();
    assert_eq!(due(&mut a1, conversation), json!(both));

    // Confirmed for B, it forgets B's note alone: C stays due, until C's own is confirmed.
    ok(&mut a1.core, delivered(conversation, b, &for_b["share_id"]));
    assert_eq!(due(&mut a1, conversation), json!([c]));
    ok(&mut a1.core, delivered(conversation, c, &for_c["share_id"]));
    assert_eq!(due(&mut a1, conversation), json!([]));
}

#[test]
fn a_delivery_after_the_member_lost_their_devices_forgets_nothing() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);
    let missed = say(&mut server, &mut a1, conversation, "para cuando llegues");
    let _b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));

    // B1 is gone before it takes the key, and the client says so. The package's delivery comes
    // after: it was sealed to a device that's gone, so it forgets nothing.
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    let refused = error(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(refusal(&refused), json!(["not_found", "catch_up"]));

    // B's next device is due the message, and that package can't be delivered any more.
    let mut b2 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    assert_eq!(due(&mut a1, conversation), json!([b]));
    let late = error(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(refusal(&late), json!(["not_found", "share"]));
    let next = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from = certificate(&server, a, a1.id);
    assert_eq!(take_package(&mut server, &mut b2, &from, &next), 1);
    assert_eq!(ids(&messages_of(&mut b2, conversation)), [missed]);
}

#[test]
fn an_edit_from_another_members_share_leaves_the_text() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // A writes, and B1 reads it itself.
    let message = say(&mut server, &mut a1, conversation, "lo que A escribió");
    server.deliver_all(&mut [&mut b1, &mut c1]);

    // C shares B an edit of A's message, as A's, dated after anything A could send.
    let edit = Record {
        kind: RecordKind::Edit,
        id: message,
        seq: 1_000_000,
        user: a,
        device: a1.id,
        sent: i64::MAX as u64,
        envelope: Envelope::Edit {
            message_id: message,
            text: "inventado".into(),
        }
        .encode()
        .unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let deflated = miniz_oxide::deflate::compress_to_vec(&cbor(&vec![edit]), 6);
    let command = package_of(&mut server, &mut c1, &mut b1, conversation, &deflated);
    let imported = ok(&mut b1.core, command)["imported"].clone();

    // B1 shows A's message as it was: an edit counts only from its author's own package.
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(shown[0]["text"], "lo que A escribió");
    assert_eq!(shown[0]["edited_at"], Value::Null);
    assert_eq!(shown[0]["shared_by"], Value::Null);
    assert_eq!(imported, 0);
}

#[test]
fn another_members_edit_under_the_authors_number_keeps_nothing_out() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let (conversation, [mut a1, mut c1]) = group_of(&mut server, [a, c]);

    // A writes and edits it; C sees the edit's number in the queue.
    let message = say(&mut server, &mut a1, conversation, "lo que A escribió");
    let edited = ok(
        &mut a1.core,
        json!({
            "cmd": "edit",
            "conversation_id": conversation,
            "message_id": message,
            "text": "lo que A corrigió",
        }),
    );
    let number = server.post_change(
        &a1,
        conversation,
        "edit",
        message,
        bytes(&edited["ciphertext"]),
    );
    server.deliver_all(&mut [&mut a1, &mut c1]);

    // B comes in after it.
    let mut b1 = server.device(b);
    server.publish(&mut b1);
    server.introduce(&mut b1);
    server.introduce(&mut a1);
    server.introduce(&mut c1);
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // C shares B an edit of A's message in C's own name, under the number of A's edit.
    let forged = Record {
        kind: RecordKind::Edit,
        id: message,
        seq: number,
        user: c,
        device: c1.id,
        sent: server.clock.now_ms() as u64,
        envelope: Envelope::Edit {
            message_id: message,
            text: "lo que C dice".into(),
        }
        .encode()
        .unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let deflated = miniz_oxide::deflate::compress_to_vec(&cbor(&vec![forged]), 6);
    let command = package_of(&mut server, &mut c1, &mut b1, conversation, &deflated);
    ok(&mut b1.core, command);

    // A's share brings the message and A's own edit: B1 shows the edit, whatever C's under its
    // number.
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": certificates(&server, b),
        }),
    );
    let from = certificate(&server, a, a1.id);
    take_package(&mut server, &mut b1, &from, &shared);
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(shown[0]["text"], "lo que A corrigió");
    assert!(shown[0]["edited_at"].is_i64(), "{}", shown[0]);
}

#[test]
fn a_delivery_to_devices_no_longer_listed_forgets_nothing() {
    let mut server = FakeServer::new();
    let (conversation, [a, b], mut a1) = deviceless_b(&mut server);
    let missed = say(&mut server, &mut a1, conversation, "para cuando llegues");
    let b1 = first_device_joins(&mut server, b, conversation);
    server.introduce(&mut a1);
    server.deliver(&mut a1);
    let caught = ok(&mut a1.core, catch_up_command(&server, conversation, b));

    // Before it's delivered, B sets up B2, which enters the group and takes B1 off B's list. A1
    // observes B, as a client does before confirming a delivery, and applies B2's commit.
    let mut b2 = first_device_joins(&mut server, b, conversation);
    let signed = ok(
        &mut b2.core,
        json!({"cmd": "sign_device_list", "remove": [b1.id]}),
    );
    server.take_list(b, &signed["device_list"]);
    ok(&mut a1.core, server.observed(b));
    server.deliver(&mut a1);
    assert_eq!(due(&mut a1, conversation), json!([b]));

    // The package went to B1 alone, which is no longer B's: its delivery forgets nothing.
    let refused = error(
        &mut a1.core,
        delivered(conversation, b, &caught["share_id"]),
    );
    assert_eq!(refusal(&refused), json!(["not_found", "catch_up"]));
    assert_eq!(due(&mut a1, conversation), json!([b]));

    // The next goes to B2, which is listed: its delivery forgets the note, as before.
    let next = ok(&mut a1.core, catch_up_command(&server, conversation, b));
    let from = certificate(&server, a, a1.id);
    assert_eq!(take_package(&mut server, &mut b2, &from, &next), 1);
    ok(&mut a1.core, delivered(conversation, b, &next["share_id"]));
    assert_eq!(due(&mut a1, conversation), json!([]));
    assert_eq!(ids(&messages_of(&mut b2, conversation)), [missed]);
}

fn cbor(value: &impl serde::Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}
