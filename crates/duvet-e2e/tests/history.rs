//! Shared history and catch-ups through `Core::handle`, against a fake of the API: a member shares
//! what its device has of a conversation with a newer member, and a sender passes a member whose
//! devices couldn't read what it sent while they had none. Either is one package, signed by the
//! sending device and sealed in parts under a key that goes to each of the recipient's devices by
//! the channel between devices; the recipient takes the key (`receive_direct`), then the package
//! (`history_import`), whose messages show as shared by the sender.

mod support;

use duvet_e2e::history::{self, Header, MAX_PACKAGE, MAX_RECORDS, Range, ShareKind};
use duvet_e2e::messages::Record;
use duvet_e2e::{Clock, DirectMessage};
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
    assert_eq!(imported["imported"], 3);

    // B1 has the week as A1 had it, C's edit included, each message marked as shared by A, and
    // nothing from before the week.
    let shown = messages_of(&mut b1, conversation);
    assert_eq!(ids(&shown), [yesterday, five]);
    assert!(!ids(&shown).contains(&old));
    assert_eq!(shown[0]["user_id"], json!(a));
    assert_eq!(shown[0]["text"], "ayer");
    assert_eq!(shown[1]["user_id"], json!(c));
    assert_eq!(shown[1]["text"], "hace cinco días, editado");
    assert!(shown[1]["edited_at"].is_i64());
    for message in &shown {
        assert_eq!(message["shared_by"], json!(a));
        assert_eq!(message["status"], "ok");
    }

    // The same package again changes nothing.
    assert_eq!(ok(&mut b1.core, import(&shared))["imported"], 0);
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
    post_keys(&mut server, &shared);
    let refused = take_inbox(&mut server, &mut b1, &a2_certificate);
    assert_eq!(
        refusal(&refused[0]["error"]),
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
    let refused = error(
        &mut b1.core,
        receive_direct(&key, &b64(&forged_certificate)),
    );
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
    // The bomb is a DEFLATE stream made by hand: a check that it inflates as meant.
    assert_eq!(
        miniz_oxide::inflate::decompress_to_vec(&bomb(b"xy", 600)).unwrap(),
        [b"xy".as_slice(), &[0; 600]].concat()
    );

    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (conversation, [mut a1, mut b1]) = group_of(&mut server, [a, b]);
    let devices = certificate_bytes(&server, b);

    // A1 signs a package whose records inflate to 300 MiB: one record whose envelope is a byte
    // string of that length, which a CBOR reader would read whole.
    let zeros: u64 = 300 * 1024 * 1024;
    let mut prefix = vec![0x81, 0xA1, 0x68];
    prefix.extend_from_slice(b"envelope");
    prefix.push(0x5B);
    prefix.extend_from_slice(&zeros.to_be_bytes());
    let records = bomb(&prefix, zeros);
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

#[test]
fn catch_up_delivers_what_was_missed() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1] = new_devices(&mut server, [a]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    // A makes the group with B, who has no device yet, as A1's client knows.
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

    // A1 writes twice while B has no device: both are noted for B.
    let first = encrypted(&mut a1, conversation, "para cuando llegues");
    let second = encrypted(&mut a1, conversation, "y esto también");

    // B's first device enters by external commit, and A1's messages reach the API after it,
    // encrypted at the epoch before: B1 can't read them, and shows them as waiting.
    let mut b1 = server.device(b);
    server.introduce(&mut b1);
    let joining = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    });
    server.commit(&mut b1, conversation, joining).unwrap();
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

    // A1 makes it, sealed to B1, and the register empties: B is due nothing more.
    let catch_up = json!({
        "cmd": "catch_up",
        "conversation_id": conversation,
        "user_id": b,
        "devices": certificates(&server, b),
    });
    let caught = ok(&mut a1.core, catch_up.clone());
    assert_eq!(caught["truncated"], false);
    assert_eq!(caught["keys"].as_array().unwrap().len(), 1);
    assert_eq!(caught["keys"][0]["device_id"], json!(b1.id));
    assert_eq!(
        ok(&mut a1.core, apply(conversation, &[]))["catch_up_due"],
        json!([])
    );
    let nothing = error(&mut a1.core, catch_up);
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

fn cbor(value: &impl serde::Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// A raw DEFLATE stream that inflates to `prefix`, then `zeros` zero bytes, in about 13 bits for
/// each 258 of them: one block of fixed Huffman codes, the zeros after the first as copies of the
/// byte before (length 258, distance 1).
fn bomb(prefix: &[u8], zeros: u64) -> Vec<u8> {
    let mut bits = Bits::default();
    bits.put(1, 1); // the last block,
    bits.put(1, 2); // of fixed codes
    for &byte in prefix {
        bits.literal(byte);
    }
    bits.literal(0);
    let mut left = zeros - 1;
    // Length 258 is code 285, 8 bits (11000101); distance 1 is code 0, 5 bits.
    let copy = reversed(0b1100_0101, 8);
    while left >= 258 {
        bits.put(copy, 13);
        left -= 258;
    }
    for _ in 0..left {
        bits.literal(0);
    }
    bits.put(0, 7); // the end of the block: code 256, seven zero bits
    bits.finish()
}

/// Bits as DEFLATE packs them: from each byte's least significant bit on, but Huffman codes from
/// their most significant bit.
#[derive(Default)]
struct Bits {
    out: Vec<u8>,
    acc: u64,
    len: u32,
}

impl Bits {
    fn put(&mut self, value: u64, count: u32) {
        self.acc |= value << self.len;
        self.len += count;
        while self.len >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.len -= 8;
        }
    }

    /// A literal byte in fixed codes: 0 to 143 in 8 bits from 00110000, 144 to 255 in 9 bits
    /// from 110010000.
    fn literal(&mut self, byte: u8) {
        let byte = u64::from(byte);
        if byte <= 143 {
            self.put(reversed(0b0011_0000 + byte, 8), 8);
        } else {
            self.put(reversed(0b1_1001_0000 + byte - 144, 9), 9);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.len > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }
}

/// A Huffman code of `count` bits, its bits in the order DEFLATE packs them.
fn reversed(code: u64, count: u32) -> u64 {
    (0..count).fold(0, |out, bit| out | ((code >> bit) & 1) << (count - 1 - bit))
}
