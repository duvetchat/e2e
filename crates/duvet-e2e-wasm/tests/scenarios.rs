//! A part of the end-to-end scenarios in WebAssembly, run under Node by `wasm-pack test --node` on
//! SQLite's in-memory VFS: two users with two devices each converse in a group, whose owner adds a
//! member and removes them, and a witness string sent in a DM reaches none of the server's storage.
//! That part is what the web's worker does most, a group's life from its creation, through the MLS
//! code, the database, and the randomness and clock the JavaScript host supplies. Second devices
//! come by the recovery key, as on the web. The server is the test's own: each conversation's queue,
//! the key packages, the users' identities, lists and certificates, without the validator, whose
//! rules run natively against `FakeServer`, as do the backup, the history and the server's attacks.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use std::cell::Cell;
use std::collections::BTreeMap;

use duvet_e2e::{Core, OpenConfig};
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;

thread_local! {
    static NEXT: Cell<u64> = const { Cell::new(1) };
}

/// A new ID in a v7 UUID's shape, unique in this run: the databases' names too, as the in-memory
/// VFS keeps every file for the whole run.
fn new_id() -> String {
    let next = NEXT.with(|next| {
        let id = next.get();
        next.set(id + 1);
        id
    });
    format!("01930000-0000-7000-8000-{next:012x}")
}

/// Standard base64, as the JSON protocol's binary fields carry it, decoded.
fn bytes(text: &Value) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.as_str().expect("base64 text").bytes() {
        if byte == b'=' {
            break;
        }
        let value = ALPHABET
            .iter()
            .position(|letter| *letter == byte)
            .expect("base64");
        buffer = buffer << 6 | u32::try_from(value).unwrap();
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(buffer >> bits).unwrap());
            buffer &= (1 << bits) - 1;
        }
    }
    out
}

fn run(core: &mut Core, command: &Value) -> Value {
    serde_json::from_str(&core.handle(&command.to_string())).expect("a JSON reply")
}

/// The reply of a command that must succeed.
fn ok(core: &mut Core, command: Value) -> Value {
    let reply = run(core, &command);
    reply
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{} failed: {reply}", command["cmd"]))
}

/// Whether `blob` holds `text`, byte for byte.
fn holds(blob: &[u8], text: &str) -> bool {
    blob.windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// Whether `blob` holds `text`, or inflates to bytes that do: a blob deflated and sent unsealed
/// would hold it there.
fn seen(blob: &[u8], text: &str) -> bool {
    holds(blob, text)
        || miniz_oxide::inflate::decompress_to_vec_with_limit(blob, 1 << 26)
            .is_ok_and(|inflated| holds(&inflated, text))
}

/// A device: a core in a database of its own.
struct Device {
    core: Core,
    user: String,
    id: String,
}

impl Device {
    fn group(&mut self, conversation: &str) -> Value {
        ok(
            &mut self.core,
            json!({"cmd": "group", "conversation_id": conversation}),
        )
    }

    /// The messages of `conversation` as this device shows them, newest first: each one's author
    /// and text.
    fn shown(&mut self, conversation: &str) -> Vec<(Value, Value)> {
        let page = ok(
            &mut self.core,
            json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
        );
        page["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| (message["user_id"].clone(), message["text"].clone()))
            .collect()
    }
}

/// A user as the server knows them: the reply of the identity their first device made (with the
/// blobs a new device recovers with), their latest list and their devices' certificates.
struct User {
    identity: Value,
    list: Value,
    certificates: BTreeMap<String, Value>,
}

/// The server: each conversation's queue in order, and how far each device has taken it; the key
/// packages devices publish; the users; the latest group info of each conversation; and the key it
/// names as every group's external sender.
struct Server {
    users: BTreeMap<String, User>,
    key_packages: BTreeMap<String, Vec<Value>>,
    handed_out: Vec<Value>,
    queues: BTreeMap<String, Vec<Value>>,
    cursors: BTreeMap<(String, String), usize>,
    group_infos: BTreeMap<String, Value>,
    external_sender: Value,
}

impl Server {
    fn new() -> Server {
        // The API's key: an Ed25519 key of its own, as an identity's is.
        let mut api = open(&new_id());
        ok(
            &mut api,
            json!({"cmd": "create_device", "user_id": new_id(), "device_id": new_id()}),
        );
        let external_sender =
            ok(&mut api, json!({"cmd": "create_identity"}))["identity_key"].clone();
        Server {
            users: BTreeMap::new(),
            key_packages: BTreeMap::new(),
            handed_out: Vec::new(),
            queues: BTreeMap::new(),
            cursors: BTreeMap::new(),
            group_infos: BTreeMap::new(),
            external_sender,
        }
    }

    /// A new device of `user`, its key packages published: the user's first makes their identity,
    /// the next ones recover it with the recovery key, and sign themselves into the list.
    fn device(&mut self, user: &str) -> Device {
        let id = new_id();
        let mut core = open(&id);
        ok(
            &mut core,
            json!({"cmd": "create_device", "user_id": user, "device_id": id}),
        );
        match self.users.get_mut(user) {
            None => {
                let identity = ok(&mut core, json!({"cmd": "create_identity"}));
                let record = User {
                    list: identity["device_list"].clone(),
                    certificates: BTreeMap::from([(id.clone(), identity["certificate"].clone())]),
                    identity,
                };
                self.users.insert(user.to_owned(), record);
            }
            Some(record) => {
                let recovered = ok(
                    &mut core,
                    json!({
                        "cmd": "recover",
                        "recovery_key": record.identity["recovery_key"],
                        "wrapped_backup_key": record.identity["wrapped_backup_key"],
                        "encrypted_identity": record.identity["encrypted_identity"],
                        "device_list": record.list,
                    }),
                );
                record.list = recovered["device_list"].clone();
                record
                    .certificates
                    .insert(id.clone(), recovered["certificate"].clone());
            }
        }
        let published = ok(&mut core, json!({"cmd": "key_packages"}));
        self.key_packages.insert(
            id.clone(),
            published["key_packages"].as_array().unwrap().clone(),
        );
        Device {
            core,
            user: user.to_owned(),
            id,
        }
    }

    /// `device` observes every user the server knows, its own included.
    fn introduce(&self, device: &mut Device) {
        for (user, record) in &self.users {
            let certificates: Vec<&Value> = record.certificates.values().collect();
            let seen = ok(
                &mut device.core,
                json!({
                    "cmd": "observe_user",
                    "user_id": user,
                    "identity_key": record.identity["identity_key"],
                    "device_list": record.list,
                    "certificates": certificates,
                }),
            );
            assert_ne!(seen["state"], "rejected", "{seen}");
        }
    }

    /// A single-use key package of each device of `user` but `except`, never handed out before.
    fn claim(&mut self, user: &str, except: &str) -> Vec<Value> {
        let devices: Vec<String> = self.users[user]
            .certificates
            .keys()
            .filter(|device| *device != except)
            .cloned()
            .collect();
        let mut claimed = Vec::new();
        for device in devices {
            let chosen = self.key_packages[&device]
                .iter()
                .find(|kp| kp["last_resort"] == false && !self.handed_out.contains(&kp["data"]))
                .expect("a key package")["data"]
                .clone();
            self.handed_out.push(chosen.clone());
            claimed.push(chosen);
        }
        claimed
    }

    /// The server takes the commit `device` made (`reply`), and its welcome for `added`: the device
    /// hears it taken, and takes the queue after it; the added devices take it from the welcome on.
    fn commit(
        &mut self,
        device: &mut Device,
        conversation: &str,
        reply: &Value,
        added: &[&Device],
    ) {
        let queue = self.queues.entry(conversation.to_owned()).or_default();
        let seq = queue.len() + 1;
        queue.push(json!({"seq": seq, "kind": "commit", "data": reply["commit"]}));
        // Cursors are places in the queue: the entry after the commit is at `seq`.
        if let Some(welcome) = reply.get("welcome").filter(|welcome| welcome.is_string()) {
            queue.push(json!({"seq": seq + 1, "kind": "welcome", "data": welcome}));
            for joining in added {
                self.cursors
                    .insert((conversation.to_owned(), joining.id.clone()), seq);
            }
        }
        self.group_infos
            .insert(conversation.to_owned(), reply["group_info"].clone());
        // The committer takes its own commit back from the queue, after what came before it: a cursor
        // it has stays, and a new one starts at the commit.
        self.cursors
            .entry((conversation.to_owned(), device.id.clone()))
            .or_insert(seq - 1);
        let result = ok(
            &mut device.core,
            json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": seq}),
        );
        assert!(result["epoch"].is_u64());
    }

    /// `device` writes `text` to `conversation`, and hears the API's answer: the message's ID.
    fn say(&mut self, device: &mut Device, conversation: &str, text: &str) -> String {
        let nonce = new_id();
        let encrypted = ok(
            &mut device.core,
            json!({
                "cmd": "encrypt",
                "conversation_id": conversation,
                "nonce": nonce,
                "envelope": {"text": text},
            }),
        );
        let queue = self.queues.get_mut(conversation).unwrap();
        let (message_id, seq) = (new_id(), queue.len() + 1);
        queue.push(json!({
            "seq": seq,
            "kind": "message",
            "data": encrypted["ciphertext"],
            "message_id": message_id,
            "sender_user": device.user,
            "sender_device": device.id,
            "sent_at": 1_000_000 + seq,
        }));
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

    /// `device` applies what each of its conversations' queues has that it hasn't taken yet.
    fn deliver(&mut self, device: &mut Device) {
        for (conversation, queue) in &self.queues {
            let key = (conversation.clone(), device.id.clone());
            let Some(&next) = self.cursors.get(&key) else {
                continue;
            };
            if next == queue.len() {
                continue;
            }
            ok(
                &mut device.core,
                json!({"cmd": "apply", "conversation_id": conversation, "entries": queue[next..]}),
            );
            self.cursors.insert(key, queue.len());
        }
    }

    fn deliver_all(&mut self, devices: &mut [&mut Device]) {
        for device in devices.iter_mut() {
            self.deliver(device);
        }
    }

    /// Every blob the server holds, each with where it holds it.
    fn held(&self) -> Vec<(String, Vec<u8>)> {
        let mut held = Vec::new();
        for (conversation, queue) in &self.queues {
            for entry in queue {
                held.push((
                    format!("{conversation}, entry {}", entry["seq"]),
                    bytes(&entry["data"]),
                ));
            }
        }
        for (conversation, info) in &self.group_infos {
            held.push((format!("{conversation}: group info"), bytes(info)));
        }
        for (device, published) in &self.key_packages {
            for key_package in published {
                held.push((
                    format!("{device}: key package"),
                    bytes(&key_package["data"]),
                ));
            }
        }
        for (user, record) in &self.users {
            for field in ["wrapped_backup_key", "encrypted_identity", "identity_key"] {
                held.push((format!("{user}: {field}"), bytes(&record.identity[field])));
            }
            held.push((format!("{user}: device list"), bytes(&record.list)));
            for (device, certificate) in &record.certificates {
                held.push((
                    format!("{user}: certificate of {device}"),
                    bytes(certificate),
                ));
            }
        }
        held
    }
}

/// A core over a new database in the in-memory VFS.
fn open(name: &str) -> Core {
    Core::open(OpenConfig::new(format!("{name}.db"), [1; 32])).expect("the core opens")
}

/// A and B, two devices each, every device knowing every user; and the server.
fn two_users() -> (Server, [Device; 4]) {
    let mut server = Server::new();
    let (a, b) = (new_id(), new_id());
    let mut devices = [
        server.device(&a),
        server.device(&a),
        server.device(&b),
        server.device(&b),
    ];
    for device in &mut devices {
        server.introduce(device);
    }
    (server, devices)
}

#[wasm_bindgen_test]
fn two_users_converse_and_a_member_comes_and_goes() {
    let (mut server, [mut a1, mut a2, mut b1, mut b2]) = two_users();
    let (a, b) = (a1.user.clone(), b1.user.clone());
    let conversation = new_id();

    // A1 makes A's group with B: every other device on both lists enters by the welcome.
    let created = ok(
        &mut a1.core,
        json!({
            "cmd": "create_group",
            "conversation_id": conversation,
            "kind": "group",
            "owner": a,
            "members": [a, b],
            "key_packages": {a.as_str(): server.claim(&a, &a1.id), b.as_str(): server.claim(&b, "")},
            "external_sender": server.external_sender,
            "legacy": false,
        }),
    );
    assert_eq!(created["skipped_devices"], json!([]));
    server.commit(&mut a1, &conversation, &created, &[&a2, &b1, &b2]);
    server.deliver_all(&mut [&mut a2, &mut b1, &mut b2]);
    let state = a1.group(&conversation);
    for device in [&mut a2, &mut b1, &mut b2] {
        assert_eq!(device.group(&conversation), state);
    }
    assert_eq!(state["devices"].as_array().unwrap().len(), 4);

    // Each device writes, and every one reads all four, its own included.
    let mut written = Vec::new();
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        let text = format!("hola desde {}", device.id);
        server.say(device, &conversation, &text);
        written.push((json!(device.user), json!(text)));
    }
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    written.reverse();
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        assert_eq!(device.shown(&conversation), written);
    }

    // A adds C, whose device enters by the welcome and reads what comes after.
    let c = new_id();
    let mut c1 = server.device(&c);
    for device in [&mut a1, &mut a2, &mut b1, &mut b2, &mut c1] {
        server.introduce(device);
    }
    let added = ok(
        &mut a1.core,
        json!({
            "cmd": "add_members",
            "conversation_id": conversation,
            "users": [{"user_id": c, "key_packages": server.claim(&c, "")}],
        }),
    );
    server.commit(&mut a1, &conversation, &added, &[&c1]);
    server.deliver_all(&mut [&mut a2, &mut b1, &mut b2, &mut c1]);
    let state = c1.group(&conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["members"].as_array().unwrap().len(), 3);
    server.say(&mut b2, &conversation, "bienvenido, C");
    server.deliver(&mut c1);
    assert_eq!(c1.shown(&conversation)[0].1, "bienvenido, C");
    // A1, the owner, takes its own commit back from the queue, and reads on.
    server.deliver(&mut a1);
    assert_eq!(a1.shown(&conversation)[0].1, "bienvenido, C");

    // A removes C: C1 leaves the group, and reads nothing written after.
    let removed = ok(
        &mut a1.core,
        json!({"cmd": "remove_members", "conversation_id": conversation, "users": [c]}),
    );
    server.commit(&mut a1, &conversation, &removed, &[]);
    server.deliver_all(&mut [&mut a2, &mut b1, &mut b2, &mut c1]);
    let out = run(
        &mut c1.core,
        &json!({"cmd": "group", "conversation_id": conversation}),
    );
    assert_eq!(out["error"]["what"], "membership", "{out}");
    server.say(&mut a2, &conversation, "ya sin C");
    server.deliver_all(&mut [&mut b1, &mut c1]);
    assert_eq!(b1.shown(&conversation)[0].1, "ya sin C");
    server.deliver(&mut a1);
    assert_eq!(a1.shown(&conversation)[0].1, "ya sin C");
    assert!(
        c1.shown(&conversation)
            .iter()
            .all(|(_, text)| text != "ya sin C")
    );
    let state = a1.group(&conversation);
    for device in [&mut a2, &mut b1, &mut b2] {
        assert_eq!(device.group(&conversation), state);
    }
    assert_eq!(state["epoch"], 3);
    assert_eq!(state["members"].as_array().unwrap().len(), 2);
}

/// One token, so a search sees it whether a blob holds it as a value or as a word.
const WITNESS: &str = "duvetwitnessword";

#[wasm_bindgen_test]
fn witness_string_never_reaches_the_server() {
    let (mut server, [mut a1, mut a2, mut b1, mut b2]) = two_users();
    let (a, b) = (a1.user.clone(), b1.user.clone());
    let conversation = new_id();
    let created = ok(
        &mut a1.core,
        json!({
            "cmd": "create_group",
            "conversation_id": conversation,
            "kind": "dm",
            "members": [a, b],
            "key_packages": {a.as_str(): server.claim(&a, &a1.id), b.as_str(): server.claim(&b, "")},
            "external_sender": server.external_sender,
            "legacy": false,
        }),
    );
    server.commit(&mut a1, &conversation, &created, &[&a2, &b1, &b2]);
    server.deliver_all(&mut [&mut a2, &mut b1, &mut b2]);

    // A1 writes the witness in the DM, and B2 answers with it: every device reads both.
    let witnessed = format!("el testigo: {WITNESS}");
    server.say(&mut a1, &conversation, &witnessed);
    server.deliver(&mut b2);
    server.say(&mut b2, &conversation, &format!("respondo a {WITNESS}"));
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        let shown = device.shown(&conversation);
        assert_eq!(shown.len(), 2);
        assert!(
            shown
                .iter()
                .all(|(_, text)| holds(text.as_str().unwrap().as_bytes(), WITNESS))
        );
    }

    // None of what the server holds has it in the clear.
    let held = server.held();
    assert!(held.len() > 400, "{} blobs", held.len());
    let found: Vec<&str> = held
        .iter()
        .filter(|(_, blob)| seen(blob, WITNESS))
        .map(|(place, _)| place.as_str())
        .collect();
    assert_eq!(found, Vec::<&str>::new());
    // The search sees through deflate: a deflated copy of the witnessed text is found.
    let deflated = miniz_oxide::deflate::compress_to_vec(witnessed.repeat(10).as_bytes(), 6);
    assert!(seen(&deflated, WITNESS));
}
