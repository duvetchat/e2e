//! Each version of the core opens the database the version before it left. `fixtures/db-v1.sqlite`
//! is a device's database as the first version wrote it, migration v1, made once and frozen: from
//! then on the schema changes in migrations v2 and on, and this test, run by every later version,
//! opens it and goes on talking.
//!
//! Beside it, what the test needs that the server would hold: `db-v1-peer.sqlite`, the other device
//! of its conversations, and `db-v1.json`, the entries of each queue the first device hadn't applied
//! yet, each queue's next number, and what the first device showed then. Both databases open with
//! the tests' key, `[1; 32]`. `write_db_v1` made them, and refuses to write them again.
//!
//! Nothing here depends on the date it runs. The core's clock is set to a minute after the fixtures
//! were made. OpenMLS checks lifetimes against the system's clock, but only a key package's (as a
//! device joins or is added) and the one a leaf keeps from its key package: every leaf in the
//! fixtures' groups is one a commit brought, which has none (`write_db_v1` checks it), and the test
//! joins no group and adds no one. It applies messages and commits, and sends them.

mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use duvet_e2e::{Clock, Core, FakeClock, OpenConfig};
use duvet_e2e_rules::{Kind, group_id};
use openmls::prelude::{MlsGroup, OpenMlsProvider};
use openmls::treesync::LeafNodeSource;
use serde_json::{Value, json};
use support::*;
use uuid::Uuid;

/// The key both databases open with: every test database's.
const KEY: [u8; 32] = [1; 32];

const MINUTE: i64 = 60 * 1000;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// IDs the fixtures don't hold: support's `new_id` starts over in each test binary, and made theirs.
fn fresh_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0015_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

/// The messages `core` shows of `conversation`: each one's ID and text.
fn shown(core: &mut Core, conversation: Uuid) -> Vec<Value> {
    let page = ok(
        core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
    );
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| json!([message["message_id"], message["text"]]))
        .collect()
}

fn texts(core: &mut Core, conversation: Uuid) -> Vec<Value> {
    shown(core, conversation)
        .into_iter()
        .map(|message| message[1].clone())
        .collect()
}

/// A conversation's queue from where the fixtures leave it: the entries A1 hadn't applied, then
/// what the devices post here, and the number each device applies from.
struct Queue {
    conversation: Uuid,
    entries: Vec<Value>,
    next: u64,
    a1: u64,
    b1: u64,
}

impl Queue {
    fn of(fixture: &Value) -> Queue {
        let entries = fixture["pending"].as_array().unwrap().clone();
        let next = fixture["next"].as_u64().unwrap();
        Queue {
            conversation: fixture["id"].as_str().unwrap().parse().unwrap(),
            a1: entries
                .first()
                .map_or(next, |entry| entry["seq"].as_u64().unwrap()),
            b1: next,
            entries,
            next,
        }
    }

    /// The server takes an entry of `kind` holding `data`, with the API's `fields`: its number.
    fn post(&mut self, kind: &str, data: &[u8], fields: Value) -> u64 {
        let seq = self.next;
        let mut entry = json!({"seq": seq, "kind": kind, "data": b64(data)});
        for (field, value) in fields.as_object().unwrap() {
            entry[field] = value.clone();
        }
        self.entries.push(entry);
        self.next += 1;
        seq
    }

    /// The device that applies from `from` (A1's or B1's number) applies what it hasn't yet: each
    /// entry's result.
    fn deliver(&self, core: &mut Core, from: &mut u64) -> Vec<Value> {
        let entries: Vec<&Value> = self
            .entries
            .iter()
            .filter(|entry| entry["seq"].as_u64().unwrap() >= *from)
            .collect();
        let reply = ok(
            core,
            json!({"cmd": "apply", "conversation_id": self.conversation, "entries": entries}),
        );
        *from = self.next;
        reply["results"].as_array().unwrap().clone()
    }

    /// `core`, the device `device` of `user`, sends `text`, and hears the server took it.
    fn send(&mut self, core: &mut Core, user: Uuid, device: Uuid, text: &str, now: i64) {
        let nonce = fresh_id().to_string();
        let encrypted = ok(
            core,
            json!({
                "cmd": "encrypt",
                "conversation_id": self.conversation,
                "nonce": nonce,
                "envelope": {"text": text},
            }),
        );
        let message_id = fresh_id();
        let fields = json!({
            "message_id": message_id,
            "sender_user": user,
            "sender_device": device,
            "sent_at": now,
        });
        let seq = self.post("message", &bytes(&encrypted["ciphertext"]), fields);
        ok(
            core,
            json!({
                "cmd": "sent",
                "conversation_id": self.conversation,
                "nonce": nonce,
                "message_id": message_id,
                "seq": seq,
            }),
        );
    }
}

#[test]
fn opens_the_previous_version_db() {
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(fixtures().join("db-v1.json")).unwrap())
            .unwrap();
    let id = |value: &Value| -> Uuid { value.as_str().unwrap().parse().unwrap() };
    let (a, a1_id) = (id(&fixture["a"]["user"]), id(&fixture["a"]["device"]));
    let (b, b1_id) = (id(&fixture["b"]["user"]), id(&fixture["b"]["device"]));
    let clock = FakeClock::at(fixture["made"].as_i64().unwrap() + MINUTE);
    // Copies: opening the fixtures in place would migrate them, in a later version.
    let dir = tempfile::tempdir().unwrap();
    let open = |name: &str| {
        let path = dir.path().join(name);
        std::fs::copy(fixtures().join(name), &path).unwrap();
        Core::open(OpenConfig {
            clock: Box::new(clock.clone()),
            ..OpenConfig::new(path, KEY)
        })
        .unwrap()
    };
    let (mut a1, mut b1) = (open("db-v1.sqlite"), open("db-v1-peer.sqlite"));

    // Each device is who it was.
    for (core, user, device) in [(&mut a1, a, a1_id), (&mut b1, b, b1_id)] {
        let status = ok(core, json!({"cmd": "status"}));
        assert_eq!(status["user_id"], json!(user));
        assert_eq!(status["device_id"], json!(device));
        assert_eq!(status["has_identity"], true);
    }

    for conversation in fixture["conversations"].as_array().unwrap() {
        let mut queue = Queue::of(conversation);
        let id = queue.conversation;
        // What A1 showed is still there, and its search finds it.
        assert_eq!(json!(shown(&mut a1, id)), conversation["shown"]);
        let word = conversation["word"].as_str().unwrap();
        let found = ok(
            &mut a1,
            json!({"cmd": "search", "text": word, "conversation_id": id, "limit": 10, "offset": 0}),
        );
        assert_eq!(found["total"], 1, "{word}: {found}");

        // A1 applies what B1 sent while it was away: messages, and B1's renewed leaf in the group.
        let (mut a1_from, mut b1_from) = (queue.a1, queue.b1);
        let results = queue.deliver(&mut a1, &mut a1_from);
        assert!(!results.is_empty());
        for result in &results {
            assert_eq!(result["result"], "applied", "{result}");
        }
        let missed = conversation["missed"].as_str().unwrap();
        assert!(texts(&mut a1, id).contains(&json!(missed)), "{missed}");

        // And they go on: A1 renews its leaf, then each writes and reads the other.
        let committed = ok(&mut a1, json!({"cmd": "refresh", "conversation_id": id}));
        let seq = queue.post("commit", &bytes(&committed["commit"]), json!({}));
        ok(
            &mut a1,
            json!({"cmd": "commit_result", "conversation_id": id, "accepted": true, "seq": seq}),
        );
        for result in queue.deliver(&mut b1, &mut b1_from) {
            assert_eq!(result["result"], "applied", "{result}");
        }
        let [state_a, state_b] =
            [&mut a1, &mut b1].map(|core| ok(core, json!({"cmd": "group", "conversation_id": id})));
        for field in ["generation", "epoch", "members", "devices", "authenticator"] {
            assert_eq!(state_a[field], state_b[field], "{field}");
        }

        queue.send(&mut a1, a, a1_id, "back again", clock.now_ms());
        queue.deliver(&mut b1, &mut b1_from);
        assert!(texts(&mut b1, id).contains(&json!("back again")));
        queue.send(&mut b1, b, b1_id, "welcome back", clock.now_ms());
        queue.deliver(&mut a1, &mut a1_from);
        assert!(texts(&mut a1, id).contains(&json!("welcome back")));
    }
}

/// Makes the fixtures, once, with the core of migration v1. Run again, a later core would write
/// its own version's databases: it refuses to overwrite them.
#[test]
#[ignore = "made db-v1's fixtures once: they're frozen"]
fn write_db_v1() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, mut b1) = (server.device(a), server.device(b));
    server.publish(&mut a1);
    server.publish(&mut b1);
    server.introduce(&mut a1);
    server.introduce(&mut b1);
    let (dm, group) = (new_id(), new_id());
    server.conversation(dm, Kind::Dm, None, &[a, b], false);
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    for conversation in [dm, group] {
        let create = server.create_group(conversation);
        server.commit(&mut a1, conversation, create).unwrap();
        server.deliver_all(&mut [&mut a1, &mut b1]);
        // Each device renews its leaf, so none keeps its key package's lifetime.
        refresh(&mut server, &mut b1, conversation);
        server.deliver_all(&mut [&mut a1, &mut b1]);
        refresh(&mut server, &mut a1, conversation);
        server.deliver_all(&mut [&mut a1, &mut b1]);
    }

    // Messages both ways: one edited, one deleted, one with a file, one mentioning A.
    let hello = send(&mut server, &mut a1, dm, json!({"text": "hello"}), &[]);
    send(&mut server, &mut b1, dm, json!({"text": "hi there"}), &[]);
    let edit = Some("hello, how are you?");
    change(&mut server, &mut a1, dm, "edit", hello, edit);
    let oops = send(&mut server, &mut b1, dm, json!({"text": "oops"}), &[]);
    change(&mut server, &mut b1, dm, "delete", oops, None);
    let file = json!({
        "id": new_id(),
        "key": b64(&[7; 32]),
        "sha256": b64(&[8; 32]),
        "name": "plan.pdf",
        "type": "application/pdf",
        "size": 48_213,
    });
    let plan = json!({"text": "the plan", "attachments": [file]});
    send(&mut server, &mut a1, group, plan, &[]);
    send(
        &mut server,
        &mut b1,
        group,
        json!({"text": "looks good"}),
        &[a],
    );
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A1 goes quiet: B1 writes in both, and renews its leaf in the group, and A1 hears none of it.
    let applied = [dm, group].map(|conversation| server.chats[&conversation].queue.len());
    let shown_then = [dm, group].map(|conversation| shown(&mut a1.core, conversation));
    send(
        &mut server,
        &mut b1,
        dm,
        json!({"text": "are you there?"}),
        &[],
    );
    refresh(&mut server, &mut b1, group);
    let ping = json!({"text": "ping after my renewal"});
    send(&mut server, &mut b1, group, ping, &[a]);
    server.deliver(&mut b1);

    // No leaf keeps a key package's lifetime, on either device: each one a commit brought.
    for device in [&mut a1, &mut b1] {
        for conversation in [dm, group] {
            let generation = device.group(conversation)["generation"].as_u64().unwrap();
            let id = group_id(conversation, generation as u32);
            device.rolled_back(|tx| {
                let group = MlsGroup::load(tx.provider().storage(), &id)
                    .unwrap()
                    .unwrap();
                for member in group.members() {
                    let leaf = group.public_group().leaf(member.index).unwrap();
                    assert!(matches!(leaf.leaf_node_source(), LeafNodeSource::Commit(_)));
                }
                Ok(())
            });
        }
    }

    let conversation = |id: Uuid, at: usize, shown: &[Value], word: &str, missed: &str| {
        json!({
            "id": id,
            "pending": server.entries(id)[applied[at]..],
            "next": server.chats[&id].queue.len() + 1,
            "shown": shown,
            "word": word,
            "missed": missed,
        })
    };
    let fixture = json!({
        "made": server.clock.now_ms(),
        "a": {"user": a, "device": a1.id},
        "b": {"user": b, "device": b1.id},
        "conversations": [
            conversation(dm, 0, &shown_then[0], "how", "are you there?"),
            conversation(group, 1, &shown_then[1], "plan", "ping after my renewal"),
        ],
    });
    std::fs::create_dir_all(fixtures()).unwrap();
    let write = |name: &str, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixtures().join(name))
            .expect("a fixture not written yet: they're frozen");
        std::io::Write::write_all(&mut file, bytes).unwrap();
    };
    write("db-v1.sqlite", &std::fs::read(a1.db_path()).unwrap());
    write("db-v1-peer.sqlite", &std::fs::read(b1.db_path()).unwrap());
    let json = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    write("db-v1.json", json.as_bytes());
}

fn refresh(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid) {
    let command = json!({"cmd": "refresh", "conversation_id": conversation});
    server.commit(device, conversation, command).unwrap();
}

/// `device` sends `envelope` in `conversation`, mentioning `mentions`, and hears the server took
/// it: the message's ID.
fn send(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    envelope: Value,
    mentions: &[Uuid],
) -> Uuid {
    let nonce = new_id().to_string();
    let encrypted = ok(
        &mut device.core,
        json!({
            "cmd": "encrypt",
            "conversation_id": conversation,
            "nonce": nonce,
            "envelope": envelope,
        }),
    );
    let ciphertext = bytes(&encrypted["ciphertext"]);
    let (message_id, seq) = server.post_message(device, conversation, &nonce, ciphertext, mentions);
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

/// `device` edits (`edit`, with `text`) or deletes (`delete`) its message `message_id`.
fn change(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    kind: &'static str,
    message_id: Uuid,
    text: Option<&str>,
) {
    let mut command =
        json!({"cmd": kind, "conversation_id": conversation, "message_id": message_id});
    if let Some(text) = text {
        command["text"] = json!(text);
    }
    let changed = ok(&mut device.core, command);
    let ciphertext = bytes(&changed["ciphertext"]);
    server.post_change(device, conversation, kind, message_id, ciphertext);
}
