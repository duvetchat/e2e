//! Each version of the core opens the databases the versions before it left. `fixtures/db-vN.*` are
//! a device's database as the core of schema version N wrote it, made once and frozen. A migration
//! vN ships its own `db-vN.*`, written by its own core (`write_db`, which names them by the schema it
//! writes), and this test opens every version's fixtures there are, then goes on talking.
//!
//! Each version's fixtures are three files: `db-vN.sqlite`, device A1's database; `db-vN-peer.sqlite`,
//! B1's, the other device of its conversations; and `db-vN.json`, what the server held for them.
//! Both databases open with the tests' key, `[1; 32]`. They hold what a migration must carry, in
//! flight: in A1's, its own message encrypted and not yet `sent`, its own commit waiting for its
//! `commit_result`, a waiting message, a member noted as without devices, backup days uploaded and
//! due, an approval under way, and its queues half applied; in B1's, a kept proposal and a share's
//! key not yet imported. From schema 3 on, both hold a device their group took out, and an identity
//! it no longer takes there. The test checks each survives the open and, where a command completes
//! it, completes.
//!
//! Nothing here depends on the date it runs. The core's clock is set to a minute after the fixtures
//! were made. OpenMLS checks lifetimes against the system's clock, but only a key package's (as a
//! device joins or is added) and the one a leaf keeps from its key package: every leaf in the
//! fixtures' groups is one a commit brought, which has none (`write_db` checks it), and the test
//! joins no group and adds no one.

mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use duvet_e2e::{Clock, Core, FakeClock, OpenConfig};
use duvet_e2e_rules::{DeviceCertificate, Kind, group_id};
use openmls::prelude::{BasicCredential, MlsGroup, OpenMlsProvider, Proposal, Sender};
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

fn id(value: &Value) -> Uuid {
    value.as_str().unwrap().parse().unwrap()
}

/// The messages `core` shows of `conversation`: each one's ID and text.
fn shown(core: &mut Core, conversation: Uuid) -> Vec<Value> {
    messages(core, conversation)
        .iter()
        .map(|message| json!([message["message_id"], message["text"]]))
        .collect()
}

fn messages(core: &mut Core, conversation: Uuid) -> Vec<Value> {
    let page = ok(
        core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
    );
    page["messages"].as_array().unwrap().clone()
}

/// The proposals `core` holds in `conversation`'s group: whether each is the server's (the group's
/// external sender), and the user and device of the leaf it removes, if it's a removal.
fn pending(core: &mut Core, conversation: Uuid) -> Vec<(bool, Option<(Uuid, Uuid)>)> {
    let group = ok(
        core,
        json!({"cmd": "group", "conversation_id": conversation}),
    );
    let id = group_id(conversation, group["generation"].as_u64().unwrap() as u32);
    core.transaction(|tx| {
        let group = MlsGroup::load(tx.provider().storage(), &id)
            .unwrap()
            .unwrap();
        let removed = |proposal: &Proposal| {
            let Proposal::Remove(remove) = proposal else {
                return None;
            };
            let leaf = group.public_group().leaf(remove.removed()).unwrap();
            let credential = BasicCredential::try_from(leaf.credential().clone()).unwrap();
            let certificate = DeviceCertificate::read_unverified(credential.identity()).unwrap();
            Some((certificate.user, certificate.device))
        };
        Ok(group
            .pending_proposals()
            .map(|queued| {
                let external = matches!(queued.sender(), Sender::External(_));
                (external, removed(queued.proposal()))
            })
            .collect())
    })
    .unwrap()
}

fn texts(core: &mut Core, conversation: Uuid) -> Vec<Value> {
    messages(core, conversation)
        .into_iter()
        .map(|message| message["text"].clone())
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
            conversation: id(&fixture["id"]),
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

    /// The device that applies from `from` applies what it hasn't yet: each entry's result, which
    /// must be one taken: applied, or the device's own.
    fn deliver(&self, core: &mut Core, from: &mut u64) {
        let entries: Vec<&Value> = self
            .entries
            .iter()
            .filter(|entry| entry["seq"].as_u64().unwrap() >= *from)
            .collect();
        let reply = ok(
            core,
            json!({"cmd": "apply", "conversation_id": self.conversation, "entries": entries}),
        );
        for result in reply["results"].as_array().unwrap() {
            let taken = ["applied", "own"].contains(&result["result"].as_str().unwrap());
            assert!(taken, "{result}");
        }
        *from = self.next;
    }

    /// `core` commits its pending change (`command`'s commit), and the server takes it.
    fn commit(&mut self, core: &mut Core, command: Value) {
        let committed = ok(core, command);
        let seq = self.post("commit", &bytes(&committed["commit"]), json!({}));
        let accepted = json!({
            "cmd": "commit_result",
            "conversation_id": self.conversation,
            "accepted": true,
            "seq": seq,
        });
        ok(core, accepted);
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
    let mut versions: Vec<PathBuf> = std::fs::read_dir(fixtures())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect();
    versions.sort();
    assert!(!versions.is_empty(), "no fixtures");
    for version in versions {
        let name = version.file_stem().unwrap().to_str().unwrap().to_owned();
        opens(
            &name,
            &serde_json::from_str(&std::fs::read_to_string(&version).unwrap()).unwrap(),
        );
    }
}

/// Opens the fixtures of `name` (`db-vN`), which `fixture` describes, and goes on with them.
fn opens(name: &str, fixture: &Value) {
    let (a, a1_id) = (id(&fixture["a"]["user"]), id(&fixture["a"]["device"]));
    let (b, b1_id) = (id(&fixture["b"]["user"]), id(&fixture["b"]["device"]));
    let clock = FakeClock::at(fixture["made"].as_i64().unwrap() + MINUTE);
    // Copies: opening the fixtures in place would migrate them, in a later version.
    let dir = tempfile::tempdir().unwrap();
    let open = |file: &str| {
        let path = dir.path().join(file);
        std::fs::copy(fixtures().join(file), &path).unwrap();
        Core::open(OpenConfig {
            clock: Box::new(clock.clone()),
            ..OpenConfig::new(path, KEY)
        })
        .unwrap()
    };
    let mut a1 = open(&format!("{name}.sqlite"));
    let mut b1 = open(&format!("{name}-peer.sqlite"));

    // Each device is who it was, and A1 shows what it showed, the waiting message among it.
    for (core, user, device) in [(&mut a1, a, a1_id), (&mut b1, b, b1_id)] {
        let status = ok(core, json!({"cmd": "status"}));
        assert_eq!(status["user_id"], json!(user), "{name}");
        assert_eq!(status["device_id"], json!(device), "{name}");
        assert_eq!(status["has_identity"], true, "{name}");
    }
    // From schema 3 on, each database holds a device its group took out, and an identity it no
    // longer takes there, for the migrations after it to carry.
    let schema: u32 = name.trim_start_matches("db-v").parse().unwrap();
    if schema >= 3 {
        for core in [&mut a1, &mut b1] {
            for table in ["removed_devices", "removed_identities"] {
                let rows: i64 = core
                    .transaction(|tx| {
                        Ok(tx.conn().query_row(
                            &format!("SELECT count(*) FROM {table}"),
                            [],
                            |row| row.get(0),
                        )?)
                    })
                    .unwrap();
                assert!(rows > 0, "{name}: no row in {table}");
            }
        }
    }
    let conversations = fixture["conversations"].as_array().unwrap();
    for conversation in conversations {
        let id = id(&conversation["id"]);
        assert_eq!(json!(shown(&mut a1, id)), conversation["shown"], "{name}");
        let word = conversation["word"].as_str().unwrap();
        let found = ok(
            &mut a1,
            json!({"cmd": "search", "text": word, "conversation_id": id, "limit": 10, "offset": 0}),
        );
        assert_eq!(found["total"], 1, "{name}: {word}: {found}");
    }
    let waiting = &fixture["waiting"];
    let held = messages(&mut a1, id(&waiting["conversation"]));
    let kept = held
        .iter()
        .find(|message| message["message_id"] == waiting["message_id"]);
    assert_eq!(
        kept.map(|message| &message["status"]),
        Some(&json!("waiting"))
    );

    // The backup days due are the ones that were, and each goes up.
    let due = ok(&mut a1, json!({"cmd": "backup_due"}))["segments"].clone();
    assert_eq!(due, fixture["backup_due"], "{name}");
    for day in due.as_array().unwrap() {
        let (conversation, day) = (&day["conversation_id"], &day["day"]);
        let built = ok(
            &mut a1,
            json!({"cmd": "backup_segment", "conversation_id": conversation, "day": day}),
        );
        let uploaded = json!({
            "cmd": "backup_uploaded",
            "conversation_id": conversation,
            "day": day,
            "complete": built["complete"],
            "version": built["version"],
        });
        ok(&mut a1, uploaded);
    }
    assert_eq!(
        ok(&mut a1, json!({"cmd": "backup_due"}))["segments"],
        json!([])
    );

    // The approval under way ends: A1 checks the new device's reveal, and confirms its code.
    let checked = ok(
        &mut a1,
        json!({"cmd": "approval_check", "reveal": fixture["approval"]["reveal"]}),
    );
    let confirmed = ok(
        &mut a1,
        json!({"cmd": "approval_confirm", "code": checked["code"]}),
    );
    assert!(confirmed["transfer"].is_string(), "{name}");

    // The member A1 noted as without devices has one again: A1 catches them up.
    let deviceless = &fixture["deviceless"];
    let conversation = &deviceless["conversation"];
    ok(
        &mut a1,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": []}),
    );
    let caught_up = ok(
        &mut a1,
        json!({
            "cmd": "catch_up",
            "conversation_id": conversation,
            "user_id": deviceless["user"],
            "devices": [fixture["b"]["certificate"]],
        }),
    );
    let delivered = json!({
        "cmd": "catch_up_delivered",
        "conversation_id": conversation,
        "user_id": deviceless["user"],
        "share_id": caught_up["share_id"],
    });
    ok(&mut a1, delivered);

    // B1 imports the share whose key it took, which uses the key up.
    let share = &fixture["share"];
    let import =
        json!({"cmd": "history_import", "share_id": share["share_id"], "parts": share["parts"]});
    ok(&mut b1, import.clone());
    let used = error(&mut b1, import);
    assert_eq!(used["code"], "not_found", "{name}: {used}");

    // A1 hears the answers it never heard: its message was sent, and its commit taken.
    let outbox = &fixture["outbox"];
    let sent = json!({
        "cmd": "sent",
        "conversation_id": outbox["conversation"],
        "nonce": outbox["nonce"],
        "message_id": outbox["message_id"],
        "seq": outbox["seq"],
    });
    ok(&mut a1, sent);
    let commit = &fixture["commit"];
    let answer = json!({
        "cmd": "commit_result",
        "conversation_id": commit["conversation"],
        "accepted": true,
        "seq": commit["seq"],
    });
    ok(&mut a1, answer);

    for conversation in conversations {
        let mut queue = Queue::of(conversation);
        let id = queue.conversation;
        let (mut a1_from, mut b1_from) = (queue.a1, queue.b1);
        // A1 applies what came while it was away: its own message and commit among them.
        queue.deliver(&mut a1, &mut a1_from);
        let missed = conversation["missed"].as_str().unwrap();
        assert!(
            texts(&mut a1, id).contains(&json!(missed)),
            "{name}: {missed}"
        );

        // B1 still holds the removal it kept, the server's, of B's other device, and commits it.
        // Checked as such: without it, B1's commit would still take that leaf out, as one of
        // B's own off B's list, once B1 had looked its own user up again (`needs_identities`).
        if fixture["proposal"]["conversation"] == json!(id) {
            let kept = pending(&mut b1, id);
            assert!(
                matches!(kept[..], [(true, Some((user, device)))] if user == b && device != b1_id),
                "{name}: B1 holds {kept:?}, not the server's removal of B's other device"
            );
            queue.commit(
                &mut b1,
                json!({"cmd": "commit_pending", "conversation_id": id}),
            );
            queue.deliver(&mut b1, &mut b1_from);
            queue.deliver(&mut a1, &mut a1_from);
        }

        // And they go on: A1 renews its leaf, then each writes and reads the other.
        queue.commit(&mut a1, json!({"cmd": "refresh", "conversation_id": id}));
        queue.deliver(&mut a1, &mut a1_from);
        queue.deliver(&mut b1, &mut b1_from);
        let [state_a, state_b] =
            [&mut a1, &mut b1].map(|core| ok(core, json!({"cmd": "group", "conversation_id": id})));
        for field in ["generation", "epoch", "members", "devices", "authenticator"] {
            assert_eq!(state_a[field], state_b[field], "{name}: {field}");
        }
        queue.send(&mut a1, a, a1_id, "back again", clock.now_ms());
        queue.deliver(&mut b1, &mut b1_from);
        assert!(texts(&mut b1, id).contains(&json!("back again")), "{name}");
        queue.send(&mut b1, b, b1_id, "welcome back", clock.now_ms());
        queue.deliver(&mut a1, &mut a1_from);
        assert!(
            texts(&mut a1, id).contains(&json!("welcome back")),
            "{name}"
        );
    }
}

/// Makes the fixtures of the schema this core writes, `db-vN.*`, once: they're frozen, and it refuses
/// to overwrite them.
#[test]
#[ignore = "made this schema's fixtures once: they're frozen"]
fn write_db() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, mut b1) = (server.device(a), server.device(b));
    server.publish(&mut a1);
    server.publish(&mut b1);
    server.introduce(&mut a1);
    server.introduce(&mut b1);
    let (dm, group) = (new_id(), new_id());
    server.conversation(dm, Kind::Dm, None, &[a, b], false);
    let create = server.create_group(dm);
    server.commit(&mut a1, dm, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    // Each device renews its leaf, so none keeps its key package's lifetime.
    refresh(&mut server, &mut b1, dm);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    refresh(&mut server, &mut a1, dm);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B's second device, in the group alone, which B takes off its list later; and E, a third
    // member of the group, which loses its second device there.
    let mut b2 = server.device(b);
    server.publish(&mut b2);
    let e = new_id();
    let (mut e1, mut e2) = (server.device(e), server.device(e));
    server.publish(&mut e1);
    server.publish(&mut e2);
    for device in [&mut a1, &mut b1, &mut b2, &mut e1, &mut e2] {
        server.introduce(device);
    }
    server.conversation(group, Kind::Group, Some(a), &[a, b, e], false);
    let create = server.create_group(group);
    server.commit(&mut a1, group, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);
    refresh(&mut server, &mut b2, group);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);
    refresh(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);
    refresh(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);

    // A's second device joins the group, and A takes it off its list: A1 takes it out, so both
    // databases hold a device the group took out (schema 3).
    let mut a2 = server.device(a);
    for device in [&mut a1, &mut b1, &mut b2, &mut e1, &mut a2] {
        server.introduce(device);
    }
    let join = json!({
        "cmd": "join_external",
        "conversation_id": group,
        "generation": 0,
        "group_info": server.group_info(group),
    });
    server.commit(&mut a2, group, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);
    let list = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &list["device_list"]);
    for device in [&mut a1, &mut b1, &mut b2, &mut e1] {
        server.introduce(device);
    }
    take_out_pending(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut e1]);
    for device in [&mut a1, &mut b1] {
        assert!(!devices(&device.group(group)).contains(&a2.id));
    }

    // E changes its keys without E2, which it lost, and E1 takes E2 out once A1 and B1 see E's new
    // identity: both note the identity that certified E2's leaf, which they take there no more.
    let rotated = ok(
        &mut e1.core,
        json!({"cmd": "rotate_keys", "remove": [e2.id]}),
    );
    server.take_identity(e, &rotated);
    ok(&mut e1.core, json!({"cmd": "identity_uploaded"}));
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    take_out_pending(&mut server, &mut e1, group);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    for device in [&mut a1, &mut b1] {
        assert!(!devices(&device.group(group)).contains(&e2.id));
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
    let good = json!({"text": "looks good"});
    send(&mut server, &mut b1, group, good, &[a]);
    // A message too large to read, which both keep waiting.
    let waiting = new_id();
    let chat = server.chats.get_mut(&dm).unwrap();
    let mut meta = serde_json::Map::new();
    meta.insert("message_id".into(), json!(waiting));
    meta.insert("sender_user".into(), json!(b));
    meta.insert("sender_device".into(), json!(b1.id));
    meta.insert("sent_at".into(), json!(server.clock.now_ms()));
    chat.queue.push(QueueEntry {
        seq: chat.queue.len() as u64 + 1,
        kind: "message",
        data: vec![0x55; 33 * 1024],
        statement: None,
        meta,
    });
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // A day later (by the core's clock, never moved back: key packages are live from the system's
    // time on), the first day is due for backup, and A1 uploads the DM's.
    server.clock.advance(DAY_MS);
    let due = ok(&mut a1.core, json!({"cmd": "backup_due"}))["segments"].clone();
    let day = due
        .as_array()
        .unwrap()
        .iter()
        .find(|day| day["conversation_id"] == json!(dm))
        .unwrap()["day"]
        .clone();
    let built = ok(
        &mut a1.core,
        json!({"cmd": "backup_segment", "conversation_id": dm, "day": day}),
    );
    let uploaded = json!({
        "cmd": "backup_uploaded",
        "conversation_id": dm,
        "day": day,
        "complete": built["complete"],
        "version": built["version"],
    });
    ok(&mut a1.core, uploaded);

    // A1 takes B as without devices in the group: its next message there is noted for B.
    let without = json!({"cmd": "without_devices", "conversation_id": group, "users": [b]});
    ok(&mut a1.core, without);
    send(
        &mut server,
        &mut a1,
        group,
        json!({"text": "for later"}),
        &[],
    );
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // A new device of A's, whose approval A1 has under way.
    let mut a2 = server.bare_device(a);
    let begun = ok(&mut a2.core, json!({"cmd": "approval_begin"}));
    let offered = ok(
        &mut a1.core,
        json!({"cmd": "approval_offer", "commitment": begun["commitment"]}),
    );
    let revealed = ok(
        &mut a2.core,
        json!({"cmd": "approval_reveal", "offer": offered["offer"]}),
    );

    // A1's share of the DM for B, whose key B1 takes and doesn't use yet.
    let devices: Vec<String> = certificates(&server, b).iter().map(|c| b64(c)).collect();
    let shared = ok(
        &mut a1.core,
        json!({"cmd": "history_share", "conversation_id": dm, "to_user": b, "range": "all", "devices": devices}),
    );
    let key = shared["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|key| key["device_id"] == json!(b1.id))
        .unwrap();
    let from = certificate(&server, a, a1.id);
    let taken =
        json!({"cmd": "receive_direct", "message": key["message"], "from_certificate": from});
    ok(&mut b1.core, taken);

    // A1 goes quiet. In the DM, the server takes A1's message, whose answer A1 never hears, and
    // B1 writes.
    let applied = [dm, group].map(|conversation| server.chats[&conversation].queue.len());
    let nonce = new_id().to_string();
    let encrypted = ok(
        &mut a1.core,
        json!({"cmd": "encrypt", "conversation_id": dm, "nonce": nonce, "envelope": {"text": "sent as it fell"}}),
    );
    let (unsent, unsent_seq) =
        server.post_message(&a1, dm, &nonce, bytes(&encrypted["ciphertext"]), &[]);
    send(
        &mut server,
        &mut b1,
        dm,
        json!({"text": "are you there?"}),
        &[],
    );
    // In the group, the server takes A1's renewal, whose answer A1 never hears; B1 writes; then B
    // takes B2 off its list, and the server proposes B2's leaf out, which B1 keeps.
    let renewal = ok(
        &mut a1.core,
        json!({"cmd": "refresh", "conversation_id": group}),
    );
    let renewal_seq = server.take_unanswered(&mut a1, group, &renewal);
    server.deliver(&mut b1);
    let ping = json!({"text": "ping after your renewal"});
    send(&mut server, &mut b1, group, ping, &[a]);
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &list["device_list"]);
    server.introduce(&mut a1);
    server.introduce(&mut b1);
    server.remove_device(group, b2.id);
    server.deliver(&mut b1);
    let shown_now = [dm, group].map(|conversation| shown(&mut a1.core, conversation));

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

    let backup_due = ok(&mut a1.core, json!({"cmd": "backup_due"}))["segments"].clone();
    let version: i64 = a1.rolled_back(|tx| {
        Ok(tx
            .conn()
            .query_row("PRAGMA user_version", [], |row| row.get(0))?)
    });
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
        "b": {"user": b, "device": b1.id, "certificate": certificate(&server, b, b1.id)},
        "conversations": [
            conversation(dm, 0, &shown_now[0], "how", "are you there?"),
            conversation(group, 1, &shown_now[1], "plan", "ping after your renewal"),
        ],
        "outbox": {"conversation": dm, "nonce": nonce, "message_id": unsent, "seq": unsent_seq},
        "commit": {"conversation": group, "seq": renewal_seq},
        "proposal": {"conversation": group},
        "waiting": {"conversation": dm, "message_id": waiting},
        "deviceless": {"conversation": group, "user": b},
        "backup_due": backup_due,
        "share": {"share_id": shared["share_id"], "parts": shared["parts"]},
        "approval": {"reveal": revealed["reveal"]},
    });
    std::fs::create_dir_all(fixtures()).unwrap();
    let write = |name: String, bytes: &[u8]| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(fixtures().join(name))
            .expect("a fixture not written yet: they're frozen");
        std::io::Write::write_all(&mut file, bytes).unwrap();
    };
    write(
        format!("db-v{version}.sqlite"),
        &std::fs::read(a1.db_path()).unwrap(),
    );
    write(
        format!("db-v{version}-peer.sqlite"),
        &std::fs::read(b1.db_path()).unwrap(),
    );
    let json = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    write(format!("db-v{version}.json"), json.as_bytes());
}

/// `device` takes out what's pending in `conversation` (`commit_pending`), looking its users up
/// again when it asks to first, and the server takes the commit.
fn take_out_pending(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid) {
    let pending = json!({"cmd": "commit_pending", "conversation_id": conversation});
    let mut removal = run(&mut device.core, &pending);
    for _ in 0..2 {
        if removal.get("error").is_none() {
            break;
        }
        assert_eq!(removal["error"]["code"], "needs_identities", "{removal}");
        server.introduce(device);
        removal = run(&mut device.core, &pending);
    }
    server.submit(device, conversation, &removal["ok"]).unwrap();
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
