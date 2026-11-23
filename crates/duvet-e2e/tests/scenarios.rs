//! Phase 1's criteria the earlier tests don't cover, end to end through `Core::handle`, against the
//! fake of the API: one installation is one device across sessions, a logout only ends the session,
//! a device back after the server's 45 days of queue comes back into its groups without losing its
//! database, and what a user writes never reaches the server's storage in the clear.

mod support;

use duvet_e2e::{Clock, Envelope};
use duvet_e2e_rules::Kind;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::*;
use uuid::Uuid;

const HOUR: i64 = 60 * 60 * 1000;

/// How long the server keeps a conversation's queue (decision 13).
const QUEUE_DAYS: i64 = 45;

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

fn command(name: &str, conversation: Uuid) -> Value {
    json!({"cmd": name, "conversation_id": conversation})
}

fn apply(conversation: Uuid, entries: &[Value]) -> Value {
    json!({"cmd": "apply", "conversation_id": conversation, "entries": entries})
}

fn joining(server: &FakeServer, conversation: Uuid) -> Value {
    json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    })
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

/// `device` sends `envelope` to `conversation`, and hears the API's answer: the message's ID and
/// number.
fn send(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    envelope: Value,
) -> (Uuid, u64) {
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
    (message_id, seq)
}

/// `device` writes `text` to `conversation`: the message's ID and number.
fn say(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    text: &str,
) -> (Uuid, u64) {
    send(server, device, conversation, json!({"text": text}))
}

/// The messages of `conversation` as `device` shows them, newest first.
fn messages_of(device: &mut TestDevice, conversation: Uuid) -> Vec<Value> {
    let page = ok(
        &mut device.core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
    );
    page["messages"].as_array().unwrap().clone()
}

/// The message `message_id` as `device` shows it, if it shows it.
fn message(device: &mut TestDevice, conversation: Uuid, message_id: Uuid) -> Option<Value> {
    messages_of(device, conversation)
        .into_iter()
        .find(|shown| shown["message_id"] == json!(message_id))
}

/// The text of `message_id` as `device` shows it.
fn text_of(device: &mut TestDevice, conversation: Uuid, message_id: Uuid) -> Value {
    message(device, conversation, message_id).expect("the message is shown")["text"].clone()
}

fn status(device: &mut TestDevice) -> Value {
    ok(&mut device.core, json!({"cmd": "status"}))
}

/// What `encrypt` checks before it encrypts: whether the device may send now.
fn ready(device: &mut TestDevice, conversation: Uuid) -> Result<(), Value> {
    device
        .core
        .transaction(|tx| duvet_e2e::mls::ready_to_send(tx, conversation))
        .map_err(|error| error.to_reply()["error"].clone())
}

/// The certificate of `user`'s `device`, as the server serves it.
fn certificate(server: &FakeServer, user: Uuid, device: Uuid) -> Value {
    server.observed(user)["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|certificate| {
            duvet_e2e_rules::DeviceCertificate::read_unverified(&bytes(certificate))
                .unwrap()
                .device
                == device
        })
        .expect("the device's certificate")
        .clone()
}

/// `device` takes what a share or a catch-up (`shared`) sealed to it, from the device whose
/// certificate is `from`: its key, through the server's inbox, then the package. The direct messages
/// it took, as the server held them.
fn take_package(
    server: &mut FakeServer,
    device: &mut TestDevice,
    from: &Value,
    shared: &Value,
) -> Vec<Vec<u8>> {
    for key in shared["keys"].as_array().unwrap() {
        let to: Uuid = key["device_id"].as_str().unwrap().parse().unwrap();
        server.post(to, bytes(&key["message"]));
    }
    let inbox = server.inbox(device.id);
    for message in &inbox {
        ok(
            &mut device.core,
            json!({"cmd": "receive_direct", "message": b64(message), "from_certificate": from}),
        );
    }
    ok(
        &mut device.core,
        json!({"cmd": "history_import", "share_id": shared["share_id"], "parts": shared["parts"]}),
    );
    inbox
}

/// A new device of `user`, recovered with the recovery key of `identity` (an identity's reply),
/// whose certificate and list the server takes.
fn recovered(server: &mut FakeServer, user: Uuid, identity: &Value) -> TestDevice {
    let mut device = server.bare_device(user);
    let reply = ok(
        &mut device.core,
        json!({
            "cmd": "recover",
            "recovery_key": identity["recovery_key"],
            "wrapped_backup_key": identity["wrapped_backup_key"],
            "encrypted_identity": identity["encrypted_identity"],
            "device_list": server.observed(user)["device_list"],
        }),
    );
    server.take_device(user, &reply["certificate"], &reply["device_list"]);
    device
}

/// The start of the UTC day after tomorrow by the system's clock: the core's clock never goes behind
/// the system's, which OpenMLS reads for key packages' lifetimes.
fn test_day(server: &FakeServer) -> i64 {
    (server.clock.now_ms().div_euclid(DAY_MS) + 2) * DAY_MS
}

/// A session that ends (it expires, or the app quits) leaves the installation as it was: the core
/// holds nothing of a session, so the client opens the same database with its key and logs in, and
/// it's the same device, with its identity, its key packages and its groups. No new device is made,
/// nothing joins or leaves a group for it, and it reads and sends on as before. (Tying a device to
/// the login, with a signed challenge, is the API's, decision 13.)
#[test]
fn same_installation_stays_the_same_device() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let (before, _) = say(&mut server, &mut a1, conversation, "antes de que venza");
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let device = status(&mut a1);
    let key_packages = ok(&mut a1.core, json!({"cmd": "key_packages"}));
    let group = a1.group(conversation);

    // A day later A1's session has expired, and B1 has written meanwhile. The client opens the same
    // database with its key, and logs in again.
    server.clock.advance(DAY_MS);
    let (meanwhile, _) = say(&mut server, &mut b1, conversation, "mientras tanto");
    let mut a1 = a1.reopened(server.clock.clone());

    // The same device: the same user, device and identity, the same key packages, the same group.
    assert_eq!(status(&mut a1), device);
    assert_eq!(
        ok(&mut a1.core, json!({"cmd": "key_packages"})),
        key_packages
    );
    assert_eq!(a1.group(conversation), group);
    // A client that took it for a new installation can't make another device of it.
    let refused = error(
        &mut a1.core,
        json!({"cmd": "create_device", "user_id": a, "device_id": new_id()}),
    );
    assert_eq!(refused["code"], "exists");
    assert_eq!(status(&mut a1), device);

    // It takes the queue from where it was, and sends on; A's list still has A1 alone.
    server.deliver(&mut a1);
    assert_eq!(text_of(&mut a1, conversation, before), "antes de que venza");
    assert_eq!(text_of(&mut a1, conversation, meanwhile), "mientras tanto");
    let (after, _) = say(&mut server, &mut a1, conversation, "sigo siendo yo");
    server.deliver(&mut b1);
    assert_eq!(text_of(&mut b1, conversation, after), "sigo siendo yo");
    assert_eq!(
        server.observed(a)["certificates"].as_array().unwrap().len(),
        1
    );
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 1);
}

/// Logging out only ends the session (decision 13): the device stays in its groups and keeps its
/// database, and nothing proposes its removal, as a device never leaves its groups by itself. While
/// it's logged out the group goes on: B writes, A's other device adds C, B renews its leaf. Logged in
/// again on the same installation, it has its history as it left it, takes the queue from where it
/// was, and reads and sends to everyone, C included. Taking a device out is another action, the
/// user's, from another of their devices (`rotate.rs`).
#[test]
fn logout_keeps_the_device_and_its_data() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut c1] = new_devices(&mut server, [a, a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let (kept, _) = say(&mut server, &mut a1, conversation, "lo que ya tenía");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let device = status(&mut a1);
    let history = messages_of(&mut a1, conversation);

    // A1 logs out: its client closes the core and keeps the database. A1 stays in the group.
    server.clock.advance(HOUR);
    let (meanwhile, _) = say(&mut server, &mut b1, conversation, "mientras no estabas");
    server.deliver_all(&mut [&mut a2, &mut b1]);
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a2, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a2, &mut b1, &mut c1]);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a2, &mut b1, &mut c1]);
    let state = same_group(&mut [&mut a2, &mut b1, &mut c1], conversation);
    assert_eq!(state["epoch"], 3);
    assert!(devices(&state).contains(&a1.id));

    // A1 logs in again: the same device, with its history as it left it.
    let mut a1 = a1.reopened(server.clock.clone());
    assert_eq!(status(&mut a1), device);
    assert_eq!(messages_of(&mut a1, conversation), history);

    // It takes the queue from where it was: B's message, C's entry and B's new leaf.
    server.deliver(&mut a1);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut c1], conversation);
    assert_eq!(members(&state), [a, b, c]);
    assert_eq!(
        text_of(&mut a1, conversation, meanwhile),
        "mientras no estabas"
    );
    assert_eq!(text_of(&mut a1, conversation, kept), "lo que ya tenía");
    assert_eq!(ready(&mut a1, conversation), Ok(()));
    let (back, _) = say(&mut server, &mut a1, conversation, "de vuelta");
    for device in [&mut b1, &mut c1] {
        server.deliver(device);
        assert_eq!(text_of(device, conversation, back), "de vuelta");
    }
}

/// B's one device goes away for longer than the server keeps the queue, 45 days (decision 13). It
/// stays in the group meanwhile, as no device leaves its groups by itself, while A renews its leaf
/// every 7 days. Once B has had no device connected for 45 days, B counts as without devices
/// (decision 14), and A's device notes what it sends for B. Back, B1 finds the entries it needs gone
/// (`gap`), and comes back into the group by an external commit, its database kept: its device, its
/// identity and its history. A1 passes it what it noted (a catch-up); what came before B counted as
/// without devices left with the queue, and A shares it (history, decision 26).
#[test]
fn returning_after_45_days_rejoins_without_losing_its_db() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let (old, _) = say(&mut server, &mut b1, conversation, "antes de irme");
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let device = status(&mut b1);
    let left = server.clock.now_ms();

    // B1 goes away. A1 writes the second day, and renews its leaf every 7 days.
    server.clock.advance(2 * DAY_MS);
    let (early, early_seq) = say(&mut server, &mut a1, conversation, "al segundo día");
    for _ in 0..6 {
        server.clock.advance(7 * DAY_MS);
        server.deliver(&mut a1);
        let due = ok(&mut a1.core, json!({"cmd": "refresh_due"}));
        assert_eq!(due["conversations"], json!([conversation]));
        server
            .commit(&mut a1, conversation, command("refresh", conversation))
            .unwrap();
    }
    server.deliver(&mut a1);

    // 46 days on, B's one device has been away more than 45: the API counts B as without devices,
    // and A1's client tells its core, which notes for B what A1 writes from then on.
    server.clock.advance(2 * DAY_MS);
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    let (late, _) = say(&mut server, &mut a1, conversation, "cuando vuelvas");
    server.deliver(&mut a1);

    // B1 comes back on day 48. The server keeps 45 days of queue: what came before is gone, and
    // what's left starts after a hole.
    server.clock.set(left + 48 * DAY_MS);
    let since = server.clock.now_ms() - QUEUE_DAYS * DAY_MS;
    let kept: Vec<Value> = server
        .entries(conversation)
        .into_iter()
        .filter(|entry| entry["sent_at"].as_i64().unwrap() >= since)
        .collect();
    assert_eq!(kept[0]["seq"], json!(early_seq + 1));
    let hole = error(&mut b1.core, apply(conversation, &kept));
    assert_eq!(
        (&hole["code"], &hole["from"]),
        (&json!("gap"), &json!(early_seq))
    );

    // B1 comes back into the group by an external commit on the latest epoch's group info, in place
    // of the group it had. The same device, with its history.
    let rejoined = server
        .commit(&mut b1, conversation, joining(&server, conversation))
        .unwrap();
    assert!(rejoined["group_info"].is_string());
    assert_eq!(status(&mut b1), device);
    assert_eq!(text_of(&mut b1, conversation, old), "antes de irme");

    // A1 takes it: B, without devices till now, is due a catch-up, which A1 makes for B1's
    // device. B1 takes it: what A1 wrote for it, marked as shared by A.
    let taken = server.deliver(&mut a1);
    assert_eq!(taken[0]["catch_up_due"], json!([b]));
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 8);
    assert_eq!(members(&state), [a, b]);
    assert_eq!(
        devices(&state)
            .iter()
            .filter(|device| **device == b1.id)
            .count(),
        1,
        "B1's leaf from before goes with its external commit: {state}"
    );
    let caught = ok(
        &mut a1.core,
        json!({
            "cmd": "catch_up",
            "conversation_id": conversation,
            "user_id": b,
            "devices": server.observed(b)["certificates"],
        }),
    );
    let from = certificate(&server, a, a1.id);
    take_package(&mut server, &mut b1, &from, &caught);
    ok(
        &mut a1.core,
        json!({
            "cmd": "catch_up_delivered",
            "conversation_id": conversation,
            "user_id": b,
            "share_id": caught["share_id"],
        }),
    );
    let copy = message(&mut b1, conversation, late).unwrap();
    assert_eq!(copy["text"], "cuando vuelvas");
    assert_eq!(copy["shared_by"], json!(a));
    assert_eq!(message(&mut b1, conversation, early), None);

    // What came before B counted as without devices, A shares with B: all of it.
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": server.observed(b)["certificates"],
        }),
    );
    take_package(&mut server, &mut b1, &from, &shared);
    assert_eq!(text_of(&mut b1, conversation, early), "al segundo día");
    assert_eq!(text_of(&mut b1, conversation, old), "antes de irme");
    assert_eq!(
        message(&mut b1, conversation, old).unwrap()["shared_by"],
        Value::Null
    );

    // And they converse again.
    let (again, _) = say(&mut server, &mut b1, conversation, "ya volví");
    server.deliver(&mut a1);
    assert_eq!(text_of(&mut a1, conversation, again), "ya volví");
}

/// One token, so a search sees it whether a blob holds it as a value or as a word.
const WITNESS: &str = "duvetwitnessword";

/// Whether `blob` holds `text`, byte for byte.
fn holds(blob: &[u8], text: &str) -> bool {
    blob.windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// A witness string goes everywhere a DM's words go: a message, a file's name and content, an edit,
/// an answer, the day's backup segment, a history package and the keys sent with it. Afterwards no
/// queue, inbox, key package, list, certificate, group state, nonce, file, segment or package the
/// server holds has it in the clear, while each device it was sent to reads it, from each of them.
#[test]
fn witness_string_never_reaches_the_server() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    // What the server keeps beside its database: the identity's blobs a new device recovers with,
    // and the files clients upload (attachments' parts, backup segments, history packages).
    let mut uploaded: Vec<(String, Vec<u8>)> = vec![
        (
            "the wrapped backup key".into(),
            bytes(&identity["wrapped_backup_key"]),
        ),
        (
            "the encrypted identity".into(),
            bytes(&identity["encrypted_identity"]),
        ),
    ];
    let mut a2 = recovered(&mut server, a, &identity);
    server.publish(&mut a2);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    let day = test_day(&server);
    server.clock.set(day - 12 * HOUR);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // During the day A1 writes the witness in a message, then sends a file named after it that
    // holds it, in parts it encrypts and uploads; it edits a message to it; B1 answers with it.
    server.clock.set(day + HOUR);
    let witnessed = format!("el testigo: {WITNESS}");
    let (said, _) = say(&mut server, &mut a1, conversation, &witnessed);
    let key = ok(&mut a1.core, json!({"cmd": "attachment_key"}))["key"].clone();
    let file_id = new_id();
    let file = format!("un archivo con {WITNESS} adentro. ").repeat(4_000);
    let pieces: Vec<&[u8]> = file
        .as_bytes()
        .chunks(duvet_e2e::parts::ATTACHMENT_PART)
        .collect();
    assert!(pieces.len() > 1);
    let mut parts = Vec::new();
    for (index, piece) in pieces.iter().enumerate() {
        let sealed = ok(
            &mut a1.core,
            json!({
                "cmd": "attachment_encrypt",
                "key": key,
                "attachment_id": file_id,
                "index": index,
                "last": index + 1 == pieces.len(),
                "data": b64(piece),
            }),
        );
        parts.push(bytes(&sealed["data"]));
    }
    for (index, part) in parts.iter().enumerate() {
        uploaded.push((format!("part {index} of the file"), part.clone()));
    }
    let attachment = json!({
        "id": file_id,
        "key": key,
        "sha256": b64(&Sha256::digest(file.as_bytes())),
        "name": format!("{WITNESS}.txt"),
        "type": "text/plain",
        "size": file.len(),
    });
    let (with_file, _) = send(
        &mut server,
        &mut a1,
        conversation,
        json!({"text": "un archivo", "attachments": [attachment]}),
    );
    let (edited, _) = say(&mut server, &mut a1, conversation, "sin nada");
    let edit = ok(
        &mut a1.core,
        json!({"cmd": "edit", "conversation_id": conversation, "message_id": edited, "text": witnessed}),
    );
    server.post_change(
        &a1,
        conversation,
        "edit",
        edited,
        bytes(&edit["ciphertext"]),
    );
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let answer = format!("respondo a {WITNESS}");
    let (answered, _) = say(&mut server, &mut b1, conversation, &answer);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // Each device reads it: the message, the file's name, the edit and the answer.
    for device in [&mut a2, &mut b1] {
        assert_eq!(text_of(device, conversation, said), json!(witnessed));
        assert_eq!(text_of(device, conversation, edited), json!(witnessed));
        let shown = message(device, conversation, with_file).unwrap();
        assert_eq!(shown["attachments"][0]["name"], format!("{WITNESS}.txt"));
    }
    assert_eq!(text_of(&mut a1, conversation, answered), json!(answer));
    // The file's parts open again to the file.
    let mut opened = Vec::new();
    for (index, part) in parts.iter().enumerate() {
        let open = ok(
            &mut b1.core,
            json!({
                "cmd": "attachment_decrypt",
                "key": key,
                "attachment_id": file_id,
                "index": index,
                "last": index + 1 == parts.len(),
                "data": b64(part),
            }),
        );
        opened.extend(bytes(&open["data"]));
    }
    assert_eq!(opened, file.as_bytes());

    // The next day A1 backs the day up, and the client uploads the segment. A3, recovered then,
    // reads the witness from it.
    server.clock.set(day + DAY_MS + HOUR);
    let due = ok(&mut a1.core, json!({"cmd": "backup_due"}));
    let the_day = due["segments"][0]["day"].clone();
    let built = ok(
        &mut a1.core,
        json!({"cmd": "backup_segment", "conversation_id": conversation, "day": the_day}),
    );
    ok(
        &mut a1.core,
        json!({
            "cmd": "backup_uploaded",
            "conversation_id": conversation,
            "day": the_day,
            "complete": built["complete"],
            "version": built["version"],
        }),
    );
    uploaded.push(("the day's segment".into(), bytes(&built["data"])));
    let mut a3 = recovered(&mut server, a, &identity);
    ok(
        &mut a3.core,
        json!({"cmd": "backup_import", "data": built["data"]}),
    );
    assert_eq!(text_of(&mut a3, conversation, said), json!(witnessed));

    // B's new device joins the DM, and A1 shares the history with B: B2 reads the witness from the
    // package, whose keys went through the server's inboxes.
    let mut b2 = server.device(b);
    server.publish(&mut b2);
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        server.introduce(device);
    }
    server
        .commit(&mut b2, conversation, joining(&server, conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "all",
            "devices": server.observed(b)["certificates"],
        }),
    );
    for (index, part) in shared["parts"].as_array().unwrap().iter().enumerate() {
        uploaded.push((format!("part {index} of the package"), bytes(part)));
    }
    let from = certificate(&server, a, a1.id);
    for message in take_package(&mut server, &mut b2, &from, &shared) {
        uploaded.push(("a key in B2's inbox".into(), message));
    }
    assert_eq!(text_of(&mut b2, conversation, said), json!(witnessed));

    // None of what the server holds has the witness in the clear, nor does what it was handed.
    let mut stored = server.held();
    stored.extend(uploaded);
    assert!(stored.len() > 50, "{} blobs", stored.len());
    let found: Vec<&str> = stored
        .iter()
        .filter(|(_, blob)| holds(blob, WITNESS))
        .map(|(place, _)| place.as_str())
        .collect();
    assert_eq!(found, Vec::<&str>::new());
    // The search sees plaintext where there is some: the envelope each device kept holds it.
    let envelope = Envelope::Message {
        text: Some(witnessed.clone()),
        attachments: Vec::new(),
    }
    .encode()
    .unwrap();
    assert!(holds(&envelope, WITNESS));
}
