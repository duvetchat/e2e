//! Messages through `Core::handle`, against a fake of the API: each device encrypts what it sends,
//! and the queue brings it to every device of the conversation, the sender's own included. Edits and
//! deletions count only from their message's author; the local search finds words with or without
//! their accents; a message a device can't read waits for an import; and a sender notes what it
//! sends while a member has no device, for that member's catch-up.

mod support;

use duvet_e2e::messages::{self, MAX_CIPHERTEXT, RecordKind};
use duvet_e2e::{Clock, Envelope, MAX_ENVELOPE, mls};
use duvet_e2e_rules::Kind;
use openmls::prelude::tls_codec::Serialize as _;
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

fn command(name: &str, conversation: Uuid) -> Value {
    json!({"cmd": name, "conversation_id": conversation})
}

fn joining(server: &FakeServer, conversation: Uuid) -> Value {
    json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": server.group_info(conversation),
    })
}

fn apply(conversation: Uuid, entries: &[Value]) -> Value {
    json!({"cmd": "apply", "conversation_id": conversation, "entries": entries})
}

fn encrypt(conversation: Uuid, nonce: &str, envelope: Value) -> Value {
    json!({"cmd": "encrypt", "conversation_id": conversation, "nonce": nonce, "envelope": envelope})
}

fn new_nonce() -> String {
    new_id().to_string()
}

/// A file as a message carries it: its ID, its key and its hash, and what it is.
fn file(name: &str, content_type: &str) -> Value {
    json!({
        "id": new_id(),
        "key": b64(&[7; 32]),
        "sha256": b64(&[8; 32]),
        "name": name,
        "type": content_type,
        "size": 48_213,
        "width": 640,
        "height": 480,
    })
}

/// `device` encrypts `envelope` under `nonce`, posts it with the users it mentions, and hears the
/// API's answer (`sent`): the message's ID.
fn send(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    envelope: Value,
    mentions: &[Uuid],
) -> Uuid {
    let nonce = new_nonce();
    let encrypted = ok(&mut device.core, encrypt(conversation, &nonce, envelope));
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

/// `device` writes `text` to `conversation`: the message's ID.
fn say(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid, text: &str) -> Uuid {
    send(server, device, conversation, json!({"text": text}), &[])
}

fn edit_command(conversation: Uuid, message_id: Uuid, text: &str) -> Value {
    json!({"cmd": "edit", "conversation_id": conversation, "message_id": message_id, "text": text})
}

fn delete_command(conversation: Uuid, message_id: Uuid) -> Value {
    json!({"cmd": "delete", "conversation_id": conversation, "message_id": message_id})
}

/// `device` edits its message `message_id` to `text`, and posts the edit: its number.
fn edit(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    message_id: Uuid,
    text: &str,
) -> u64 {
    let edited = ok(
        &mut device.core,
        edit_command(conversation, message_id, text),
    );
    for field in ["ciphertext", "generation", "epoch"] {
        assert!(!edited[field].is_null(), "{field}");
    }
    let ciphertext = bytes(&edited["ciphertext"]);
    server.post_change(device, conversation, "edit", message_id, ciphertext)
}

/// `device` deletes its message `message_id` for everyone, and posts the deletion: its number.
fn delete(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    message_id: Uuid,
) -> u64 {
    let deleted = ok(&mut device.core, delete_command(conversation, message_id));
    let ciphertext = bytes(&deleted["ciphertext"]);
    server.post_change(device, conversation, "delete", message_id, ciphertext)
}

/// A message `device` encrypts in its group past its core's checks, as a client that skips them
/// would. Its state moves on as with any message it sends.
fn forge(device: &mut TestDevice, conversation: Uuid, envelope: &Envelope) -> Vec<u8> {
    let plain = envelope.encode().unwrap();
    device
        .core
        .transaction(|tx| {
            let (mut group, _) = mls::load_group(tx, conversation)?;
            let own = tx.own_device()?;
            let message = group
                .create_message(tx.provider(), &own.signer, &plain)
                .unwrap();
            Ok(message.tls_serialize_detached().unwrap())
        })
        .unwrap()
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

/// The messages as every device shows them alike: without the nonce, which only the sender's own
/// copy keeps.
fn shared_view(device: &mut TestDevice, conversation: Uuid) -> Vec<Value> {
    messages_of(device, conversation)
        .into_iter()
        .map(|mut shown| {
            shown.as_object_mut().unwrap().remove("nonce");
            shown
        })
        .collect()
}

/// The `search` reply for `query`, 25 results at most unless it says otherwise.
fn search(device: &mut TestDevice, query: Value) -> Value {
    let mut command = json!({"cmd": "search", "limit": 25});
    for (field, value) in query.as_object().unwrap() {
        command[field] = value.clone();
    }
    ok(&mut device.core, command)
}

/// The IDs of the messages a search finds, newest first.
fn found(device: &mut TestDevice, query: Value) -> Vec<Uuid> {
    search(device, query)["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|shown| shown["message_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// The text and the file a message's row keeps, read from the table itself.
fn stored(device: &mut TestDevice, message_id: Uuid) -> (Option<String>, Option<Vec<u8>>) {
    device.rolled_back(|tx| {
        Ok(tx.conn().query_row(
            "SELECT text, envelope FROM messages WHERE message_id = ?1",
            [message_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?)
    })
}

/// How many edits of `message_id` the device keeps.
fn edits_kept(device: &mut TestDevice, message_id: Uuid) -> i64 {
    device.rolled_back(|tx| {
        Ok(tx.conn().query_row(
            "SELECT count(*) FROM edits WHERE message_id = ?1",
            [message_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?)
    })
}

/// Whether the search index's own storage holds `word`, as it holds the words it indexes.
fn index_holds(device: &mut TestDevice, word: &str) -> bool {
    device.rolled_back(|tx| {
        let mut statement = tx.conn().prepare("SELECT block FROM messages_fts_data")?;
        let blocks = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(blocks.iter().any(|block| {
            block
                .windows(word.len())
                .any(|window| window == word.as_bytes())
        }))
    })
}

/// The results of `replies`, each `[seq, kind, result, rule or reason]`.
fn results(replies: &[Value]) -> Vec<Value> {
    replies
        .iter()
        .flat_map(|reply| reply["results"].as_array().unwrap().clone())
        .map(|result| {
            let why = result
                .get("rule")
                .or_else(|| result.get("reason"))
                .cloned()
                .unwrap_or(Value::Null);
            json!([result["seq"], result["kind"], result["result"], why])
        })
        .collect()
}

/// A group of A and B, two devices each, everyone in it.
fn group_of_four() -> (FakeServer, Uuid, [Uuid; 2], [TestDevice; 4]) {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    (server, conversation, [a, b], [a1, a2, b1, b2])
}

/// A DM of A and B, one device each, both in it.
fn dm() -> (FakeServer, Uuid, [Uuid; 2], [TestDevice; 2]) {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    (server, conversation, [a, b], [a1, b1])
}

#[test]
fn two_users_two_devices_converse() {
    let (mut server, conversation, [a, b], [mut a1, mut a2, mut b1, mut b2]) = group_of_four();

    // A1 writes with a photo, and B2 answers.
    let photo = file("playa.jpg", "image/jpeg");
    let hello = json!({"text": "Hola, ¿cómo estás?", "attachments": [photo]});
    let first = send(&mut server, &mut a1, conversation, hello, &[]);
    server.clock.advance(1_000);
    let second = say(&mut server, &mut b2, conversation, "Bien, ¿y tú? 👍");

    // Each device takes the queue: its own message comes back as its own, the other it reads.
    let taken = server.deliver(&mut a1);
    assert_eq!(
        results(&taken),
        [
            json!([3, "message", "own", null]),
            json!([4, "message", "applied", null])
        ]
    );
    let taken = server.deliver(&mut b2);
    assert_eq!(
        results(&taken),
        [
            json!([3, "message", "applied", null]),
            json!([4, "message", "own", null])
        ]
    );
    server.deliver_all(&mut [&mut a2, &mut b1]);

    // The four show the same two messages, newest first: the text, the file with its key, and who
    // wrote each from which device.
    let shown = shared_view(&mut a1, conversation);
    assert_eq!(shown.len(), 2);
    let expected = [
        (second, b, b2.id, 4, json!("Bien, ¿y tú? 👍"), json!([])),
        (
            first,
            a,
            a1.id,
            3,
            json!("Hola, ¿cómo estás?"),
            json!([photo]),
        ),
    ];
    for (shown, (id, user, device, seq, text, attachments)) in shown.iter().zip(expected) {
        assert_eq!(shown["message_id"], json!(id));
        assert_eq!(shown["conversation_id"], json!(conversation));
        assert_eq!(shown["user_id"], json!(user));
        assert_eq!(shown["device_id"], json!(device));
        assert_eq!(shown["seq"], json!(seq));
        assert_eq!(shown["status"], "ok");
        assert_eq!(shown["text"], text);
        assert_eq!(shown["attachments"], attachments);
        assert_eq!(shown["edited_at"], Value::Null);
        assert_eq!(shown["shared_by"], Value::Null);
        assert!(shown["sent_at"].is_i64());
    }
    for device in [&mut a2, &mut b1, &mut b2] {
        assert_eq!(shared_view(device, conversation), shown);
    }
    // The sender's own copy keeps the nonce it was sent under.
    assert!(messages_of(&mut a1, conversation)[1]["nonce"].is_string());

    // A page of the history goes back from a message's number.
    let page = ok(
        &mut b1.core,
        json!({"cmd": "messages", "conversation_id": conversation, "before": 4, "limit": 10}),
    );
    let ids: Vec<&Value> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|shown| &shown["message_id"])
        .collect();
    assert_eq!(ids, [&json!(first)]);
    let newest = ok(
        &mut b1.core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 1}),
    );
    assert_eq!(newest["messages"][0]["message_id"], json!(second));
    assert_eq!(newest["messages"].as_array().unwrap().len(), 1);
}

#[test]
fn nonce_retry_does_not_duplicate() {
    let (mut server, conversation, _, [mut a1, mut b1]) = dm();

    // A1 encrypts its message: until the API answers, A1 shows it as being sent.
    let envelope = json!({"text": "solo una vez"});
    let first = ok(
        &mut a1.core,
        encrypt(conversation, "retry", envelope.clone()),
    );
    assert_eq!(first["sender_device_id"], json!(a1.id));
    assert_eq!(first["generation"], 0);
    assert_eq!(first["epoch"], 1);
    let pending = messages_of(&mut a1, conversation);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["status"], "pending");
    assert_eq!(pending[0]["nonce"], "retry");
    assert_eq!(pending[0]["message_id"], Value::Null);
    assert_eq!(pending[0]["text"], "solo una vez");

    // The API takes it, but its answer is lost. The retry, under the same nonce, is the same
    // ciphertext, not encrypted again, and the API answers with the message it took.
    let taken = server.post_message(&a1, conversation, "retry", bytes(&first["ciphertext"]), &[]);
    let again = ok(
        &mut a1.core,
        encrypt(conversation, "retry", envelope.clone()),
    );
    assert_eq!(again, first);
    let posted = server.post_message(&a1, conversation, "retry", bytes(&again["ciphertext"]), &[]);
    assert_eq!(posted, taken);

    // The same nonce for another message is a mistake.
    let other = error(
        &mut a1.core,
        encrypt(conversation, "retry", json!({"text": "otra cosa"})),
    );
    assert_eq!(
        (&other["code"], &other["field"]),
        (&json!("bad_command"), &json!("nonce"))
    );

    // The answer binds the nonce to the message's ID and number, the same answer again changes
    // nothing, and another one is refused.
    let sent = json!({
        "cmd": "sent",
        "conversation_id": conversation,
        "nonce": "retry",
        "message_id": taken.0,
        "seq": taken.1,
    });
    ok(&mut a1.core, sent.clone());
    ok(&mut a1.core, sent.clone());
    let mut wrong = sent.clone();
    wrong["message_id"] = json!(new_id());
    assert_eq!(error(&mut a1.core, wrong)["field"], "message_id");
    let mut unknown = sent;
    unknown["nonce"] = json!("never");
    assert_eq!(error(&mut a1.core, unknown)["what"], "message");

    // One message on each side.
    server.deliver_all(&mut [&mut a1, &mut b1]);
    for device in [&mut a1, &mut b1] {
        let shown = messages_of(device, conversation);
        assert_eq!(shown.len(), 1);
        assert_eq!(shown[0]["message_id"], json!(taken.0));
        assert_eq!(shown[0]["status"], "ok");
        assert_eq!(shown[0]["text"], "solo una vez");
    }

    // Once its copy has come back, the nonce is spent.
    let spent = error(&mut a1.core, encrypt(conversation, "retry", envelope));
    assert_eq!(spent["code"], "exists");
}

#[test]
fn edit_and_delete_from_the_author_only() {
    let (mut server, conversation, _, [mut a1, mut a2, mut b1, mut b2]) = group_of_four();
    let mine = say(&mut server, &mut a1, conversation, "la primera versión");
    let other = say(&mut server, &mut a1, conversation, "otra frase de A");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // A1 edits its message: every device shows the new text, marked as edited.
    server.clock.advance(1_000);
    edit(
        &mut server,
        &mut a1,
        conversation,
        mine,
        "la versión corregida",
    );
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        let shown = message(device, conversation, mine).unwrap();
        assert_eq!(shown["text"], "la versión corregida");
        assert!(shown["edited_at"].is_i64(), "{shown}");
    }

    // B1's core won't edit or delete A's message...
    for refused in [
        edit_command(conversation, other, "de B"),
        delete_command(conversation, other),
    ] {
        let refused = error(&mut b1.core, refused);
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("not_author"))
        );
    }
    // ...and the edit and the deletion B1 makes past its core's checks every device ignores.
    let forged = Envelope::Edit {
        message_id: other,
        text: "de B".into(),
    };
    let forged = forge(&mut b1, conversation, &forged);
    let edit_seq = server.post_change(&b1, conversation, "edit", other, forged);
    let forged = forge(
        &mut b1,
        conversation,
        &Envelope::Delete { message_id: other },
    );
    let delete_seq = server.post_change(&b1, conversation, "delete", other, forged);
    for device in [&mut a1, &mut a2, &mut b2] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [
                json!([edit_seq, "edit", "rejected", "not_author"]),
                json!([delete_seq, "delete", "rejected", "not_author"])
            ]
        );
        let shown = message(device, conversation, other).unwrap();
        assert_eq!(shown["text"], "otra frase de A");
        assert_eq!(shown["edited_at"], Value::Null);
    }
    let taken = server.deliver(&mut b1);
    assert_eq!(
        results(&taken),
        [
            json!([edit_seq, "edit", "own", null]),
            json!([delete_seq, "delete", "own", null])
        ]
    );

    // A1 deletes its message: no device shows it, and its text leaves the table, its edits and the
    // search index, whose own storage held its words until then.
    assert!(index_holds(&mut b1, "corregida"));
    delete(&mut server, &mut a1, conversation, mine);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        assert_eq!(message(device, conversation, mine), None);
        assert!(message(device, conversation, other).is_some());
        assert_eq!(
            found(device, json!({"text": "corregida"})),
            Vec::<Uuid>::new()
        );
        assert_eq!(
            found(device, json!({"text": "primera"})),
            Vec::<Uuid>::new()
        );
        assert!(!index_holds(device, "corregida"));
        assert!(!index_holds(device, "primera"));
        assert_eq!(stored(device, mine), (None, None));
        assert_eq!(edits_kept(device, mine), 0);
    }
}

#[test]
fn delete_reaches_an_offline_device() {
    let (mut server, conversation, _, [mut a1, mut a2, mut b1, mut b2]) = group_of_four();
    let gone = say(&mut server, &mut a1, conversation, "esto desaparece");
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    assert_eq!(
        message(&mut b2, conversation, gone).unwrap()["text"],
        "esto desaparece"
    );

    // B2 goes away, and A2 hasn't taken anything yet. A1 deletes the message, and B1 sees it go.
    let seq = delete(&mut server, &mut a1, conversation, gone);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(message(&mut b1, conversation, gone), None);

    // Back, B2 takes the deletion from the queue, and A2 the message and its deletion at once.
    let taken = server.deliver(&mut b2);
    assert_eq!(results(&taken), [json!([seq, "delete", "applied", null])]);
    let taken = server.deliver(&mut a2);
    assert_eq!(
        results(&taken),
        [
            json!([3, "message", "applied", null]),
            json!([seq, "delete", "applied", null])
        ]
    );
    for device in [&mut a2, &mut b2] {
        assert_eq!(message(device, conversation, gone), None);
        assert_eq!(
            found(device, json!({"text": "desaparece"})),
            Vec::<Uuid>::new()
        );
        assert_eq!(stored(device, gone), (None, None));
    }
}

#[test]
fn decrypt_and_store_commit_together() {
    let (mut server, conversation, _, [mut a1, mut b1]) = dm();
    let said = say(&mut server, &mut a1, conversation, "una sola oportunidad");
    let entry = server.entries(conversation)[2].clone();
    assert_eq!(entry["kind"], "message");

    // B1 decrypts the message, but its command fails before it commits: nothing of it stays, the
    // key OpenMLS used and dropped included.
    b1.core.fail_next_commit();
    let failed = error(
        &mut b1.core,
        apply(conversation, std::slice::from_ref(&entry)),
    );
    assert_eq!(failed["code"], "internal");
    assert_eq!(messages_of(&mut b1, conversation), Vec::<Value>::new());
    assert_eq!(b1.group(conversation)["epoch"], 1);

    // Taken again, the entry decrypts again.
    let taken = ok(
        &mut b1.core,
        apply(conversation, std::slice::from_ref(&entry)),
    );
    assert_eq!(results(&[taken]), [json!([3, "message", "applied", null])]);
    let shown = message(&mut b1, conversation, said).unwrap();
    assert_eq!(shown["text"], "una sola oportunidad");

    // Kept, its key is gone: the same ciphertext under the next number can't be opened again.
    let mut again = entry;
    again["seq"] = json!(4);
    let replayed = ok(&mut b1.core, apply(conversation, &[again]));
    assert_eq!(
        results(&[replayed]),
        [json!([4, "message", "undecryptable", "message"])]
    );
    assert_eq!(messages_of(&mut b1, conversation).len(), 1);
}

#[test]
fn ciphertext_over_32_kib_is_too_large() {
    let (mut server, conversation, [a, _], [mut a1, mut b1]) = dm();

    // An envelope that fits in 32 KiB whose ciphertext doesn't.
    let text = "a".repeat(MAX_ENVELOPE - 64);
    let envelope = Envelope::Message {
        text: Some(text.clone()),
        attachments: Vec::new(),
    };
    assert!(envelope.encode().unwrap().len() <= MAX_ENVELOPE);
    let refused = error(
        &mut a1.core,
        encrypt(conversation, "big", json!({"text": text})),
    );
    assert_eq!(
        (&refused["code"], &refused["limit"]),
        (&json!("too_large"), &json!(MAX_CIPHERTEXT))
    );

    // Nothing of it was kept: the nonce is free, and what fits goes.
    assert_eq!(messages_of(&mut a1, conversation), Vec::<Value>::new());
    let fits = ok(
        &mut a1.core,
        encrypt(conversation, "big", json!({"text": "cabe"})),
    );
    assert!(bytes(&fits["ciphertext"]).len() <= MAX_CIPHERTEXT);

    // An envelope over 32 KiB is refused before anything is encrypted.
    let refused = error(
        &mut a1.core,
        encrypt(
            conversation,
            &new_nonce(),
            json!({"text": "a".repeat(MAX_ENVELOPE)}),
        ),
    );
    assert_eq!(
        (&refused["code"], &refused["limit"]),
        (&json!("too_large"), &json!(MAX_CIPHERTEXT))
    );

    // A message the server hands over beyond 32 KiB isn't read: it waits, as one that can't be.
    let (huge, seq) =
        server.post_message(&a1, conversation, "huge", vec![0; MAX_CIPHERTEXT + 1], &[]);
    let taken = server.deliver(&mut b1);
    assert_eq!(
        results(&taken),
        [json!([seq, "message", "undecryptable", "too_large"])]
    );
    let shown = message(&mut b1, conversation, huge).unwrap();
    assert_eq!(shown["status"], "waiting");
    assert_eq!(shown["user_id"], json!(a));
    assert_eq!(shown["text"], Value::Null);
}

#[test]
fn a_proposal_passed_off_as_a_message_is_refused() {
    let (mut server, conversation, _, [mut a1, b1]) = dm();

    // The API proposes removing B1's leaf; a server hands the same proposal again as a message.
    server.remove_device(conversation, b1.id);
    let proposal = server.entries(conversation)[2].clone();
    assert_eq!(proposal["kind"], "proposal");
    let seq = server.force(conversation, "message", bytes(&proposal["data"]));

    // A1 takes the proposal, and refuses the message, which isn't one, without stopping its queue.
    let taken = server.deliver(&mut a1);
    assert_eq!(
        results(&taken),
        [
            json!([3, "proposal", "applied", null]),
            json!([seq, "message", "rejected", "malformed"])
        ]
    );
    assert_eq!(taken[0]["applied_through"], json!(seq));
    assert_eq!(messages_of(&mut a1, conversation), Vec::<Value>::new());
}

#[test]
fn search_finds_words_without_accents() {
    let (mut server, conversation, [a, b], [mut a1, mut a2, mut b1, mut b2]) = group_of_four();
    let start = server.clock.now_ms();
    let song = say(
        &mut server,
        &mut a1,
        conversation,
        &format!("Una canción para <@{b}>"),
    );
    server.clock.advance(60_000);
    let reply = send(
        &mut server,
        &mut b1,
        conversation,
        json!({"text": "la cancion sin tilde"}),
        &[a],
    );
    server.clock.advance(60_000);
    let photo = send(
        &mut server,
        &mut a2,
        conversation,
        json!({"text": "foto de la Canción", "attachments": [file("canción.png", "image/png")]}),
        &[],
    );
    server.clock.advance(60_000);
    let pdf = send(
        &mut server,
        &mut a1,
        conversation,
        json!({"attachments": [file("letra.pdf", "application/pdf")]}),
        &[],
    );
    let unrelated = say(&mut server, &mut b2, conversation, "nada que ver");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    for device in [&mut a1, &mut b1] {
        // With its accent or without, in any case, whole or begun.
        for text in ["canción", "cancion", "CANCIÓN", "canc"] {
            assert_eq!(
                found(device, json!({"text": text})),
                [photo, reply, song],
                "{text}"
            );
        }
        // Every word has to be there.
        assert_eq!(found(device, json!({"text": "cancion tilde"})), [reply]);
        // from: who wrote it.
        assert_eq!(
            found(device, json!({"text": "cancion", "from": [b]})),
            [reply]
        );
        // mentions: in the text, or in the list its sender gave the API.
        assert_eq!(found(device, json!({"mentions": [b]})), [song]);
        assert_eq!(found(device, json!({"mentions": [a]})), [reply]);
        // has: an image, or any file.
        assert_eq!(found(device, json!({"has": ["image"]})), [photo]);
        assert_eq!(found(device, json!({"has": ["file"]})), [pdf, photo]);
        assert_eq!(
            found(device, json!({"has": ["audio", "video"]})),
            Vec::<Uuid>::new()
        );
        // after and before: from one, up to the other.
        assert_eq!(
            found(
                device,
                json!({"text": "cancion", "after": start + 60_000, "before": start + 120_000})
            ),
            [reply]
        );
        // conversation_id: one conversation's.
        assert_eq!(
            found(
                device,
                json!({"text": "nada", "conversation_id": conversation})
            ),
            [unrelated]
        );
        assert_eq!(
            found(device, json!({"text": "nada", "conversation_id": new_id()})),
            Vec::<Uuid>::new()
        );
    }

    // The count is of every result; the page is limit and offset.
    let page = search(&mut b2, json!({"text": "cancion", "limit": 1, "offset": 1}));
    assert_eq!(page["total"], 3);
    let shown = page["messages"].as_array().unwrap();
    assert_eq!(shown.len(), 1);
    assert_eq!(shown[0]["message_id"], json!(reply));
    assert_eq!(shown[0]["text"], "la cancion sin tilde");

    // A deleted message isn't found.
    delete(&mut server, &mut a1, conversation, song);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    for device in [&mut a1, &mut b2] {
        assert_eq!(found(device, json!({"text": "canción"})), [photo, reply]);
        assert_eq!(found(device, json!({"mentions": [b]})), Vec::<Uuid>::new());
    }
}

#[test]
fn undecryptable_message_waits_until_imported() {
    let (mut server, conversation, [a, _], [mut a1, mut b1]) = dm();
    let late = say(&mut server, &mut a1, conversation, "llega tarde");
    server.deliver(&mut a1);

    // The server hands B1 a copy it can't read: B1 keeps the message as waiting, with its ID and
    // its sender, as the API gives them.
    let mut copy = server.entries(conversation)[2].clone();
    let mut data = bytes(&copy["data"]);
    *data.last_mut().unwrap() ^= 1;
    copy["data"] = json!(b64(&data));
    let taken = ok(&mut b1.core, apply(conversation, &[copy]));
    assert_eq!(
        results(&[taken]),
        [json!([3, "message", "undecryptable", "message"])]
    );
    let shown = message(&mut b1, conversation, late).unwrap();
    assert_eq!(shown["status"], "waiting");
    assert_eq!(shown["user_id"], json!(a));
    assert_eq!(shown["text"], Value::Null);
    assert_eq!(found(&mut b1, json!({"from": [a]})), Vec::<Uuid>::new());

    // A1 edits it meanwhile. B1 reads the edit, which waits for its message.
    let seq = edit(
        &mut server,
        &mut a1,
        conversation,
        late,
        "llega tarde, editado",
    );
    server.deliver(&mut a1);
    let edit_entry = server.entries(conversation)[3].clone();
    let taken = ok(&mut b1.core, apply(conversation, &[edit_entry]));
    assert_eq!(results(&[taken]), [json!([seq, "edit", "applied", null])]);
    assert_eq!(
        message(&mut b1, conversation, late).unwrap()["status"],
        "waiting"
    );

    // What A1 has of the conversation, as a backup or a history share carries it: B1's import
    // replaces the waiting message, with its edit, marked as shared by A.
    let records = a1
        .core
        .transaction(|tx| messages::records_for(tx, conversation, 0, i64::MAX))
        .unwrap();
    let kinds: Vec<RecordKind> = records.iter().map(|record| record.kind).collect();
    assert_eq!(kinds, [RecordKind::Message, RecordKind::Edit]);
    assert!(records.iter().all(|record| record.id == late));
    let import = |device: &mut TestDevice| {
        device
            .core
            .transaction(|tx| messages::import(tx, conversation, &records, Some(a)))
            .unwrap()
    };
    assert_eq!(import(&mut b1), 1);
    let shown = message(&mut b1, conversation, late).unwrap();
    assert_eq!(shown["status"], "ok");
    assert_eq!(shown["text"], "llega tarde, editado");
    assert_eq!(shown["shared_by"], json!(a));
    assert!(shown["edited_at"].is_i64());
    assert_eq!(found(&mut b1, json!({"text": "editado"})), [late]);

    // An import never overwrites what's there.
    assert_eq!(import(&mut b1), 0);

    // Nor does it bring back a message deleted since.
    delete(&mut server, &mut a1, conversation, late);
    server.deliver(&mut a1);
    let deletion = server.entries(conversation)[4].clone();
    ok(&mut b1.core, apply(conversation, &[deletion]));
    assert_eq!(import(&mut b1), 0);
    assert_eq!(message(&mut b1, conversation, late), None);
    assert_eq!(stored(&mut b1, late), (None, None));
}

#[test]
fn deviceless_member_gets_catch_up_due() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1] = new_devices(&mut server, [a]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    // A makes the group with B, who has no device yet: none of B's enters.
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

    // Only a member who isn't this device's own user can be without devices.
    let stranger = error(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [new_id()]}),
    );
    assert_eq!(
        (&stranger["code"], &stranger["what"]),
        (&json!("not_found"), &json!("member"))
    );
    let own = error(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [a]}),
    );
    assert_eq!(
        (&own["code"], &own["field"]),
        (&json!("bad_command"), &json!("users"))
    );

    // A1's client knows from the API that B has no device: what A1 sends now is noted for B.
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    let first = say(&mut server, &mut a1, conversation, "para cuando llegues");
    let second = say(&mut server, &mut a1, conversation, "y esto también");
    let taken = server.deliver(&mut a1);
    assert_eq!(taken[0]["catch_up_due"], json!([]));

    // B's first device enters by external commit. A1, once it knows B, takes it: B is due the
    // catch-up.
    let mut b1 = server.device(b);
    server.introduce(&mut b1);
    server
        .commit(&mut b1, conversation, joining(&server, conversation))
        .unwrap();
    server.introduce(&mut a1);
    let taken = server.deliver(&mut a1);
    assert_eq!(results(&taken), [json!([4, "commit", "applied", null])]);
    assert_eq!(taken[0]["catch_up_due"], json!([b]));
    let noted = |device: &mut TestDevice| -> Vec<Uuid> {
        device
            .core
            .transaction(|tx| messages::noted_records(tx, conversation, b))
            .unwrap()
            .iter()
            .map(|record| record.id)
            .collect()
    };
    assert_eq!(noted(&mut a1), [first, second]);

    // B's device reads what A1 sends from now on: nothing more is noted, and B stays due until
    // the catch-up is made.
    say(&mut server, &mut a1, conversation, "ya estás");
    let taken = server.deliver(&mut a1);
    assert_eq!(taken[0]["catch_up_due"], json!([b]));
    assert_eq!(noted(&mut a1), [first, second]);

    a1.core
        .transaction(|tx| messages::forget_noted(tx, conversation, b))
        .unwrap();
    let after = ok(&mut a1.core, apply(conversation, &[]));
    assert_eq!(after["catch_up_due"], json!([]));
}

#[test]
fn catch_up_is_for_the_identity_pinned_when_noted() {
    let (mut server, conversation, [_, b], [mut a1, b1]) = dm();

    // B1 logs out: the API proposes its removal, which A1 commits before it sends anything.
    server.remove_device(conversation, b1.id);
    server.deliver(&mut a1);
    let waits = error(
        &mut a1.core,
        encrypt(conversation, &new_nonce(), json!({"text": "todavía no"})),
    );
    assert_eq!(waits["code"], "pending_proposals");
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver(&mut a1);

    // B has no device left. A1 notes what it sends for B, under the identity it pinned for B.
    ok(
        &mut a1.core,
        json!({"cmd": "without_devices", "conversation_id": conversation, "users": [b]}),
    );
    say(
        &mut server,
        &mut a1,
        conversation,
        "para la identidad de antes",
    );

    // B starts over, with a new identity, which A1 sees; what A1 sends now is noted under it.
    server.forget_user(b);
    let mut b2 = server.device(b);
    server.introduce(&mut b2);
    assert_eq!(ok(&mut a1.core, server.observed(b))["state"], "changed");
    let later = say(
        &mut server,
        &mut a1,
        conversation,
        "para la identidad nueva",
    );
    server.deliver(&mut a1);

    // B2 enters: only what A1 sent under the identity B2's leaf has is due to it.
    server
        .commit(&mut b2, conversation, joining(&server, conversation))
        .unwrap();
    let taken = server.deliver(&mut a1);
    assert_eq!(taken[0]["catch_up_due"], json!([b]));
    let noted: Vec<Uuid> = a1
        .core
        .transaction(|tx| messages::noted_records(tx, conversation, b))
        .unwrap()
        .iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(noted, [later]);
}
