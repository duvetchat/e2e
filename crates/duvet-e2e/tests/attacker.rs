//! The server as an attacker, through `Core::handle`, against the fake of the API: the moves the
//! plan's «Pruebas que corren siempre» list. The server adds a device its user never signed, and a
//! member without the owner's commit; it makes up deletions; it replays old commits and an old list
//! of a user's devices; it leaves a pending removal out; it changes ciphertext; it turns end-to-end
//! encryption off; and it guesses at a new device's approval code. It also plants a member at the
//! cutover and hands out a backup from before a deletion, and a member forges a share. The server is
//! `FakeServer` skipping its validator (`force`) or changing what it hands out; the clients, cores
//! driven through their commands, refuse each move. Where a client can't, the test pins the limit,
//! and its doc comment says so.

mod support;

use std::collections::BTreeSet;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e::history::{self, Header, ShareKind};
use duvet_e2e::messages::{Record, RecordKind};
use duvet_e2e::{Clock, Envelope, mls};
use duvet_e2e_rules::{
    CommitAad, DeviceCertificate, DeviceList, Entry as ListEntry, Kind, MemberList, SUITE,
    group_id, join_config, leaf_capabilities,
};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, CredentialWithKey, ExternalProposal, GroupEpoch, GroupId, KeyPackage,
    KeyPackageIn, LeafNodeParameters, MlsGroup, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    OpenMlsProvider, OpenMlsRand, ProtocolVersion, SenderExtensionIndex, SignatureScheme,
    WireFormat,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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
fn start(server: &mut FakeServer, creator: &mut TestDevice, conversation: Uuid) -> Value {
    let command = server.create_group(conversation);
    server
        .commit(creator, conversation, command)
        .expect("the server takes epoch 0")
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

/// What `encrypt` checks before it encrypts: whether the device may send now.
fn ready(device: &mut TestDevice, conversation: Uuid) -> Result<(), Value> {
    device
        .core
        .transaction(|tx| mls::ready_to_send(tx, conversation))
        .map_err(|error| error.to_reply()["error"].clone())
}

/// `device` encrypts `text` under a new nonce: the nonce and the ciphertext.
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

/// `device` posts what it encrypted under `nonce`, and hears the API's answer: the message's ID and
/// number.
fn post(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    (nonce, ciphertext): (String, Vec<u8>),
) -> (Uuid, u64) {
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
    let message = encrypted(device, conversation, text);
    post(server, device, conversation, message)
}

/// `device` deletes its message `message_id` for everyone, and posts the deletion: its number.
fn delete(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    message_id: Uuid,
) -> u64 {
    let deleted = ok(
        &mut device.core,
        json!({"cmd": "delete", "conversation_id": conversation, "message_id": message_id}),
    );
    server.post_change(
        device,
        conversation,
        "delete",
        message_id,
        bytes(&deleted["ciphertext"]),
    )
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

/// The IDs of the messages `device` shows, newest first.
fn shown_ids(device: &mut TestDevice, conversation: Uuid) -> Vec<Uuid> {
    messages_of(device, conversation)
        .iter()
        .map(|shown| shown["message_id"].as_str().unwrap().parse().unwrap())
        .collect()
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

/// The entry `seq` of `conversation`'s queue, as the server keeps it.
fn queued(server: &mut FakeServer, conversation: Uuid, seq: u64) -> &mut QueueEntry {
    let queue = &mut server.chats.get_mut(&conversation).unwrap().queue;
    &mut queue[usize::try_from(seq).unwrap() - 1]
}

/// The entry `seq` of `conversation`'s queue, as the API hands it out.
fn entry(server: &FakeServer, conversation: Uuid, seq: u64) -> Value {
    server.entries(conversation)[usize::try_from(seq).unwrap() - 1].clone()
}

/// An attacker server takes the commit `device` made (`reply`) past its validator, with its
/// welcome, and answers it as taken: the commit's number in the queue.
fn take_unchecked(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    reply: &Value,
) -> u64 {
    let seq = server.force(conversation, "commit", bytes(&reply["commit"]));
    if let Some(welcome) = reply.get("welcome").and_then(Value::as_str) {
        let welcome = STANDARD.decode(welcome).unwrap();
        server.force(conversation, "welcome", welcome);
    }
    ok(
        &mut device.core,
        json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": seq}),
    );
    seq
}

/// `device` applies `entries` as its client does: when its core asks to observe some users first,
/// the client observes them as `served` gives them, and applies again. What each `observe_user`
/// answered, and the last `apply`'s reply.
fn apply_observing(
    device: &mut TestDevice,
    conversation: Uuid,
    entries: &[Value],
    served: impl Fn(Uuid) -> Value,
) -> (Vec<Value>, Value) {
    let mut observed = Vec::new();
    loop {
        let reply = run(&mut device.core, &apply(conversation, entries));
        let Some(asked) = reply.get("error") else {
            return (observed, reply["ok"].clone());
        };
        assert_eq!(asked["code"], "needs_identities", "{reply}");
        assert!(observed.len() < 3, "asked again and again: {observed:?}");
        for user in asked["users"].as_array().unwrap() {
            let user: Uuid = user.as_str().unwrap().parse().unwrap();
            observed.push(ok(&mut device.core, served(user))["state"].clone());
        }
    }
}

/// `entry` with one byte of its MLS message changed, at `position`.
fn changed_at(entry: &Value, position: usize) -> Value {
    let mut data = bytes(&entry["data"]);
    data[position] ^= 0x01;
    let mut changed = entry.clone();
    changed["data"] = json!(b64(&data));
    changed
}

/// An external commit `device` makes outside its core, from its own keys and `group_info`: the
/// commit and the group info of the epoch it makes.
fn external_commit_by_hand(device: &mut TestDevice, group_info: &str) -> (Vec<u8>, Vec<u8>) {
    let own = device.rolled_back(|tx| tx.own_device());
    let provider = OpenMlsRustCrypto::default();
    let message = MlsMessageIn::tls_deserialize_exact_bytes(&STANDARD.decode(group_info).unwrap());
    let MlsMessageBodyIn::GroupInfo(info) = message.unwrap().extract() else {
        panic!("not a group info");
    };
    let (_, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .with_aad(CommitAad::new(Vec::new()).encode())
        .build_group(&provider, info, own.credential().unwrap())
        .unwrap()
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(leaf_capabilities())
                .build(),
        )
        .load_psks(provider.storage())
        .unwrap()
        .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
        .unwrap()
        .finalize(&provider)
        .unwrap();
    let info = MlsMessageOut::from(bundle.group_info().unwrap().clone());
    (
        bundle.commit().tls_serialize_detached().unwrap(),
        info.tls_serialize_detached().unwrap(),
    )
}

/// A key pair the server made, standing in for an identity or a device's key.
fn server_key() -> SignatureKeyPair {
    SignatureKeyPair::new(SignatureScheme::ED25519).unwrap()
}

/// A key package of `device`, a device the server made up for `user`, under a certificate
/// `forger` signed in place of the user's identity.
fn forged_key_package(user: Uuid, device: Uuid, forger: &SignatureKeyPair) -> KeyPackage {
    let provider = OpenMlsRustCrypto::default();
    let leaf = server_key();
    let certificate =
        DeviceCertificate::new(user, device, leaf.public().try_into().unwrap(), [9; 32], 1)
            .sign(forger)
            .unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(certificate).into(),
        signature_key: leaf.public().into(),
    };
    KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities())
        .build(SUITE, &provider, &leaf, credential)
        .unwrap()
        .key_package()
        .clone()
}

/// A proposal the server signs with its key, as the groups' external sender, for `conversation`'s
/// first generation at `epoch`: `make` builds it from the group's ID, the epoch, the key and the
/// server's place among the external senders.
fn server_proposal(
    server: &FakeServer,
    conversation: Uuid,
    epoch: u64,
    make: impl FnOnce(GroupId, GroupEpoch, &SignatureKeyPair, SenderExtensionIndex) -> MlsMessageOut,
) -> Vec<u8> {
    let signer = server.api_signer();
    make(
        group_id(conversation, 0),
        GroupEpoch::from(epoch),
        &signer,
        SenderExtensionIndex::new(0),
    )
    .tls_serialize_detached()
    .unwrap()
}

/// The devices of `device`'s group of `conversation`.
fn device_set(device: &mut TestDevice, conversation: Uuid) -> BTreeSet<Uuid> {
    devices(&device.group(conversation)).into_iter().collect()
}

/// The server adds a device of B's that B's identity never signed: it hands its key package to the
/// owner who makes the group, beside a key package of B's second device whose certificate it
/// forged; it proposes it as the groups' external sender; and it lets it in by its own external
/// commit. Each device takes a leaf only under a certificate its user's pinned identity signed, for
/// a device on that user's latest signed list: the owner's core leaves both forgeries out, and the
/// members refuse the proposal and the commit. A server that also serves another identity for B
/// makes an identity change, which `observe_user` reports (`changed`) and safety numbers show.
#[test]
fn server_adds_unsigned_device() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    // B's second device, on B's list, whose key packages never reach the server.
    let b2 = server.virtual_device(b);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut b1] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    let forger = server_key();

    // The server hands A1, for B, B1's key package, one it forged for B2, and one of a device it
    // made up. A1 brings B1 alone, and says B2 had no key package it could take.
    let planted = forged_key_package(b, new_id(), &forger);
    let mut create = server.create_group(conversation);
    for forged in [forged_key_package(b, b2, &forger), planted.clone()] {
        create["key_packages"][b.to_string().as_str()]
            .as_array_mut()
            .unwrap()
            .push(json!(b64(&forged.tls_serialize_detached().unwrap())));
    }
    let created = server.commit(&mut a1, conversation, create).unwrap();
    assert_eq!(
        created["skipped_devices"],
        json!([{"user_id": b, "device_id": b2}])
    );
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(
        device_set(&mut a1, conversation),
        BTreeSet::from([a1.id, b1.id])
    );

    // The server proposes adding its device, as the groups' external sender: refused, and the
    // group goes on as it was.
    let proposal = server_proposal(&server, conversation, 1, |group, epoch, signer, sender| {
        ExternalProposal::new_add::<OpenMlsRustCrypto>(planted, group, epoch, signer, sender)
            .unwrap()
    });
    let seq = server.force(conversation, "proposal", proposal);
    for device in [&mut a1, &mut b1] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [json!([
                seq,
                "proposal",
                "rejected",
                "server_proposal_not_remove"
            ])]
        );
        assert_eq!(ready(device, conversation), Ok(()));
    }

    // A device of the server's, under a certificate it forged for its own keys, joins by an
    // external commit it makes outside any core. Each member first asks to observe B, then refuses
    // the leaf, which B's identity never signed: the group stays where it was, blocked until a
    // reset.
    let mut intruder = server.bare_device(b);
    let (signature_key, hpke_key) = intruder.rolled_back(|tx| {
        let own = tx.own_device()?;
        Ok((own.signer.public().to_vec(), own.hpke.public.clone()))
    });
    let certificate = DeviceCertificate::new(
        b,
        intruder.id,
        signature_key.try_into().unwrap(),
        hpke_key.try_into().unwrap(),
        1,
    )
    .sign(&forger)
    .unwrap();
    intruder
        .core
        .transaction(|tx| {
            tx.conn()
                .execute("UPDATE device SET certificate = ?1", [&certificate])?;
            Ok(())
        })
        .unwrap();
    let (commit, info) = external_commit_by_hand(&mut intruder, &server.group_info(conversation));
    assert_eq!(
        server
            .check(conversation, &commit, &info)
            .error
            .unwrap()
            .code,
        "leaf_not_signed",
        "the validator the server skips"
    );
    let seq = server.force(conversation, "commit", commit);
    let forced = entry(&server, conversation, seq);
    for device in [&mut a1, &mut b1] {
        let (observed, refused) = apply_observing(
            device,
            conversation,
            std::slice::from_ref(&forced),
            |user| server.observed(user),
        );
        assert_eq!(observed, [json!("same")]);
        assert_eq!(
            results(&[refused]),
            [json!([seq, "commit", "rejected", "leaf_not_signed"])]
        );
        let state = device.group(conversation);
        assert_eq!(
            (&state["epoch"], &state["blocked"]),
            (&json!(1), &json!(true))
        );
        assert!(!devices(&state).contains(&intruder.id));
    }
}

/// The server adds C to A's group without a commit of A's, the owner: it proposes C's device as the
/// groups' external sender, proposes a member list with C in it, and lets C in by an external
/// commit C makes outside its core. The members refuse each: the server proposes removals alone,
/// and only the owner's commit adds a user. A non-owner member's commit that adds C, taken past the
/// validator, is refused the same way (`groups.rs`, `invalid_commit_blocks_and_reset_recovers`).
#[test]
fn server_adds_member_without_owner_commit() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // An Add of C1's own key package, proposed by the server.
    let claimed = server.claim(&[c]);
    let key_package = bytes(&claimed[c.to_string().as_str()][0]);
    let key_package = KeyPackageIn::tls_deserialize_exact_bytes(&key_package)
        .unwrap()
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .unwrap();
    let add = server_proposal(&server, conversation, 1, |group, epoch, signer, sender| {
        ExternalProposal::new_add::<OpenMlsRustCrypto>(key_package, group, epoch, signer, sender)
            .unwrap()
    });
    // The group's context with C on its member list, proposed by the server.
    let context = a1.rolled_back(|tx| {
        let (group, _) = mls::load_group(tx, conversation)?;
        Ok(group.public_group().group_context().clone())
    });
    let mut list = MemberList::from_group_context(&context).unwrap();
    list.users.push(ListEntry {
        user: c,
        generation: 0,
        epoch: 2,
    });
    let mut extensions = context.extensions().clone();
    extensions.add_or_replace(list.to_extension()).unwrap();
    let listed = server_proposal(&server, conversation, 1, |group, epoch, signer, sender| {
        ExternalProposal::new_group_context_extensions::<OpenMlsRustCrypto>(
            extensions, group, epoch, signer, sender,
        )
        .unwrap()
    });
    let add_seq = server.force(conversation, "proposal", add);
    let list_seq = server.force(conversation, "proposal", listed);
    for device in [&mut a1, &mut b1] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [
                json!([
                    add_seq,
                    "proposal",
                    "rejected",
                    "server_proposal_not_remove"
                ]),
                json!([
                    list_seq,
                    "proposal",
                    "rejected",
                    "server_proposal_not_remove"
                ]),
            ]
        );
    }
    // Nothing of them waits for a commit: the next one, A1's renewal, carries none, and C isn't in.
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(members(&state), [a, b]);
    assert_eq!(state["epoch"], 2);

    // C's own core won't join a group whose list doesn't have C. The commit C makes outside it,
    // which the server takes past its validator, every member refuses.
    let refused = error(&mut c1.core, joining(&server, conversation));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("user_not_member"))
    );
    let (commit, _) = external_commit_by_hand(&mut c1, &server.group_info(conversation));
    let seq = server.force(conversation, "commit", commit);
    for device in [&mut a1, &mut b1] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [json!([seq, "commit", "rejected", "user_not_member"])]
        );
        let state = device.group(conversation);
        assert_eq!(members(&state), [a, b]);
        assert_eq!(state["epoch"], 2);
    }
}

/// The server makes up deletions of A's messages: one with no MLS message behind it, A's own
/// deletion of one message relabeled as another's, a message of A's relabeled as a deletion, a
/// deletion handed out again, and B's deletion of its own message passed off as A's of another. A
/// deletion counts for what its envelope names, which only its sender's leaf could seal, and from
/// its message's author alone (a member's own forgery: `messages.rs`,
/// `edit_and_delete_from_the_author_only`): each device deletes what A and B deleted, and nothing
/// else.
///
/// The one way the server makes a device hold less is `backup_import`'s `deleted`, the IDs the
/// client takes from the API, which erase those messages where the device holds them: as ruled
/// with the backup, the plan lets a server make a device delete more, as it can withhold the queue.
#[test]
fn server_forges_delete() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1] = new_devices(&mut server, [a, a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let (first, _) = say(&mut server, &mut a1, conversation, "la primera");
    let (second, _) = say(&mut server, &mut a1, conversation, "la segunda");
    let (theirs, _) = say(&mut server, &mut b1, conversation, "la de B");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A deletion the server made up: no MLS message is behind it.
    let made_up = OpenMlsRustCrypto::default().rand().random_vec(200).unwrap();
    let seq = server.post_change(&a1, conversation, "delete", first, made_up);
    for device in [&mut a2, &mut b1] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [json!([seq, "delete", "undecryptable", "message"])]
        );
    }

    // A1 deletes its second message, and the server labels the deletion as the first's.
    let relabeled = delete(&mut server, &mut a1, conversation, second);
    queued(&mut server, conversation, relabeled)
        .meta
        .insert("message_id".into(), json!(first));
    // A message of A1's, handed out as a deletion of the first.
    let (fourth, passed_off) = say(&mut server, &mut a1, conversation, "no borra nada");
    let disguise = queued(&mut server, conversation, passed_off);
    disguise.kind = "delete";
    disguise.meta.insert("message_id".into(), json!(first));
    // B1 deletes its own message, and the server hands the deletion out as A1's, of the first.
    let disguised = delete(&mut server, &mut b1, conversation, theirs);
    let disguise = queued(&mut server, conversation, disguised);
    for (field, value) in [
        ("message_id", json!(first)),
        ("sender_user", json!(a)),
        ("sender_device", json!(a1.id)),
    ] {
        disguise.meta.insert(field.into(), value);
    }
    // A1's deletion again, under a new number.
    let again = queued(&mut server, conversation, relabeled).clone();
    let replayed = server.force(conversation, "delete", again.data);
    queued(&mut server, conversation, replayed).meta = again.meta;

    // A2 and B1 delete A's second message and B's own, as their authors did, and nothing else: the
    // message A1 sent deletes nothing (its label names a message they hold, so it's taken for
    // nothing), and the deletion handed out again has no key left to open with.
    for (device, b_own) in [(&mut a2, "applied"), (&mut b1, "own")] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [
                json!([relabeled, "delete", "applied", null]),
                json!([passed_off, "delete", "ignored", null]),
                json!([disguised, "delete", b_own, null]),
                json!([replayed, "delete", "undecryptable", "message"]),
            ]
        );
        assert_eq!(shown_ids(device, conversation), [first]);
        assert_eq!(
            message(device, conversation, first).unwrap()["text"],
            "la primera"
        );
    }
    server.deliver(&mut a1);
    assert_eq!(shown_ids(&mut a1, conversation), [fourth, first]);
}

/// The server replays old commits under new numbers: the one that added C, the one that removed C,
/// the group's first and the latest. A device behind takes them after the commits themselves, one
/// is handed again under its own number, and C's device gets its old welcome again. A commit counts
/// only at the epoch it was made for, and a welcome only to an epoch its device never saw pass:
/// each device skips the replays, without blocking, C stays out, and the group goes on.
#[test]
fn server_replays_old_commit() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut c1] = new_devices(&mut server, [a, a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A adds C (whose last-resort key package the welcome doesn't use up), then removes C; B1
    // renews its leaf. A2 takes nothing meanwhile.
    let mut add = adding(&mut server, conversation, c);
    add["users"][0]["key_packages"] = json!([server.last_resort(c1.id)]);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [c]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    assert_eq!(c1.no_group(conversation)["what"], "membership");
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let entries = server.entries(conversation);
    let kinds: Vec<&Value> = entries.iter().map(|entry| &entry["kind"]).collect();
    assert_eq!(
        kinds,
        ["commit", "welcome", "commit", "welcome", "commit", "commit"]
    );

    // The commit that added C, the one that removed C, the first and the latest, each again.
    let replays: Vec<u64> = [3, 5, 1, 6]
        .into_iter()
        .map(|seq| server.force(conversation, "commit", bytes(&entries[seq - 1]["data"])))
        .collect();
    let skipped: Vec<Value> = replays
        .iter()
        .map(|seq| json!([seq, "commit", "ignored", null]))
        .collect();
    for device in [&mut a1, &mut b1] {
        assert_eq!(results(&server.deliver(device)), skipped);
    }
    // A2, behind, takes its welcome and every commit once, at its epoch; C's welcome and the
    // replays it skips.
    let taken = results(&server.deliver(&mut a2));
    let outcomes: Vec<&Value> = taken.iter().map(|result| &result[2]).collect();
    assert_eq!(
        outcomes,
        [
            "applied", "applied", "ignored", "applied", "applied", "ignored", "ignored", "ignored",
            "ignored"
        ]
    );
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1], conversation);
    assert_eq!(state["epoch"], 4);
    assert_eq!(state["blocked"], false);
    assert_eq!(members(&state), [a, b]);
    assert!(!devices(&state).contains(&c1.id));

    // One handed again under its own number is a number already applied: skipped, without an
    // effect.
    let mut own_number = entries[4].clone();
    own_number["data"] = entries[2]["data"].clone();
    let skipped = ok(&mut a2.core, apply(conversation, &[own_number]));
    assert_eq!(skipped["results"], json!([]));
    assert_eq!(a2.group(conversation)["epoch"], 4);

    // C1, out since its removal, takes the replays and its old welcome again: none brings it back.
    let welcome = server.force(conversation, "welcome", bytes(&entries[3]["data"]));
    let taken = results(&server.deliver(&mut c1));
    assert_eq!(
        taken.last().unwrap(),
        &json!([welcome, "welcome", "rejected", "stale_welcome"])
    );
    assert!(
        taken[..taken.len() - 1]
            .iter()
            .all(|result| result[2] == "ignored"),
        "{taken:?}"
    );
    assert_eq!(c1.no_group(conversation)["what"], "membership");

    // The group goes on: what A1 writes now, A2 and B1 read, and C1 doesn't.
    let (said, _) = say(&mut server, &mut a1, conversation, "seguimos");
    for device in [&mut a2, &mut b1] {
        server.deliver(device);
        assert_eq!(
            message(device, conversation, said).unwrap()["text"],
            "seguimos"
        );
    }
    server.deliver(&mut c1);
    assert_eq!(message(&mut c1, conversation, said), None);
}

/// The server serves a user's list from before a device left it. A device that knows the newer
/// list refuses the older one (`older_list`), its own user's included, and keeps the newer one;
/// with it, it refuses a commit that brings the left device back, its own external commit included
/// (`device_not_listed`), whatever list the server serves then.
///
/// `recover`'s limit: a recovering device knows no list, takes the one the server serves, and signs
/// it with itself into the next one. Devices that know a newer list refuse what it signs, a version
/// they hold with other devices (`conflicting_list`); a contact that knew none of the user's lists
/// takes it, the left device on it, as a first contact takes what the server serves. Safety numbers
/// don't catch it: the identity is the user's.
#[test]
fn server_serves_old_device_list() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    let old = server.observed(a);
    let identity_key: [u8; 32] = bytes(&identity["identity_key"]).try_into().unwrap();

    // A loses A2: A1 takes it off A's list, B1 sees the new list, and A1 takes A2 out of the group.
    // A2, in other hands now, takes none of it.
    let list = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &list["device_list"]);
    server.introduce(&mut b1);
    let asked = ready(&mut a1, conversation).unwrap_err();
    assert_eq!(asked["code"], "needs_identities");
    ok(&mut a1.core, server.observed(a));
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    for device in [&mut a1, &mut b1] {
        assert!(!device_set(device, conversation).contains(&a2.id));
    }
    let newer = DeviceList::verify(&bytes(&list["device_list"]), &identity_key).unwrap();

    // The older list, served to B1 and to A1: refused, and the newer one stays.
    for device in [&mut b1, &mut a1] {
        let seen = ok(&mut device.core, old.clone());
        assert_eq!(
            (&seen["state"], &seen["reason"]),
            (&json!("rejected"), &json!("older_list"))
        );
        let kept = device.rolled_back(|tx| tx.device_list_of(a)).unwrap();
        assert_eq!(kept, newer);
    }

    // A2, which still holds the older list, joins by external commit; the server takes it past its
    // validator. B1 asks about A first, is served the older list again, and refuses the commit.
    let joined = ok(&mut a2.core, joining(&server, conversation));
    let commit = bytes(&joined["commit"]);
    assert_eq!(
        server
            .check(conversation, &commit, &bytes(&joined["group_info"]))
            .error
            .unwrap()
            .code,
        "device_not_listed",
        "the validator the server skips"
    );
    let seq = server.force(conversation, "commit", commit);
    let forced = entry(&server, conversation, seq);
    let (observed, refused) =
        apply_observing(&mut b1, conversation, std::slice::from_ref(&forced), |_| {
            old.clone()
        });
    assert_eq!(observed, [json!("rejected")]);
    assert_eq!(
        results(&[refused]),
        [json!([seq, "commit", "rejected", "device_not_listed"])]
    );
    assert!(!device_set(&mut b1, conversation).contains(&a2.id));

    // A new device of A's recovers with A's key against the older list: it signs that list, with
    // itself and A2, into the next version. A1 and B1, which hold that version with A1 alone,
    // refuse it.
    let mut a3 = server.bare_device(a);
    let recovered = ok(
        &mut a3.core,
        json!({
            "cmd": "recover",
            "recovery_key": identity["recovery_key"],
            "wrapped_backup_key": identity["wrapped_backup_key"],
            "encrypted_identity": identity["encrypted_identity"],
            "device_list": old["device_list"],
        }),
    );
    let signed = DeviceList::verify(&bytes(&recovered["device_list"]), &identity_key).unwrap();
    assert_eq!(signed.version, newer.version);
    assert!(signed.contains(a2.id) && signed.contains(a3.id));
    let mut served = old.clone();
    served["device_list"] = recovered["device_list"].clone();
    served["certificates"]
        .as_array_mut()
        .unwrap()
        .push(recovered["certificate"].clone());
    for device in [&mut a1, &mut b1] {
        let seen = ok(&mut device.core, served.clone());
        assert_eq!(
            (&seen["state"], &seen["reason"]),
            (&json!("rejected"), &json!("conflicting_list"))
        );
    }
    // The limit: C, who never saw A's lists, takes it.
    let mut c1 = server.device(c);
    let seen = ok(&mut c1.core, served);
    assert_eq!(seen, json!({"state": "new", "verified": false}));
    let taken = c1.rolled_back(|tx| tx.device_list_of(a)).unwrap();
    assert!(taken.contains(a2.id));
}

/// The API proposes removing A2, a device A took off its list, and an attacker server drops that
/// removal: it takes B1's commit that leaves it out past its validator, and proposes it no more.
/// Every device takes that commit (that a member's commit carries the pending removals is the
/// validator's rule alone), but A1, a device of A2's own user, sends nothing while A2's leaf is in:
/// it takes A2 out itself, as the list allows any member to, and what is sent after its commit A2
/// can't read.
///
/// The limit, as the contract has it: only a user's own devices hold their user's leaves to the
/// user's latest list. B1 knows A's newer list, yet sends while A2 is in, and A2 reads it; where a
/// lost device is its user's only one in the group, or the server refuses its user's devices'
/// commits, its removal waits for the server's proposal.
#[test]
fn server_drops_pending_removal() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1] = new_devices(&mut server, [a, a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A takes A2 off its list, which B1 sees. The API proposes A2's removal; B1 renews its leaf
    // before it hears of it, and the server takes that commit, which its validator refuses.
    let list = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &list["device_list"]);
    server.introduce(&mut b1);
    server.remove_device(conversation, a2.id);
    let made = ok(&mut b1.core, command("refresh", conversation));
    let check = server.check(
        conversation,
        &bytes(&made["commit"]),
        &bytes(&made["group_info"]),
    );
    assert_eq!(
        check.error.unwrap().code,
        "pending_removal_dropped",
        "the validator the server skips"
    );
    let dropped = take_unchecked(&mut server, &mut b1, conversation, &made);

    // A1 and A2 take the proposal, then the commit that left it out: A2 is still in.
    for device in [&mut a1, &mut a2] {
        let taken = server.deliver(device);
        assert_eq!(
            results(&taken),
            [
                json!([dropped - 1, "proposal", "applied", null]),
                json!([dropped, "commit", "applied", null]),
            ]
        );
    }
    for device in [&mut a1, &mut b1] {
        assert!(device_set(device, conversation).contains(&a2.id));
    }

    // The limit: B1 sends, and A2 reads it.
    assert_eq!(ready(&mut b1, conversation), Ok(()));
    let (meanwhile, _) = say(&mut server, &mut b1, conversation, "mientras tanto");
    server.deliver(&mut a2);
    assert_eq!(
        message(&mut a2, conversation, meanwhile).unwrap()["text"],
        "mientras tanto"
    );

    // A1 sends nothing while A2's leaf is in: it asks to observe its own user once, then takes A2
    // out with its own commit, which the server takes.
    let asked = ready(&mut a1, conversation).unwrap_err();
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a.to_string()]))
    );
    ok(&mut a1.core, server.observed(a));
    let wait = ready(&mut a1, conversation).unwrap_err();
    assert_eq!(wait["code"], "pending_proposals");
    let removal = ok(&mut a1.core, command("commit_pending", conversation));
    take_unchecked(&mut server, &mut a1, conversation, &removal);
    assert_eq!(ready(&mut a1, conversation), Ok(()));
    assert!(!device_set(&mut a1, conversation).contains(&a2.id));

    // A2 takes that commit once it observes A's list without it: its group is gone. What A1 and B1
    // send after it, A2 can't read.
    let (observed, _) = apply_observing(
        &mut a2,
        conversation,
        &server.entries(conversation),
        |user| server.observed(user),
    );
    assert_eq!(observed, [json!("same")]);
    assert_eq!(a2.no_group(conversation)["what"], "membership");
    server.deliver(&mut b1);
    let (from_a, _) = say(&mut server, &mut a1, conversation, "ya sin A2");
    let (from_b, _) = say(&mut server, &mut b1, conversation, "tampoco esto");
    ok(
        &mut a2.core,
        apply(conversation, &server.entries(conversation)),
    );
    for said in [from_a, from_b] {
        assert_eq!(message(&mut a2, conversation, said), None);
    }
    server.deliver(&mut b1);
    assert_eq!(
        message(&mut b1, conversation, from_a).unwrap()["text"],
        "ya sin A2"
    );
}

/// The server changes bytes of what it hands out: a message's ciphertext at every seventh byte and
/// at its last, a commit's and a welcome's. A message changed anywhere opens to nothing, and waits
/// as one that can't be read, never showing other text; the message as it was sent then fills it.
/// A changed commit is refused, and its group waits for a reset, as a server that withholds the
/// queue makes it wait; a changed welcome is refused, and the welcome as it was made then brings
/// its device in.
/// Every other format holds the same against changes: `formats.rs` (envelopes, attachments' parts,
/// messages between devices), `backup.rs` (segments) and `history.rs` (packages).
#[test]
fn server_changes_ciphertext() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut b2, mut c1] = new_devices(&mut server, [a, b, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // Messages of one length, whose ciphertexts have one length.
    let text = |position: usize| format!("el mensaje {position:04}");
    let (nonce, sample) = encrypted(&mut a1, conversation, &text(0));
    ok(&mut a1.core, json!({"cmd": "discard", "nonce": nonce}));
    let length = sample.len();

    // B1 is handed each message changed at one byte, then the message as A1 sent it, which the
    // server hands out again under the next number: B1's own count from here on.
    let mut b1_next = ok(&mut b1.core, apply(conversation, &[]))["applied_through"]
        .as_u64()
        .unwrap()
        + 1;
    let mut positions: Vec<usize> = (0..length).step_by(7).collect();
    positions.push(length - 1);
    for position in positions {
        let (message_id, seq) = say(&mut server, &mut a1, conversation, &text(position));
        let genuine = entry(&server, conversation, seq);
        assert_eq!(bytes(&genuine["data"]).len(), length);
        let mut changed = changed_at(&genuine, position);
        changed["seq"] = json!(b1_next);
        let taken = ok(&mut b1.core, apply(conversation, &[changed]));
        assert_ne!(
            taken["results"][0]["result"], "applied",
            "byte {position}: {taken}"
        );
        if let Some(shown) = message(&mut b1, conversation, message_id) {
            assert_eq!(
                (&shown["status"], &shown["text"]),
                (&json!("waiting"), &Value::Null),
                "byte {position}"
            );
        }
        let mut again = genuine;
        again["seq"] = json!(b1_next + 1);
        let taken = ok(&mut b1.core, apply(conversation, &[again]));
        assert_eq!(
            taken["results"][0]["result"], "applied",
            "byte {position}: {taken}"
        );
        assert_eq!(
            message(&mut b1, conversation, message_id).unwrap()["text"],
            json!(text(position)),
            "byte {position}"
        );
        b1_next += 2;
    }

    // A1 renews its leaf. B2 takes every message as it was sent, then the commit changed at its
    // last byte: refused, and nothing of it taken.
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
    let mut entries = server.entries(conversation);
    let commit = entries.pop().unwrap();
    let changed = changed_at(&commit, bytes(&commit["data"]).len() - 1);
    entries.push(changed);
    let taken = results(&[ok(&mut b2.core, apply(conversation, &entries[2..]))]);
    assert_eq!(
        taken.last().unwrap(),
        &json!([commit["seq"], "commit", "rejected", "invalid_commit"])
    );
    let state = b2.group(conversation);
    assert_eq!(
        (&state["epoch"], &state["blocked"]),
        (&json!(1), &json!(true))
    );

    // A adds C, by C1's last-resort key package. C1 is handed the welcome changed at its last
    // byte: refused, and C1 isn't in. The welcome as A1 made it then brings C1 in.
    let mut add = adding(&mut server, conversation, c);
    add["users"][0]["key_packages"] = json!([server.last_resort(c1.id)]);
    server.commit(&mut a1, conversation, add).unwrap();
    let welcome = server.entries(conversation).pop().unwrap();
    assert_eq!(welcome["kind"], "welcome");
    let changed = changed_at(&welcome, bytes(&welcome["data"]).len() - 1);
    let refused = results(&[ok(&mut c1.core, apply(conversation, &[changed]))]);
    assert_eq!(refused[0][2], "rejected", "{refused:?}");
    assert_eq!(c1.no_group(conversation)["what"], "group");
    let joined = results(&[ok(&mut c1.core, apply(conversation, &[welcome]))]);
    assert_eq!(joined[0][2], "applied", "{joined:?}");
    server.deliver_all(&mut [&mut a1, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut c1], conversation);
    assert_eq!(members(&state), [a, b, c]);
}

/// The server turns end-to-end encryption off. No command sends in the clear: the core's commands
/// are its whole surface, and none takes text out but as an MLS `PrivateMessage`, whatever field
/// the server slips in beside theirs. A plaintext the server hands out as a message is no message:
/// it waits as one that can't be read, its text never shown. The flag that pauses sending is the
/// API's and the clients' (decision 49): the core has no way to send in the clear.
#[test]
fn server_turns_e2e_off() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let text = "en claro, nunca";

    // A command that would send in the clear doesn't exist.
    for name in [
        "send",
        "send_plaintext",
        "encrypt_off",
        "set_e2e",
        "disable_e2e",
        "plaintext",
    ] {
        let refused = error(
            &mut a1.core,
            json!({"cmd": name, "conversation_id": conversation, "text": text, "e2e": false}),
        );
        assert_eq!(refused["code"], "bad_command", "{name}");
    }
    // An envelope with a field of the server's is no envelope.
    let refused = error(
        &mut a1.core,
        json!({
            "cmd": "encrypt",
            "conversation_id": conversation,
            "nonce": new_id().to_string(),
            "envelope": {"text": text, "plaintext": true},
        }),
    );
    assert_eq!(refused["code"], "bad_command");

    // `encrypt`, `edit` and `delete`, with the server's fields beside theirs, give an MLS private
    // message whose bytes don't hold the text.
    let nonce = new_id().to_string();
    let sealed = ok(
        &mut a1.core,
        json!({
            "cmd": "encrypt",
            "conversation_id": conversation,
            "nonce": nonce,
            "envelope": {"text": text},
            "e2e": false,
            "plaintext": true,
        }),
    );
    let (message_id, _) = post(
        &mut server,
        &mut a1,
        conversation,
        (nonce, bytes(&sealed["ciphertext"])),
    );
    let edited = ok(
        &mut a1.core,
        json!({
            "cmd": "edit",
            "conversation_id": conversation,
            "message_id": message_id,
            "text": text,
            "e2e": false,
        }),
    );
    let deleted = ok(
        &mut a1.core,
        json!({
            "cmd": "delete",
            "conversation_id": conversation,
            "message_id": message_id,
            "e2e": false,
        }),
    );
    for out in [&sealed, &edited, &deleted] {
        let ciphertext = bytes(&out["ciphertext"]);
        let message = MlsMessageIn::tls_deserialize_exact_bytes(&ciphertext).unwrap();
        assert_eq!(message.wire_format(), WireFormat::PrivateMessage);
        assert!(
            !ciphertext
                .windows(text.len())
                .any(|window| window == text.as_bytes()),
            "the text in the clear"
        );
    }
    server.deliver(&mut b1);

    // The server hands B1 a message in the clear: its envelope, then its text alone. Neither is a
    // message: each waits as one that can't be read, its text never shown.
    let envelope = Envelope::Message {
        text: Some(text.into()),
        attachments: Vec::new(),
    }
    .encode()
    .unwrap();
    for plain in [envelope, text.as_bytes().to_vec()] {
        let (id, seq) = server.post_message(&a1, conversation, &new_id().to_string(), plain, &[]);
        let taken = server.deliver(&mut b1);
        assert_eq!(
            results(&taken),
            [json!([seq, "message", "undecryptable", "message"])]
        );
        let shown = message(&mut b1, conversation, id).unwrap();
        assert_eq!(shown["status"], "waiting");
        assert_eq!(shown["text"], Value::Null);
    }
}

/// What the new device sends first, through the server: itself and the commitment's hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commitment {
    v: u32,
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hpke_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

/// The approver's answer: the commitment it answers, its certificate and its nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    v: u32,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

/// The key and the nonce the commitment hid.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reveal {
    v: u32,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// A blob of the core's, read as exactly one CBOR value of that shape.
fn read<T: serde::de::DeserializeOwned>(blob: &Value) -> T {
    let blob = bytes(blob);
    let mut rest = blob.as_slice();
    let value = ciborium::from_reader(&mut rest).expect("the contract's CBOR");
    assert!(rest.is_empty(), "nothing after the value");
    value
}

fn random32() -> Vec<u8> {
    OpenMlsRustCrypto::default()
        .rand()
        .random_array::<32>()
        .unwrap()
        .to_vec()
}

/// SHA-256("duvet approval commit v1" || key || nonce).
fn commitment_hash(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"duvet approval commit v1")
        .chain_update(key)
        .chain_update(nonce)
        .finalize()
        .to_vec()
}

/// The code, as the contract computes it, apart from the core: of the key and nonce a commitment
/// hid, the offer that answered it and the request it carried.
fn code_of(key: &[u8], nonce: &[u8], offer: &Offer, asked: &Commitment) -> String {
    let digest = Sha256::new()
        .chain_update(b"duvet approval code v1")
        .chain_update(key)
        .chain_update(nonce)
        .chain_update(&offer.certificate)
        .chain_update(asked.user.as_bytes())
        .chain_update(asked.device.as_bytes())
        .chain_update(&asked.signature_key)
        .chain_update(&asked.hpke_key)
        .chain_update(&offer.nonce)
        .finalize();
    let first: [u8; 8] = digest[..8].try_into().unwrap();
    format!("{:06}", u64::from_be_bytes(first) % 1_000_000)
}

fn offering(commitment: &Commitment) -> Value {
    json!({"cmd": "approval_offer", "commitment": b64(&cbor(commitment))})
}

fn checking(key: &[u8], nonce: &[u8]) -> Value {
    let reveal = Reveal {
        v: 1,
        key: key.to_vec(),
        nonce: nonce.to_vec(),
    };
    json!({"cmd": "approval_check", "reveal": b64(&cbor(&reveal))})
}

/// The server stands between a new device and its approver and guesses at the code: it commits to
/// a key of its own under the new device's request, for the approver to seal the user's identity
/// to. The commitment binds it to that key before the approver draws its offer's nonce, which the
/// code covers: the approver takes no other key for that offer, the same commitment gets the same
/// offer, nonce included, and a new commitment is a new attempt, whose offer has a nonce drawn after
/// it. The server learns the new device's code once the device reveals, and still has one guess per
/// offer at making the approver show it; the new device refuses every other code.
///
/// The core counts no offers: each one takes the person's tap (a client rule), so a server needs
/// about a million taps for an even chance. The person compares the codes on the new device before
/// confirming on the approver: a confirmation without it seals the identity to the server's key.
#[test]
fn server_brute_forces_approval_code() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);
    let mut n = server.bare_device(a);

    // The new device commits; the server puts a key of its own in the commitment it hands the
    // approver, under the new device's request.
    let begun = ok(&mut n.core, json!({"cmd": "approval_begin"}));
    let asked: Commitment = read(&begun["commitment"]);
    let (key, nonce) = (random32(), random32());
    let substituted = Commitment {
        hash: commitment_hash(&key, &nonce),
        ..asked.clone()
    };
    let first: Offer = read(&ok(&mut a1.core, offering(&substituted))["offer"]);

    // The offer goes on to the new device as an answer to its own commitment, and the new device
    // reveals: the server can now work out the code the new device holds.
    let forwarded = Offer {
        hash: asked.hash.clone(),
        ..first.clone()
    };
    let revealed = ok(
        &mut n.core,
        json!({"cmd": "approval_reveal", "offer": b64(&cbor(&forwarded))}),
    );
    let theirs: Reveal = read(&revealed["reveal"]);
    let wanted = code_of(&theirs.key, &theirs.nonce, &forwarded, &asked);

    // For that offer, the approver takes the key committed to and no other: not the new device's,
    // not another the server picks.
    for (other_key, other_nonce) in [
        (theirs.key.clone(), theirs.nonce.clone()),
        (random32(), nonce.clone()),
    ] {
        let refused = error(&mut a1.core, checking(&other_key, &other_nonce));
        assert_eq!(
            (&refused["code"], &refused["what"]),
            (&json!("invalid_signature"), &json!("reveal"))
        );
    }
    let shown = ok(&mut a1.core, checking(&key, &nonce))["code"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(shown, code_of(&key, &nonce, &first, &substituted));

    // The same commitment again: the same offer, nonce included. No new guess.
    let same: Offer = read(&ok(&mut a1.core, offering(&substituted))["offer"]);
    assert_eq!(same.nonce, first.nonce);

    // A new commitment, to another key: a new attempt, whose offer has a nonce of its own, drawn
    // after the commitment. Whatever the server worked out against the first nonce is of no use:
    // the approver shows the code of the new one.
    let (key2, nonce2) = (random32(), random32());
    let guess = Commitment {
        hash: commitment_hash(&key2, &nonce2),
        ..asked.clone()
    };
    let second: Offer = read(&ok(&mut a1.core, offering(&guess))["offer"]);
    assert_ne!(second.nonce, first.nonce);
    let shown2 = ok(&mut a1.core, checking(&key2, &nonce2))["code"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(shown2, code_of(&key2, &nonce2, &second, &guess));

    // The person types each code the approver showed into the new device, which refuses it, its
    // attempt unchanged (a guess the server makes is right once in a million, and then accepted).
    // The code the server worked out is the one the new device takes.
    for code in [&shown, &shown2] {
        if *code == wanted {
            continue;
        }
        let refused = error(&mut n.core, json!({"cmd": "approval_accept", "code": code}));
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("code_mismatch"))
        );
    }
    ok(
        &mut n.core,
        json!({"cmd": "approval_accept", "code": wanted}),
    );
}

/// At the cutover the server swaps B, in A's DM with B, for an account of its own, X, and plants X
/// in A's group with B. The client's record of each conversation from before the cutover, which it
/// hands its core, refuses that: A1's own group made from the server's list, the founding welcome
/// X's device made, and an external join on X's group (a DM's joins have exactly its two users, a
/// group's joins only its users; `groups.rs` has each rule's cases).
#[test]
fn server_plants_a_member_at_the_cutover() {
    let mut server = FakeServer::new();
    let (a, b, x) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut x1] = new_devices(&mut server, [a, a, b, x]);
    let (dm, group) = (new_id(), new_id());
    server.conversation(dm, Kind::Dm, None, &[a, x], true);
    server.conversation(group, Kind::Group, Some(a), &[a, b, x], true);
    let records = [(dm, None, [a, b]), (group, Some(a), [a, b])];
    for (conversation, owner, members) in &records {
        for device in [&mut a1, &mut a2, &mut b1] {
            device.remember(*conversation, *owner, members);
        }
    }

    // A1 makes each group as the server lists it, with A's record beside: refused.
    for (conversation, owner, members) in &records {
        let mut create = server.create_group(*conversation);
        create["expected"] = json!({"owner": owner, "members": members});
        let refused = error(&mut a1.core, create);
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("member_list_mismatch"))
        );
        assert_eq!(a1.no_group(*conversation)["what"], "group");
    }

    // X's device founds both, as any member of a conversation from before the cutover may. Every
    // device with A's or B's record refuses the founding welcome.
    for (conversation, _, _) in &records {
        let create = server.create_group(*conversation);
        server.commit(&mut x1, *conversation, create).unwrap();
    }
    for (device, welcomed) in [(&mut a1, 2), (&mut a2, 2), (&mut b1, 1)] {
        let replies = server.deliver(device);
        assert_eq!(replies.len(), welcomed);
        for reply in replies {
            assert_eq!(
                results(&[reply]),
                [json!([2, "welcome", "rejected", "member_list_mismatch"])]
            );
        }
    }

    // A2 then joins each by external commit, with A's record: refused.
    for (conversation, owner, members) in &records {
        let mut join = joining(&server, *conversation);
        join["expected"] = json!({"owner": owner, "members": members});
        let refused = error(&mut a2.core, join);
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("member_list_mismatch"))
        );
        assert_eq!(a2.no_group(*conversation)["what"], "group");
    }
}

/// The server hands out a segment of the backup from before a message was deleted, without the IDs
/// the API saw deleted. A device that holds the deletion never brings the message back from it.
///
/// The limit (`backup.rs`, and the backup task's report): a segment carries no version or time, so
/// a device that never saw the deletion, as one recovered after it, takes the message from that
/// segment when the server leaves its ID out of `deleted`.
#[test]
fn server_replays_a_backup_from_before_a_deletion() {
    const HOUR: i64 = 60 * 60 * 1000;
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    let recovering = |server: &FakeServer| {
        json!({
            "cmd": "recover",
            "recovery_key": identity["recovery_key"],
            "wrapped_backup_key": identity["wrapped_backup_key"],
            "encrypted_identity": identity["encrypted_identity"],
            "device_list": server.observed(a)["device_list"],
        })
    };
    // A2, recovered with A's key, holds the backup key.
    let mut a2 = server.bare_device(a);
    let recovered = ok(&mut a2.core, recovering(&server));
    server.take_device(a, &recovered["certificate"], &recovered["device_list"]);
    server.publish(&mut a2);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    // The day after tomorrow by the system's clock: the core's clock never goes behind it.
    let day = (server.clock.now_ms().div_euclid(DAY_MS) + 2) * DAY_MS;
    server.clock.set(day + HOUR);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // That day A1 writes a message, then B1; the next day A1 builds the day's segment, then deletes
    // its message, which every device applies.
    server.clock.set(day + 2 * HOUR);
    let (gone, _) = say(&mut server, &mut a1, conversation, "lo borraré");
    let (stays, _) = say(&mut server, &mut b1, conversation, "esto queda");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    server.clock.set(day + DAY_MS + HOUR);
    let due = ok(&mut a1.core, json!({"cmd": "backup_due"}));
    let the_day = due["segments"][0]["day"].clone();
    let before = ok(
        &mut a1.core,
        json!({"cmd": "backup_segment", "conversation_id": conversation, "day": the_day}),
    );
    delete(&mut server, &mut a1, conversation, gone);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A2 holds the deletion: the copy from before it, handed without `deleted`, brings nothing back.
    ok(
        &mut a2.core,
        json!({"cmd": "backup_import", "data": before["data"]}),
    );
    assert_eq!(shown_ids(&mut a2, conversation), [stays]);

    // The limit: A3, recovered after the deletion, takes the message from the same copy.
    let mut a3 = server.bare_device(a);
    let recovered = ok(&mut a3.core, recovering(&server));
    server.take_device(a, &recovered["certificate"], &recovered["device_list"]);
    ok(
        &mut a3.core,
        json!({"cmd": "backup_import", "data": before["data"]}),
    );
    assert_eq!(shown_ids(&mut a3, conversation), [stays, gone]);
}

/// A member forges a share: C, sharing the history from before B joined, passes made-up text off as
/// A's message, and a message A never wrote. The documented limit (decision 26): what came before a
/// device joined is taken from a share as its sharer gives it, marked as shared by them, and the
/// first share's claim stands, but against its claimed author's own package, which replaces their
/// message: another member's share changes nothing, and a message the author never wrote stays.
#[test]
fn a_forged_share_stands_marked_as_its_sharers() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut c1]);
    let (written, written_seq) = say(&mut server, &mut a1, conversation, "lo que A escribió");
    server.deliver_all(&mut [&mut a1, &mut c1]);

    // A adds B, whose device has nothing from before.
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    assert_eq!(messages_of(&mut b1, conversation), Vec::<Value>::new());

    // C shares, as A's, made-up text under the ID of A's message, and a message A never wrote.
    let a1_id = a1.id;
    let as_a = |id: Uuid, seq: u64, text: &str| Record {
        kind: RecordKind::Message,
        id,
        seq,
        user: a,
        device: a1_id,
        sent: 1,
        envelope: Envelope::Message {
            text: Some(text.into()),
            attachments: Vec::new(),
        }
        .encode()
        .unwrap(),
        shared_by: None,
        reply_to: None,
    };
    let made_up = new_id();
    let forged = [
        as_a(written, written_seq, "texto inventado"),
        as_a(made_up, written_seq + 1, "nunca lo escribió"),
    ];
    let devices: Vec<Vec<u8>> = server.observed(b)["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect();
    let share = |sharer: &mut TestDevice, records: &[Record]| {
        let deflated = miniz_oxide::deflate::compress_to_vec(&cbor(&records), 6);
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
                let package = history::package(&own.signer, &header, &deflated)?;
                history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
            })
            .unwrap();
        serde_json::to_value(&sealed).unwrap()
    };
    // B1 takes a package's key, from its sharer's device, then the package.
    let take = |b1: &mut TestDevice, from: Uuid, shared: &Value| {
        let certificate = server.observed(from)["certificates"][0].clone();
        for key in shared["keys"].as_array().unwrap() {
            ok(
                &mut b1.core,
                json!({"cmd": "receive_direct", "message": key["message"], "from_certificate": certificate}),
            );
        }
        ok(
            &mut b1.core,
            json!({"cmd": "history_import", "share_id": shared["share_id"], "parts": shared["parts"]}),
        );
    };
    let forgery = share(&mut c1, &forged);
    take(&mut b1, c, &forgery);

    // B1 shows both as A's, marked as shared by C.
    for (id, text) in [(written, "texto inventado"), (made_up, "nunca lo escribió")] {
        let copy = message(&mut b1, conversation, id).unwrap();
        assert_eq!(copy["user_id"], json!(a));
        assert_eq!(copy["text"], text);
        assert_eq!(copy["shared_by"], json!(c));
    }

    // C's own share of the true text, as another member's, changes nothing.
    let honest = share(&mut c1, &[as_a(written, written_seq, "lo que A escribió")]);
    take(&mut b1, c, &honest);
    assert_eq!(
        message(&mut b1, conversation, written).unwrap()["text"],
        "texto inventado"
    );

    // A's own share of its week replaces its message, marked as shared by A; the message A never
    // wrote stays, as C shared it.
    let shared = ok(
        &mut a1.core,
        json!({
            "cmd": "history_share",
            "conversation_id": conversation,
            "to_user": b,
            "range": "week",
            "devices": server.observed(b)["certificates"],
        }),
    );
    take(&mut b1, a, &shared);
    let copy = message(&mut b1, conversation, written).unwrap();
    assert_eq!(copy["text"], "lo que A escribió");
    assert_eq!(copy["shared_by"], json!(a));
    let copy = message(&mut b1, conversation, made_up).unwrap();
    assert_eq!(copy["text"], "nunca lo escribió");
    assert_eq!(copy["shared_by"], json!(c));
}
