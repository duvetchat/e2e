//! Conversations' groups through `Core::handle`, against a fake of the API: making them, adding,
//! removing and leaving, the server's word on each commit, joining by welcome and by external
//! commit, and each group's queue taken in order.

mod support;

use std::collections::BTreeSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e::mls;
use duvet_e2e_rules::{
    CommitAad, DeviceList, Entry, Kind, MemberList, join_config, leaf_capabilities,
};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    KeyPackageIn, LeafNodeParameters, MlsGroup, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    OpenMlsProvider, ProtocolVersion, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
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
fn start(server: &mut FakeServer, creator: &mut TestDevice, conversation: Uuid) -> Value {
    let command = server.create_group(conversation);
    server
        .commit(creator, conversation, command)
        .expect("the server takes epoch 0")
}

fn command(name: &str, conversation: Uuid) -> Value {
    json!({"cmd": name, "conversation_id": conversation})
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

/// What `encrypt` checks before it encrypts: whether the device may send now.
fn ready(device: &mut TestDevice, conversation: Uuid) -> Result<(), Value> {
    device
        .core
        .transaction(|tx| mls::ready_to_send(tx, conversation))
        .map_err(|error| error.to_reply()["error"].clone())
}

fn due(device: &mut TestDevice) -> Value {
    ok(&mut device.core, json!({"cmd": "refresh_due"}))["conversations"].clone()
}

fn tls(message: &MlsMessageOut) -> Vec<u8> {
    message.tls_serialize_detached().unwrap()
}

fn device_set(state: &Value) -> BTreeSet<Uuid> {
    devices(state).into_iter().collect()
}

/// The results of `replies`, each `[seq, kind, result, rule]`.
fn results(replies: &[Value]) -> Vec<Value> {
    replies
        .iter()
        .flat_map(|reply| reply["results"].as_array().unwrap().clone())
        .map(|result| {
            json!([
                result["seq"],
                result["kind"],
                result["result"],
                result["rule"]
            ])
        })
        .collect()
}

#[test]
fn create_add_remove_leave() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2, mut c1] = new_devices(&mut server, [a, a, b, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    // A makes the group with B: every device on both users' lists enters, and the four reach the
    // same epoch and authenticator.
    let created = start(&mut server, &mut a1, conversation);
    assert_eq!(created["generation"], 0);
    assert_eq!(created["skipped_devices"], json!([]));
    for field in ["initial_group_info", "commit", "welcome", "group_info"] {
        assert!(created[field].is_string(), "{field}");
    }
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 1);
    assert_eq!(state["kind"], "group");
    assert_eq!(state["owner"], json!(a));
    assert_eq!(state["blocked"], false);
    assert_eq!(members(&state), [a, b]);
    assert_eq!(
        device_set(&state),
        BTreeSet::from([a1.id, a2.id, b1.id, b2.id])
    );
    assert_eq!(
        state["members"][1],
        json!({"user_id": b, "generation": 0, "epoch": 0})
    );

    // A adds C, whose device enters by the welcome.
    let add = adding(&mut server, conversation, c);
    let added = server.commit(&mut a1, conversation, add).unwrap();
    assert!(added["welcome"].is_string());
    assert_eq!(added["skipped_devices"], json!([]));
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2, &mut c1]);
    let state = same_group(
        &mut [&mut a1, &mut a2, &mut b1, &mut b2, &mut c1],
        conversation,
    );
    assert_eq!(state["epoch"], 2);
    assert_eq!(members(&state), [a, b, c]);
    assert_eq!(
        state["members"][2],
        json!({"user_id": c, "generation": 0, "epoch": 2})
    );

    // A removes C, whose device leaves the group.
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [c]});
    let removed = server.commit(&mut a1, conversation, remove).unwrap();
    assert!(removed.get("welcome").is_none());
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 3);
    assert_eq!(members(&state), [a, b]);
    assert_eq!(device_set(&state).len(), 4);
    let out = c1.no_group(conversation);
    assert_eq!(
        (&out["code"], &out["what"]),
        (&json!("not_found"), &json!("membership"))
    );

    // B leaves with its statement, and the next commit, here A2's, takes B's devices out and B off
    // the list.
    server.leave(&mut b1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    server
        .commit(
            &mut a2,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2], conversation);
    assert_eq!(state["epoch"], 4);
    assert_eq!(members(&state), [a]);
    assert_eq!(state["owner"], json!(a));
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, a2.id]));
    for device in [&mut b1, &mut b2] {
        assert_eq!(device.no_group(conversation)["what"], "membership");
    }
}

#[test]
fn losing_commit_retries() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // A1 and B1 each make a commit in epoch 1.
    let refresh = command("refresh", conversation);
    let from_a = ok(&mut a1.core, refresh.clone());
    let from_b = ok(&mut b1.core, refresh.clone());

    // Until the server answers, B1 makes no other commit and takes no more of the queue.
    assert_eq!(
        error(&mut b1.core, refresh.clone())["code"],
        "pending_commit"
    );
    let waiting = error(&mut b1.core, apply(conversation, &[]));
    assert_eq!(waiting["code"], "pending_commit");

    // A1's comes first; B1's gets the 409, and B1 drops it.
    server.submit(&mut a1, conversation, &from_a).unwrap();
    assert_eq!(
        server.submit(&mut b1, conversation, &from_b),
        Err(Refusal::Conflict)
    );
    assert_eq!(b1.group(conversation)["epoch"], 1);

    // B1 applies the winner, and makes its commit again.
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    assert_eq!(b1.group(conversation)["epoch"], 2);
    server.commit(&mut b1, conversation, refresh).unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 3);
}

#[test]
fn own_commit_answered_refused_settles_from_the_queue() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B1's refresh: the server takes it, but B1 hears a refusal.
    let refresh = command("refresh", conversation);
    let made = ok(&mut b1.core, refresh.clone());
    let seq = server.take_unheard(&mut b1, conversation, &made);

    // Until the queue says which commit took the epoch, B1 makes no other and sends nothing.
    assert_eq!(
        error(&mut b1.core, refresh.clone())["code"],
        "pending_commit"
    );
    assert_eq!(
        ready(&mut b1, conversation).unwrap_err()["code"],
        "pending_commit"
    );

    // The queue brings B1's own commit back: B1 merges it, and its group isn't blocked.
    let replies = server.deliver(&mut b1);
    assert_eq!(results(&replies), [json!([seq, "commit", "own", null])]);
    server.deliver(&mut a1);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["blocked"], false);
    assert_eq!(ready(&mut b1, conversation), Ok(()));
    server.commit(&mut b1, conversation, refresh).unwrap();
}

#[test]
fn concurrent_epoch_zero_converges() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    // A conversation from before the cutover, whose epoch 0 any member may make.
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);

    // A1 and B1 make it at once.
    let from_a = ok(&mut a1.core, server.create_group(conversation));
    let from_b = ok(&mut b1.core, server.create_group(conversation));

    // B1's comes first, though B isn't the owner. A1's loses, and its group goes whole.
    server.submit(&mut b1, conversation, &from_b).unwrap();
    assert_eq!(
        server.submit(&mut a1, conversation, &from_a),
        Err(Refusal::Conflict)
    );
    assert_eq!(a1.no_group(conversation)["what"], "group");

    // A device holds the welcome to the members its client showed before the cutover: A2's shows
    // another owner, and A2 refuses it.
    a1.remember(conversation, Some(a), &[a, b]);
    a2.remember(conversation, Some(b), &[a, b]);
    let refused = server.deliver(&mut a2);
    assert_eq!(
        results(&refused),
        [json!([2, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(a2.no_group(conversation)["what"], "group");

    // A device whose client didn't know the conversation before the cutover has no list to hold
    // the welcome to, and takes it as it comes, though B, not the owner, made the group.
    let taken = server.deliver(&mut b2);
    assert_eq!(results(&taken), [json!([2, "welcome", "applied", null])]);

    // A1 takes the winner's welcome, which matches its record; A2, whose key package that refused
    // welcome used up, rejoins by external commit. All four end in one group.
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let join = joining(&server, conversation);
    server.commit(&mut a2, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["owner"], json!(a));
    assert_eq!(members(&state), [a, b]);
    assert_eq!(device_set(&state).len(), 4);
}

#[test]
fn legacy_welcome_is_held_to_the_devices_own_record() {
    let mut server = FakeServer::new();
    let (a, b, x) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut x1] = new_devices(&mut server, [a, b, x]);
    let conversation = new_id();
    // Before the cutover, B's client showed the conversation with A, its owner, and B. The server
    // now has X in it too, and A1 makes the group as the server has it.
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, x], true);
    b1.remember(conversation, Some(a), &[a, b]);
    start(&mut server, &mut a1, conversation);

    // B1 holds the welcome to its own record, not the server's: X is a member too many.
    let refused = server.deliver(&mut b1);
    assert_eq!(
        results(&refused),
        [json!([2, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(b1.no_group(conversation)["what"], "group");

    // X1, whose client had no record of the conversation, takes the welcome as it comes.
    let taken = server.deliver(&mut x1);
    assert_eq!(results(&taken), [json!([2, "welcome", "applied", null])]);
}

#[test]
fn catch_up_after_many_epochs() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // 30 commits, A1's and B1's in turn, while B2 is away.
    for round in 0..30 {
        let committer = if round % 2 == 0 { &mut a1 } else { &mut b1 };
        server
            .commit(committer, conversation, command("refresh", conversation))
            .unwrap();
        server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    }

    // B2 comes back and takes them all at once.
    let caught_up = server.deliver(&mut b2);
    let taken = results(&caught_up);
    assert_eq!(taken.len(), 30);
    assert!(taken.iter().all(|result| result[2] == "applied"));
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 31);
}

/// An external commit `device` makes outside its core, from its own keys and `group_info`: the
/// commit and the new group info.
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
    (tls(bundle.commit()), tls(&info))
}

#[test]
fn non_member_cannot_join_external() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // C's own core won't make the commit: C isn't on the list.
    let refused = error(&mut c1.core, joining(&server, conversation));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("user_not_member"))
    );
    assert_eq!(c1.no_group(conversation)["what"], "group");

    // One C makes by hand, outside its core, the API's validator refuses...
    let group_info = server.group_info(conversation);
    let (commit, info) = external_commit_by_hand(&mut c1, &group_info);
    let checked = server.check(conversation, &commit, &info);
    assert_eq!(checked.error.unwrap().code, "user_not_member");

    // ...and so do the members, from a server that skips its validator.
    let seq = server.force(conversation, "commit", commit);
    let replies = server.deliver(&mut a1);
    assert_eq!(
        results(&replies),
        [json!([seq, "commit", "rejected", "user_not_member"])]
    );
    let state = a1.group(conversation);
    assert_eq!(state["blocked"], true);
    assert_eq!(state["epoch"], 1);
}

#[test]
fn removed_device_cannot_rejoin() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // A drops A2 from its devices: A1 signs a list without it, which everyone but A2 sees, and the
    // API proposes A2's removal, which the next commit makes.
    let list = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &list["device_list"]);
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    server.remove_device(conversation, a2.id);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    server
        .commit(
            &mut b1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    assert_eq!(a2.no_group(conversation)["what"], "membership");

    // Off its user's list, A2 can't come back by external commit: the API's validator refuses it,
    // and A2 drops the group it made.
    let join = joining(&server, conversation);
    assert_eq!(
        server.commit(&mut a2, conversation, join),
        Err(Refusal::Invalid("device_not_listed".into()))
    );
    assert_eq!(a2.no_group(conversation)["what"], "membership");

    // Once A2 knows its user's list, its own core won't even try.
    server.introduce(&mut a2);
    let refused = error(&mut a2.core, joining(&server, conversation));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("device_not_listed"))
    );

    let state = same_group(&mut [&mut a1, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, b1.id, b2.id]));
}

#[test]
fn replayed_welcome_keeps_a_removed_device_out() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    // B1 enters with its last-resort key package, which the welcome doesn't use up.
    let mut create = server.create_group(conversation);
    create["key_packages"][b.to_string().as_str()] = json!([server.last_resort(b1.id)]);
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let welcome = server.entries(conversation)[1].clone();
    assert_eq!(welcome["kind"], "welcome");
    assert_eq!(b1.group(conversation)["epoch"], 1);

    // A removes B: B1 is out.
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(b1.no_group(conversation)["what"], "membership");

    // The server hands B1 its old welcome again, under a new number. It still opens, but it's for
    // an epoch B1 has seen pass: B1 refuses it, and stays out.
    let seq = server.force(conversation, "welcome", bytes(&welcome["data"]));
    let replies = server.deliver(&mut b1);
    assert_eq!(
        results(&replies),
        [json!([seq, "welcome", "rejected", "stale_welcome"])]
    );
    assert_eq!(b1.no_group(conversation)["what"], "membership");
}

#[test]
fn returning_device_rejoins_external() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // B2 goes quiet: the API proposes its removal (B2 stays on B's list), and the next commit
    // takes it out, while B2 hears nothing.
    server.remove_device(conversation, b2.id);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    assert_eq!(b2.group(conversation)["epoch"], 1, "B2's view from before");

    // Back, B2 rejoins by external commit, in place of the group it had.
    let join = joining(&server, conversation);
    let joined = server.commit(&mut b2, conversation, join).unwrap();
    assert!(joined["group_info"].is_string());
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 3);
    assert_eq!(
        device_set(&state),
        BTreeSet::from([a1.id, a2.id, b1.id, b2.id])
    );
}

#[test]
fn stale_knowledge_asks_to_observe_before_blocking() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let old_list = server.observed(b);

    // B gets a new device, which joins by external commit. A1 and C1 haven't seen B's new list.
    let mut b2 = server.device(b);
    server.introduce(&mut b2);
    let join = joining(&server, conversation);
    server.commit(&mut b2, conversation, join).unwrap();
    let entries = server.entries(conversation);
    assert_eq!(entries.len(), 3);
    let asked_for_b = (json!("needs_identities"), json!([b.to_string()]));

    // A1 doesn't block on a commit only its own knowledge refuses: it asks to observe B first, and
    // keeps nothing of the call.
    let asked = error(&mut a1.core, apply(conversation, &entries[1..]));
    assert_eq!((asked["code"].clone(), asked["users"].clone()), asked_for_b);
    assert_eq!(a1.group(conversation)["epoch"], 1);

    // With B's newer list, A1 takes the commit.
    ok(&mut a1.core, server.observed(b));
    let taken = ok(&mut a1.core, apply(conversation, &entries[1..]));
    assert_eq!(results(&[taken]), [json!([3, "commit", "applied", null])]);

    // C1 is asked the same, but observes B's old list again: the same knowledge refuses the commit
    // a second time, and C1 blocks.
    let asked = error(&mut c1.core, apply(conversation, &entries[2..]));
    assert_eq!((asked["code"].clone(), asked["users"].clone()), asked_for_b);
    assert_eq!(ok(&mut c1.core, old_list)["state"], "same");
    let refused = ok(&mut c1.core, apply(conversation, &entries[2..]));
    assert_eq!(
        results(&[refused]),
        [json!([3, "commit", "rejected", "device_not_listed"])]
    );
    assert_eq!(c1.group(conversation)["blocked"], true);

    // B1, once it knows its user's new list, takes it too.
    server.introduce(&mut b1);
    server.deliver(&mut b1);
    let state = same_group(&mut [&mut a1, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 2);
}

#[test]
fn server_proposal_is_committed_by_next_writer() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2] = new_devices(&mut server, [a, a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    assert_eq!(ready(&mut b1, conversation), Ok(()));

    // A2 logs out: the API proposes its removal.
    server.remove_device(conversation, a2.id);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // No message goes before a commit takes A2 out: encrypt's check says to commit it first.
    let wait = ready(&mut b1, conversation).unwrap_err();
    assert_eq!(wait["code"], "pending_proposals");

    // A2 is on its way out: it neither sends nor makes that commit, which OpenMLS and the
    // validator wouldn't take from it.
    let out = ready(&mut a2, conversation).unwrap_err();
    assert_eq!(
        (&out["code"], &out["what"]),
        (&json!("not_found"), &json!("membership"))
    );
    for name in ["commit_pending", "refresh"] {
        let refused = error(&mut a2.core, command(name, conversation));
        assert_eq!(
            (&refused["code"], &refused["what"]),
            (&json!("not_found"), &json!("membership")),
            "{name}"
        );
    }

    // B1, the next to write, commits the removal.
    server
        .commit(
            &mut b1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    assert_eq!(ready(&mut b1, conversation), Ok(()));
    assert_eq!(a2.no_group(conversation)["what"], "membership");
    let state = same_group(&mut [&mut a1, &mut b1, &mut b2], conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, b1.id, b2.id]));

    // With nothing pending, commit_pending has nothing to commit.
    let nothing = error(&mut b1.core, command("commit_pending", conversation));
    assert_eq!(
        (&nothing["code"], &nothing["what"]),
        (&json!("not_found"), &json!("proposals"))
    );
}

/// `device` adds `user` from its own group state, without its core's rules, which keeps that
/// state as it was: the commit and the welcome.
fn add_by_hand(
    device: &mut TestDevice,
    conversation: Uuid,
    user: Uuid,
    key_package: &Value,
) -> (Vec<u8>, Vec<u8>) {
    let key_package = KeyPackageIn::tls_deserialize_exact_bytes(&bytes(key_package))
        .unwrap()
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .unwrap();
    device.rolled_back(|tx| {
        let (mut group, _) = mls::load_group(tx, conversation)?;
        let own = tx.own_device()?;
        let context = group.public_group().group_context().clone();
        let mut list = MemberList::from_group_context(&context).unwrap();
        list.users.push(Entry {
            user,
            generation: 0,
            epoch: context.epoch().as_u64() + 1,
        });
        let mut extensions = context.extensions().clone();
        extensions.add_or_replace(list.to_extension()).unwrap();
        group.set_aad(CommitAad::new(Vec::new()).encode());
        let provider = tx.provider();
        let bundle = group
            .commit_builder()
            .propose_adds([key_package])
            .propose_group_context_extensions(extensions)
            .unwrap()
            .force_self_update(true)
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();
        Ok((tls(bundle.commit()), tls(&bundle.to_welcome_msg().unwrap())))
    })
}

#[test]
fn invalid_commit_blocks_and_reset_recovers() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut b2, mut c1] = new_devices(&mut server, [a, a, b, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);

    // B2, not the owner, adds C: its own core refuses.
    let add = adding(&mut server, conversation, c);
    let refused = error(&mut b2.core, add.clone());
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (
            &json!("rule_violation"),
            &json!("members_changed_by_non_owner")
        )
    );

    // So B2 makes it by hand, and a server that skips its validator queues it.
    let key_package = &add["users"][0]["key_packages"][0];
    let (commit, welcome) = add_by_hand(&mut b2, conversation, c, key_package);
    let commit_seq = server.force(conversation, "commit", commit);
    let welcome_seq = server.force(conversation, "welcome", welcome);

    // Every member refuses it, and its group is blocked: the owner's devices and B1 see a
    // non-owner's change; B2 its own commit, which it can't read, its state having stayed.
    let mut rules = Vec::new();
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        let taken = results(&server.deliver(device));
        assert_eq!(taken.len(), 2, "{taken:?}");
        let rule = taken[0][3].clone();
        assert_eq!(taken[0], json!([commit_seq, "commit", "rejected", rule]));
        assert_eq!(taken[1], json!([welcome_seq, "welcome", "ignored", null]));
        rules.push(rule);
        let state = device.group(conversation);
        assert_eq!(state["blocked"], true);
        assert_eq!(state["epoch"], 1);
    }
    assert_eq!(
        rules,
        [
            "members_changed_by_non_owner",
            "members_changed_by_non_owner",
            "members_changed_by_non_owner",
            "invalid_commit",
        ]
    );

    // A blocked group takes no commit.
    let blocked = error(&mut a1.core, command("refresh", conversation));
    assert_eq!(
        (&blocked["code"], &blocked["rule"]),
        (&json!("rule_violation"), &json!("group_blocked"))
    );

    // C refuses the welcome that came with it: B2 isn't the owner.
    let welcome = server.entries(conversation)[welcome_seq as usize - 1].clone();
    let refused = ok(&mut c1.core, apply(conversation, &[welcome]));
    assert_eq!(
        results(&[refused]),
        [json!([
            welcome_seq,
            "welcome",
            "rejected",
            "members_changed_by_non_owner"
        ])]
    );
    assert_eq!(c1.no_group(conversation)["what"], "group");

    // A, the owner, resets the group: everyone enters its next generation, with the members it
    // had, and the block is gone.
    let reset = json!({
        "cmd": "reset_group",
        "conversation_id": conversation,
        "key_packages": server.claim(&[a, b]),
    });
    let reset = server.commit(&mut a1, conversation, reset).unwrap();
    assert_eq!(reset["generation"], 1);
    assert_eq!(reset["skipped_devices"], json!([]));
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1, &mut b2], conversation);
    assert_eq!(state["generation"], 1);
    assert_eq!(state["epoch"], 1);
    assert_eq!(state["blocked"], false);
    assert_eq!(members(&state), [a, b]);
    assert_eq!(state["members"][0]["generation"], 1);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
}

#[test]
fn refresh_due_uses_the_clock() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(due(&mut a1), json!([]));

    // A leaf is due 7 days after it was last new, by the core's clock.
    server.clock.advance(7 * DAY_MS - 1);
    assert_eq!(due(&mut a1), json!([]));
    server.clock.advance(1);
    assert_eq!(due(&mut a1), json!([conversation]));
    assert_eq!(due(&mut b1), json!([conversation]));

    // A refresh waiting for the server's word isn't due; taken, A1's leaf is new.
    let refreshed = ok(&mut a1.core, command("refresh", conversation));
    assert_eq!(due(&mut a1), json!([]));
    server.submit(&mut a1, conversation, &refreshed).unwrap();
    assert_eq!(due(&mut a1), json!([]));
    assert_eq!(due(&mut b1), json!([conversation]));
}

#[test]
fn apply_skips_replayed_entries_and_reports_gaps() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver(&mut a1);
    for _ in 0..3 {
        server
            .commit(&mut a1, conversation, command("refresh", conversation))
            .unwrap();
        server.deliver(&mut a1);
    }
    // A1's commit, its welcome to B1, and three commits more.
    let entries = server.entries(conversation);
    assert_eq!(entries.len(), 5);

    // B1 takes the first two: the welcome brings it in.
    let first = ok(&mut b1.core, apply(conversation, &entries[..2]));
    assert_eq!(first["applied_through"], 2);
    assert_eq!(
        results(&[first]),
        [
            json!([1, "commit", "ignored", null]),
            json!([2, "welcome", "applied", null]),
        ]
    );
    let before = b1.group(conversation);

    // The same again: skipped, without an error or an effect.
    let again = ok(&mut b1.core, apply(conversation, &entries[..2]));
    assert_eq!(again["applied_through"], 2);
    assert_eq!(again["results"], json!([]));
    assert_eq!(b1.group(conversation), before);

    // An entry after a hole: a gap, from the first number missing.
    let gap = error(&mut b1.core, apply(conversation, &entries[3..4]));
    assert_eq!((&gap["code"], &gap["from"]), (&json!("gap"), &json!(3)));

    // A hole inside a batch: nothing of it is applied, so the core still needs the first.
    let gap = error(
        &mut b1.core,
        apply(conversation, &[entries[2].clone(), entries[4].clone()]),
    );
    assert_eq!((&gap["code"], &gap["from"]), (&json!("gap"), &json!(3)));
    assert_eq!(b1.group(conversation), before);

    // Old entries among new ones: only the new ones count.
    let rest = ok(&mut b1.core, apply(conversation, &entries[1..]));
    assert_eq!(rest["applied_through"], 5);
    let seqs: Vec<Value> = results(&[rest]).iter().map(|r| r[0].clone()).collect();
    assert_eq!(seqs, [json!(3), json!(4), json!(5)]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 4);
}

#[test]
fn holes_are_reported_in_and_out_of_the_group() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);

    // B1 hasn't anchored: nothing it takes before its welcome counts as applied.
    let entries = server.entries(conversation);
    let first = ok(&mut b1.core, apply(conversation, &entries[..1]));
    assert_eq!(
        results(&[first.clone()]),
        [json!([1, "commit", "ignored", null])]
    );
    assert_eq!(first["applied_through"], Value::Null);
    server.deliver(&mut b1);

    // B1 commits twice before A1 hears anything. A1 counts from its own commit, by the number the
    // server gave it: the second commit alone is a gap.
    for _ in 0..2 {
        server
            .commit(&mut b1, conversation, command("refresh", conversation))
            .unwrap();
        server.deliver(&mut b1);
    }
    let entries = server.entries(conversation);
    let gap = error(&mut a1.core, apply(conversation, &entries[3..4]));
    assert_eq!((&gap["code"], &gap["from"]), (&json!("gap"), &json!(2)));
    server.deliver(&mut a1);
    same_group(&mut [&mut a1, &mut b1], conversation);

    // A removes B, and B1 hears it.
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(b1.no_group(conversation)["what"], "membership");

    // A adds B again (its commit and B1's welcome), then refreshes.
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver(&mut a1);
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver(&mut a1);
    let entries = server.entries(conversation);
    assert_eq!(entries[6]["kind"], "welcome");

    // The refresh reaches B1 first, pushed live ahead of the backlog. Out of the group, B1 takes
    // nothing from it, and its cursor doesn't pass the hole.
    let early = ok(&mut b1.core, apply(conversation, &entries[7..8]));
    assert_eq!(
        results(&[early.clone()]),
        [json!([8, "commit", "ignored", null])]
    );
    assert_eq!(early["applied_through"], 5);

    // The backlog brings the welcome: B1 is back, and takes the refresh after it.
    let backlog = ok(&mut b1.core, apply(conversation, &entries[5..]));
    assert_eq!(
        results(&[backlog.clone()]),
        [
            json!([6, "commit", "ignored", null]),
            json!([7, "welcome", "applied", null]),
            json!([8, "commit", "applied", null]),
        ]
    );
    assert_eq!(backlog["applied_through"], 8);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 6);
}

#[test]
fn devices_without_key_packages_are_skipped() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    let mut b2 = server.device(b);
    // A device of B's whose only key package expires within the hour.
    let b3 = server.virtual_device(b);
    // B2 never publishes a key package.
    for device in [&mut a1, &mut a2, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut a2, &mut b1, &mut b2] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    // A2's key package is damaged on the way: its signature no longer verifies.
    let mut create = server.create_group(conversation);
    let a2_key_package = &mut create["key_packages"][a.to_string().as_str()][1];
    let mut damaged = bytes(a2_key_package);
    let last = damaged.len() - 1;
    damaged[last] ^= 1;
    *a2_key_package = json!(b64(&damaged));
    create["key_packages"][b.to_string().as_str()]
        .as_array_mut()
        .unwrap()
        .push(json!(server.virtual_key_package(b3, 60 * 60)));

    // Two hours on by the core's clock, B3's has expired (the system's clock, which OpenMLS reads,
    // hasn't moved).
    server.clock.advance(2 * 60 * 60 * 1000);

    // The group is made with the devices that have one, and names those it skipped.
    let created = server.commit(&mut a1, conversation, create).unwrap();
    let skipped: BTreeSet<(String, String)> = created["skipped_devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|skipped| {
            let text = |field: &str| skipped[field].as_str().unwrap().to_string();
            (text("user_id"), text("device_id"))
        })
        .collect();
    assert_eq!(
        skipped,
        BTreeSet::from([
            (a.to_string(), a2.id.to_string()),
            (b.to_string(), b2.id.to_string()),
            (b.to_string(), b3.to_string()),
        ])
    );
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 1);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, b1.id]));
    for device in [&mut a2, &mut b2] {
        assert!(server.deliver(device).is_empty());
        assert_eq!(device.no_group(conversation)["what"], "group");
    }
}

/// `observe_user` for `user` with an identity the test makes up, listing `devices`: what a device
/// sees once the user started over with a new identity.
fn another_identity(user: Uuid, devices: &[Uuid]) -> Value {
    let identity = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let key: [u8; 32] = identity.public().try_into().unwrap();
    let list = DeviceList::new(user, key, 1, devices.to_vec())
        .sign(&identity)
        .unwrap();
    json!({
        "cmd": "observe_user",
        "user_id": user,
        "identity_key": b64(&key),
        "device_list": b64(&list),
        "certificates": [],
    })
}

#[test]
fn welcome_accepts_stale_devices_not_other_identities() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut b2, mut c1, mut d1] = new_devices(&mut server, [a, b, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // A adds C. Before C takes the welcome, B drops B2 from its devices and C sees B's new list:
    // the welcome's tree still has B2's leaf.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &list["device_list"]);
    server.introduce(&mut c1);

    // C enters all the same: B2 is on its way out of the group, for C as for the members.
    let joined = results(&server.deliver(&mut c1));
    assert_eq!(
        (&joined[0][1], &joined[0][2]),
        (&json!("welcome"), &json!("applied")),
        "{joined:?}"
    );
    assert!(device_set(&c1.group(conversation)).contains(&b2.id));

    // The API proposes B2's removal: C sends nothing before the commit that makes it, which C may
    // make itself.
    server.remove_device(conversation, b2.id);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);
    let wait = ready(&mut c1, conversation).unwrap_err();
    assert_eq!(wait["code"], "pending_proposals");
    server
        .commit(
            &mut c1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut b1, &mut c1], conversation);
    assert_eq!(state["epoch"], 3);
    assert!(!device_set(&state).contains(&b2.id));

    // D pinned another identity for B than the one that certified B1's leaf, as after B started
    // over: D first asks to observe B anew, then, still pinning it, can't tell that leaf from a
    // forged one, and stays out.
    let add = adding(&mut server, conversation, d);
    server.commit(&mut a1, conversation, add).unwrap();
    let other = another_identity(b, &[b1.id]);
    assert_eq!(ok(&mut d1.core, other.clone())["state"], "changed");
    let welcome = server.entries(conversation).last().unwrap().clone();
    assert_eq!(welcome["kind"], "welcome");
    let asked = error(
        &mut d1.core,
        apply(conversation, std::slice::from_ref(&welcome)),
    );
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([b.to_string()]))
    );
    assert_eq!(ok(&mut d1.core, other)["state"], "same");
    let refused = ok(
        &mut d1.core,
        apply(conversation, std::slice::from_ref(&welcome)),
    );
    assert_eq!(
        results(&[refused]),
        [json!([
            welcome["seq"],
            "welcome",
            "rejected",
            "leaf_not_signed"
        ])]
    );
    assert_eq!(d1.no_group(conversation)["what"], "group");
}

#[test]
fn stale_leaf_does_not_keep_anyone_out() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    let mut b2 = server.device(b);
    let mut c1 = server.device(c);
    // A device of B's that never comes back. Its leaf keeps its key package's lifetime, which
    // here ends in seconds: OpenMLS reads the system's clock, which the test can't move.
    let gone = server.virtual_device(b);
    // B2 publishes no key package: it joins later, by external commit.
    for device in [&mut a1, &mut b1, &mut c1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut b1, &mut b2, &mut c1] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);

    let mut create = server.create_group(conversation);
    let short = server.virtual_key_package(gone, 3);
    let ends = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3;
    create["key_packages"][b.to_string().as_str()]
        .as_array_mut()
        .unwrap()
        .push(json!(short));
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert!(device_set(&a1.group(conversation)).contains(&gone));
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= ends
    {
        std::thread::sleep(Duration::from_millis(200));
    }

    // Its leaf is stale now: C still enters by a welcome, and B2 by an external commit.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let join = joining(&server, conversation);
    server.commit(&mut b2, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut b1, &mut b2, &mut c1], conversation);
    assert_eq!(state["epoch"], 3);
    assert_eq!(
        device_set(&state),
        BTreeSet::from([a1.id, b1.id, gone, b2.id, c1.id])
    );
}

#[test]
fn corrupted_proposal_queue_is_an_error() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1] = new_devices(&mut server, [a, a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    server.remove_device(conversation, a2.id);
    server.deliver(&mut b1);

    // The proposal goes from under its queue's list of references.
    b1.core
        .transaction(|tx| {
            let removed = tx.conn().execute(
                "DELETE FROM openmls_kv WHERE substr(key, 1, 14) = ?1",
                [b"QueuedProposal".as_slice()],
            )?;
            assert_eq!(removed, 1);
            Ok(())
        })
        .unwrap();

    // Loading the group fails as a storage failure, not with a panic, which aborts the web's worker.
    let refused = b1.no_group(conversation);
    assert_eq!(refused["code"], "storage", "{refused}");
}
