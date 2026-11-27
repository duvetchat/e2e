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
    CommitAad, DeviceList, Entry, Kind, MemberList, group_config, group_id, group_id_parts,
    join_config, leaf_capabilities,
};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    KeyPackageIn, LeafNodeParameters, MlsGroup, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
    OpenMlsProvider, ProtocolVersion, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use rusqlite::OptionalExtension as _;
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

    // A1's comes first; B1's gets the 409. B1 keeps it until the queue shows which commit took
    // the epoch: A1's, which B1 merges in its place.
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

/// `apply`'s `commit_due` with no entries, as a client reads it after observing a user.
fn commit_due(device: &mut TestDevice, conversation: Uuid) -> Value {
    ok(&mut device.core, apply(conversation, &[]))["commit_due"].clone()
}

/// `apply` says when this device would take leaves out with `commit_pending`: a removal the server
/// proposed, or a leaf whose device is off its user's latest list as this device knows it, which a
/// member that only reads would otherwise keep until it sends. Not on the device a removal takes
/// out, and no more once the commit that takes them out is in.
#[test]
fn apply_says_when_a_commit_is_due() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1, mut b2, mut b3] = new_devices(&mut server, [a, b, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut b3]);
    assert_eq!(commit_due(&mut a1, conversation), false);

    // The API proposes B2's removal: every member but B2 would commit it.
    server.remove_device(conversation, b2.id);
    assert_eq!(server.deliver(&mut a1)[0]["commit_due"], true);
    assert_eq!(server.deliver(&mut b1)[0]["commit_due"], true);
    assert_eq!(server.deliver(&mut b2)[0]["commit_due"], false);
    assert_eq!(server.deliver(&mut b3)[0]["commit_due"], true);

    // A1 commits it: until the server's answer, `apply` itself refuses.
    let pending = command("commit_pending", conversation);
    let made = ok(&mut a1.core, pending.clone());
    let waiting = error(&mut a1.core, apply(conversation, &[]));
    assert_eq!(waiting["code"], "pending_commit");
    server.submit(&mut a1, conversation, &made).unwrap();

    // B1's commit of the same removal comes too late, and the server refuses it. While the queue
    // hasn't settled it, nothing is due on B1, though the removal waits there still.
    let late = ok(&mut b1.core, pending.clone());
    assert_eq!(
        server.submit(&mut b1, conversation, &late),
        Err(Refusal::Conflict)
    );
    assert_eq!(commit_due(&mut b1, conversation), false);

    // B3 is handed A1's commit with a byte changed, which blocks its group: nothing is due there
    // either, though the removal waits there too.
    let mut changed = server.entries(conversation).last().unwrap().clone();
    let mut data = bytes(&changed["data"]);
    *data.last_mut().unwrap() ^= 1;
    changed["data"] = json!(b64(&data));
    let seq = changed["seq"].clone();
    let blocked = ok(&mut b3.core, apply(conversation, &[changed]));
    assert_eq!(
        results(std::slice::from_ref(&blocked)),
        [json!([seq, "commit", "rejected", "invalid_commit"])]
    );
    assert_eq!(blocked["commit_due"], false);
    assert_eq!(b3.group(conversation)["blocked"], true);

    // The commit in, nothing is due on A1 or B1.
    assert_eq!(server.deliver(&mut a1)[0]["commit_due"], false);
    assert_eq!(server.deliver(&mut b1)[0]["commit_due"], false);

    // B takes B3 off its list. Once A1, which only reads, sees the new list, its next apply says
    // so without asking to observe B; the commit asks first, then takes B3 out.
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b3.id]}),
    );
    server.take_list(b, &list["device_list"]);
    assert_eq!(commit_due(&mut a1, conversation), false);
    ok(&mut a1.core, server.observed(b));
    assert_eq!(commit_due(&mut a1, conversation), true);
    let asked = error(&mut a1.core, pending.clone());
    assert_eq!(asked["code"], "needs_identities");
    ok(&mut a1.core, server.observed(b));
    server.commit(&mut a1, conversation, pending).unwrap();
    assert_eq!(server.deliver(&mut a1)[0]["commit_due"], false);
    assert!(!device_set(&a1.group(conversation)).contains(&b3.id));
}

/// A conversation of A, with A1 and A2, and of B, with B1, every device in the group; then the API
/// proposes A2's removal, which no device has applied yet.
fn removal_on_its_way(server: &mut FakeServer) -> (Uuid, Uuid, [TestDevice; 3]) {
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut a2, mut b1] = new_devices(server, [a, a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    server.remove_device(conversation, a2.id);
    (conversation, b, [a1, a2, b1])
}

#[test]
fn own_commit_the_validator_refused_is_dropped() {
    let mut server = FakeServer::new();
    let (conversation, _, [mut a1, _, mut b1]) = removal_on_its_way(&mut server);

    // B1 refreshes before it hears of the removal, and the validator refuses a commit that leaves
    // a pending removal out.
    let made = ok(&mut b1.core, command("refresh", conversation));
    // (An answer that takes a commit says where in the queue it is: one without is refused.)
    let unnumbered = error(
        &mut b1.core,
        json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true}),
    );
    assert_eq!(
        (&unnumbered["code"], &unnumbered["field"]),
        (&json!("bad_command"), &json!("seq"))
    );
    assert_eq!(
        server.submit(&mut b1, conversation, &made),
        Err(Refusal::Invalid("pending_removal_dropped".into()))
    );

    // The answer says it never entered: B1 drops it at once, and may send and commit again.
    assert_eq!(ready(&mut b1, conversation), Ok(()));
    server.deliver(&mut b1);
    assert_eq!(
        ready(&mut b1, conversation).unwrap_err()["code"],
        "pending_proposals"
    );
    server
        .commit(
            &mut b1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(ready(&mut b1, conversation), Ok(()));
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 2);
}

#[test]
fn own_commit_a_proposal_shows_left_out_is_dropped() {
    let mut server = FakeServer::new();
    let (conversation, _, [mut a1, _, mut b1]) = removal_on_its_way(&mut server);

    // The same refresh, but B1 doesn't get the answer: it can't tell whether the commit entered.
    let made = ok(&mut b1.core, command("refresh", conversation));
    assert!(matches!(
        server.answer_lost(&mut b1, conversation, &made),
        Err(Refusal::Invalid(_))
    ));
    assert_eq!(
        ready(&mut b1, conversation).unwrap_err()["code"],
        "pending_commit"
    );

    // The queue brings the API's proposal at the commit's epoch, which the commit doesn't carry:
    // the validator would have refused it, so it never entered, and B1 drops it.
    let replies = server.deliver(&mut b1);
    assert_eq!(results(&replies), [json!([3, "proposal", "applied", null])]);
    assert_eq!(
        ready(&mut b1, conversation).unwrap_err()["code"],
        "pending_proposals"
    );
    server
        .commit(
            &mut b1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 2);
}

#[test]
fn own_commit_in_other_bytes_is_still_known() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B1's refresh is taken but heard as refused; and its echo can't know it, as when the queue
    // carries the commit in other bytes than those B1 made.
    let made = ok(&mut b1.core, command("refresh", conversation));
    let seq = server.take_unheard(&mut b1, conversation, &made);
    b1.core
        .transaction(|tx| {
            tx.conn().execute("UPDATE groups SET echo = NULL", [])?;
            Ok(())
        })
        .unwrap();

    // OpenMLS still knows it as B1's waiting commit: B1 merges it.
    let replies = server.deliver(&mut b1);
    assert_eq!(results(&replies), [json!([seq, "commit", "own", null])]);
    server.deliver(&mut a1);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["blocked"], false);
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

    // A1 takes the winner's welcome, which matches its record. A2, whose key package that refused
    // welcome used up, joins by external commit, its client passing the record there too: refused,
    // as the record has B owning the group. Once its person has checked the members, its client
    // stops passing the record, and A2 joins. All four end in one group.
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let mut join = joining(&server, conversation);
    join["expected"] = json!({"owner": b, "members": [a, b]});
    let refused = error(&mut a2.core, join);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    server
        .commit(&mut a2, conversation, joining(&server, conversation))
        .unwrap();
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
fn founding_welcome_takes_the_record_in_any_order() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    // B's client keeps its record of a group and of a DM with B first, the API with A first: a
    // record keeps no order, and B1 takes each founding welcome.
    for (kind, owner) in [(Kind::Group, Some(a)), (Kind::Dm, None)] {
        let conversation = new_id();
        server.conversation(conversation, kind, owner, &[a, b], true);
        b1.remember(conversation, owner, &[b, a]);
        start(&mut server, &mut a1, conversation);
        let taken = server.deliver(&mut b1);
        assert_eq!(
            results(&taken),
            [json!([2, "welcome", "applied", null])],
            "{kind:?}"
        );
    }
}

#[test]
fn dm_join_takes_the_record_in_any_order() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], true);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B's new device joins the DM by external commit, with B's record of it, B first.
    let [mut b2] = new_devices(&mut server, [b]);
    let mut join = joining(&server, conversation);
    join["expected"] = json!({"owner": null, "members": [b, a]});
    server.commit(&mut b2, conversation, join).unwrap();
}

#[test]
fn create_group_keeps_to_the_record() {
    let mut server = FakeServer::new();
    let (a, b, x) = (new_id(), new_id(), new_id());
    let [mut a1, _b1, _x1] = new_devices(&mut server, [a, b, x]);

    // The API lists X, whom A's client never showed, beside A, the owner, and B. A1 makes the
    // group with its record beside the API's list, and refuses: X is no user of the record.
    let planted = new_id();
    server.conversation(planted, Kind::Group, Some(a), &[a, b, x], true);
    let mut create = server.create_group(planted);
    create["expected"] = json!({"owner": a, "members": [a, b]});
    let refused = error(&mut a1.core, create);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    assert_eq!(a1.no_group(planted)["what"], "group");

    // The record's users, whatever order it keeps them in, make the group.
    for members in [[a, b], [b, a]] {
        let conversation = new_id();
        server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
        let mut create = server.create_group(conversation);
        create["expected"] = json!({"owner": a, "members": members});
        assert_eq!(ok(&mut a1.core, create)["generation"], 0);
    }
}

/// A group from before the cutover with more than 20 people keeps them all (ruling 38): it starts
/// with every one of them, its devices holding it to their records of the conversation, and its
/// members renew their leaves and take someone out; but it takes no one in while it's past 20,
/// from its owner's core or past a server that skips its validator.
#[test]
fn a_legacy_group_past_20_keeps_its_members() {
    let mut server = FakeServer::new();
    let (o, a, b, c) = (new_id(), new_id(), new_id(), new_id());
    let [mut o1, mut a1, mut b1, mut c1] = new_devices(&mut server, [o, a, b, c]);
    // O, its owner, A, B, and 19 people whose devices haven't come yet.
    let mut users = vec![o, a, b];
    users.extend((0..19).map(|_| new_id()));
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(o), &users, true);
    o1.remember(conversation, Some(o), &users);
    b1.remember(conversation, Some(o), &users);

    // A, not its owner, makes epoch 0 with all 22, as its own record has them, and the validator
    // takes it as the conversation's; O and B take the welcome, held to their records.
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "group",
        "owner": o,
        "members": users,
        "key_packages": server.claim(&[o, a, b]),
        "external_sender": server.external_sender(),
        "legacy": true,
        "expected": {"owner": o, "members": users},
    });
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut o1, &mut a1, &mut b1]);
    let state = same_group(&mut [&mut o1, &mut a1, &mut b1], conversation);
    assert_eq!(members(&state), users);

    // A renews its leaf, and O takes B out: 21 stay.
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut o1, &mut a1, &mut b1]);
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut o1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut o1, &mut a1, &mut b1]);
    let state = same_group(&mut [&mut o1, &mut a1], conversation);
    assert_eq!(state["epoch"], 3);
    assert_eq!(members(&state).len(), 21);
    assert_eq!(b1.no_group(conversation)["what"], "membership");

    // No one comes in while it's past 20: O's core makes no such add...
    let add = adding(&mut server, conversation, c);
    let refused = error(&mut o1.core, add.clone());
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("too_many_members"))
    );

    // ...the validator takes none O makes by hand, and when a server that skips it queues one, A
    // refuses the commit and C its welcome.
    let key_package = &add["users"][0]["key_packages"][0];
    let (commit, welcome, group_info) = add_by_hand(&mut o1, conversation, Some(c), key_package);
    let checked = server.check(conversation, &commit, &group_info);
    assert_eq!(
        checked.error.map(|refusal| refusal.code).as_deref(),
        Some("too_many_members")
    );
    let commit_seq = server.force(conversation, "commit", commit);
    let welcome_seq = server.force(conversation, "welcome", welcome);
    assert_eq!(
        results(&server.deliver(&mut a1)),
        [
            json!([commit_seq, "commit", "rejected", "too_many_members"]),
            json!([welcome_seq, "welcome", "ignored", null]),
        ]
    );
    let welcome = server.entries(conversation)[welcome_seq as usize - 1].clone();
    let refused = ok(&mut c1.core, apply(conversation, &[welcome]));
    assert_eq!(
        results(&[refused]),
        [json!([
            welcome_seq,
            "welcome",
            "rejected",
            "too_many_members"
        ])]
    );
}

#[test]
fn reset_without_the_group_is_refused() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A2, a device of the owner that never held the group, can't make its next generation: a reset
    // holds the API's members to the group it holds, so it has none to hold them to, whatever
    // record its client passes.
    let [mut a2] = new_devices(&mut server, [a]);
    let mut reset = server.reset_group(conversation, &[b]);
    reset["expected"] = json!({"owner": a, "members": [a, b]});
    let refused = error(&mut a2.core, reset);
    assert_eq!(
        (&refused["code"], &refused["what"]),
        (&json!("not_found"), &json!("group"))
    );
}

#[test]
fn reset_welcome_goes_by_the_reset_not_the_record() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    b1.remember(conversation, Some(a), &[a, b]);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A adds C, after the cutover.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // A resets the group. B1's welcome to the next generation, even with B1's record from before
    // the cutover beside it, goes by the reset: the members B1 had, C among them.
    let reset = server.reset_group(conversation, &[a, b, c]);
    server.commit(&mut a1, conversation, reset).unwrap();
    let mut entries = server.entries(conversation)[4..].to_vec();
    assert_eq!(entries[1]["kind"], "welcome");
    entries[1]["expected"] = json!({"owner": a, "members": [a, b]});
    let taken = ok(&mut b1.core, apply(conversation, &entries));
    assert_eq!(
        results(std::slice::from_ref(&taken)),
        [
            json!([5, "commit", "ignored", null]),
            json!([6, "welcome", "applied", null]),
        ]
    );
    let state = b1.group(conversation);
    assert_eq!(state["generation"], 1);
    assert_eq!(members(&state), [a, b, c]);
}

#[test]
fn re_added_member_keeps_to_the_record() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], true);
    b1.remember(conversation, Some(a), &[a, b, c]);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // A removes B, then adds B back, still in the first group: the list is now A, C, B.
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    assert_eq!(b1.no_group(conversation)["what"], "membership");
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();

    // B1's welcome to that later epoch, with B1's record from before the cutover beside it, keeps
    // to it: every user listed is the record's, in another order, and A, its owner, still owns
    // the group.
    let mut entries = server.entries(conversation)[3..].to_vec();
    assert_eq!(entries[1]["kind"], "welcome");
    entries[1]["expected"] = json!({"owner": a, "members": [a, b, c]});
    let back = ok(&mut b1.core, apply(conversation, &entries));
    assert_eq!(
        results(std::slice::from_ref(&back)),
        [
            json!([4, "commit", "ignored", null]),
            json!([5, "welcome", "applied", null]),
        ]
    );
    server.deliver_all(&mut [&mut a1, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut b1, &mut c1], conversation);
    assert_eq!(members(&state), [a, c, b]);
}

/// A conversation from before the cutover whose group X founded alone: X is an account the server
/// lists beside A, the owner, and B in a group, or in B's place in a DM of A and B, as A's client
/// recorded it. X's next commit, made by hand past the validator, brings A1's device and moves X's
/// own entry to the epoch it makes, so X looks added later. A1, A2 (another device of A), the
/// conversation, that commit's welcome and an external join on its group info, both with A's
/// record.
fn planted_founder(
    server: &mut FakeServer,
    kind: Kind,
) -> (TestDevice, TestDevice, Uuid, Value, Value) {
    let (a, b, x) = (new_id(), new_id(), new_id());
    let [a1, a2, _b1, mut x1] = new_devices(server, [a, a, b, x]);
    let conversation = new_id();
    let (owner, listed) = match kind {
        Kind::Group => (Some(a), vec![a, b, x]),
        Kind::Dm => (None, vec![a, x]),
    };
    server.conversation(conversation, kind, owner, &listed, true);
    let mut create = server.create_group(conversation);
    create["key_packages"] = json!({});
    server.commit(&mut x1, conversation, create).unwrap();

    let key_package = json!(server.last_resort(a1.id));
    let (commit, welcome, group_info) = add_by_hand(&mut x1, conversation, Some(x), &key_package);
    server.force(conversation, "commit", commit);
    server.force(conversation, "welcome", welcome);
    let record = json!({"owner": owner, "members": [a, b]});
    let mut entry = server.entries(conversation).last().unwrap().clone();
    entry["expected"] = record.clone();
    let join = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": b64(&group_info),
        "expected": record,
    });
    (a1, a2, conversation, entry, join)
}

#[test]
fn planted_founder_is_refused_in_a_later_welcome() {
    let mut server = FakeServer::new();
    let (mut a1, _, conversation, entry, _) = planted_founder(&mut server, Kind::Group);

    // A1's welcome lists X as entered later, as the owner's addition would be: from the group's
    // state A1 can't tell the two apart, and refuses it, X being no user of the record.
    let seq = entry["seq"].clone();
    let refused = ok(&mut a1.core, apply(conversation, &[entry]));
    assert_eq!(
        results(&[refused]),
        [json!([seq, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(a1.no_group(conversation)["what"], "group");
}

#[test]
fn planted_founder_is_refused_on_an_external_join() {
    let mut server = FakeServer::new();
    let (_, mut a2, conversation, _, join) = planted_founder(&mut server, Kind::Group);

    // A2 joins by external commit on that epoch's group info, with A's record: refused, as X is no
    // user of the record, however late its entry says it came.
    let refused = error(&mut a2.core, join);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    assert_eq!(a2.no_group(conversation)["what"], "group");
}

#[test]
fn swapped_dm_user_is_refused_in_a_later_welcome() {
    let mut server = FakeServer::new();
    let (mut a1, _, conversation, entry, _) = planted_founder(&mut server, Kind::Dm);

    // A's client recorded the DM with B. The server's device made it with X, and lists X as
    // entered at the commit that brings A1. A DM's users never change: A1 refuses the welcome.
    let seq = entry["seq"].clone();
    let refused = ok(&mut a1.core, apply(conversation, &[entry]));
    assert_eq!(
        results(&[refused]),
        [json!([seq, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(a1.no_group(conversation)["what"], "group");
}

#[test]
fn swapped_dm_user_is_refused_on_an_external_join() {
    let mut server = FakeServer::new();
    let (_, mut a2, conversation, _, join) = planted_founder(&mut server, Kind::Dm);

    // A2 joins that DM by external commit, with A's record of it with B: refused.
    let refused = error(&mut a2.core, join);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    assert_eq!(a2.no_group(conversation)["what"], "group");
}

#[test]
fn planted_founder_is_refused_after_a_reset() {
    let mut server = FakeServer::new();
    let (a, b, x) = (new_id(), new_id(), new_id());
    let [mut a1, _b1, mut x1] = new_devices(&mut server, [a, b, x]);
    let conversation = new_id();
    // The server lists X beside A, the owner, and B. X founds the group with every device, and A1,
    // whose client had no record of the conversation, takes it as it comes. A resets the group,
    // X among its members.
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, x], true);
    let create = server.create_group(conversation);
    server.commit(&mut x1, conversation, create).unwrap();
    server.deliver(&mut a1);
    let reset = server.reset_group(conversation, &[x]);
    server.commit(&mut a1, conversation, reset).unwrap();
    server.deliver(&mut x1);

    // X's next commit, made by hand past the validator, brings A's new device and moves X's entry
    // to the epoch it makes. A2, whose client has A's record and which never held the group,
    // refuses the welcome: X is no user of the record.
    let [mut a2] = new_devices(&mut server, [a]);
    let key_package = json!(server.last_resort(a2.id));
    let (commit, welcome, _) = add_by_hand(&mut x1, conversation, Some(x), &key_package);
    server.force(conversation, "commit", commit);
    let seq = server.force(conversation, "welcome", welcome);
    let mut entry = server.entries(conversation).last().unwrap().clone();
    entry["expected"] = json!({"owner": a, "members": [a, b]});
    let refused = ok(&mut a2.core, apply(conversation, &[entry]));
    assert_eq!(
        results(&[refused]),
        [json!([seq, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(a2.no_group(conversation)["what"], "group");
}

#[test]
fn user_added_after_the_cutover_is_refused_to_a_late_joiner() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // A added C after the cutover, as the owner may. B's new device, whose client has B's record of
    // the conversation, joins late with it: from the group's state it can't tell the owner's
    // addition from one the server's device wrote, and refuses C. That's the cost the rule
    // accepts. Once its person has checked the members, its client stops passing the record.
    let [mut b2] = new_devices(&mut server, [b]);
    let mut join = joining(&server, conversation);
    join["expected"] = json!({"owner": a, "members": [a, b]});
    let refused = error(&mut b2.core, join);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    server
        .commit(&mut b2, conversation, joining(&server, conversation))
        .unwrap();
}

#[test]
fn new_devices_keep_to_the_record() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B gets two devices after the cutover, whose client has B's record of the conversation. B3
    // joins by external commit with it, at a later epoch: A and B, the users listed, are the
    // record's.
    let [mut b2, mut b3] = new_devices(&mut server, [b, b]);
    let record = json!({"owner": a, "members": [a, b]});
    server.introduce(&mut a1);
    let mut join = joining(&server, conversation);
    join["expected"] = record.clone();
    server.commit(&mut b3, conversation, join).unwrap();
    server.deliver(&mut a1);

    // A1 brings B2 in its next commit, made by hand, as no command adds a member's device, and B2
    // takes the welcome with the record beside it.
    let key_package = json!(server.last_resort(b2.id));
    let (commit, welcome, _) = add_by_hand(&mut a1, conversation, None, &key_package);
    server.force(conversation, "commit", commit);
    let seq = server.force(conversation, "welcome", welcome);
    let mut entry = server.entries(conversation).last().unwrap().clone();
    entry["expected"] = record;
    let taken = ok(&mut b2.core, apply(conversation, &[entry]));
    assert_eq!(
        results(&[taken]),
        [json!([seq, "welcome", "applied", null])]
    );
    assert_eq!(members(&b2.group(conversation)), [a, b]);
}

#[test]
fn reset_welcome_keeps_a_new_device_to_the_record() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A adds C after the cutover. Then B gets a device that never held the group, whose client has
    // B's record from before the cutover.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let [mut b2] = new_devices(&mut server, [b]);
    b2.remember(conversation, Some(a), &[a, b]);
    server.introduce(&mut a1);

    // A resets the group. B2's welcome to the next generation, with the record beside it, lists C,
    // a user the record doesn't have: B2 refuses it.
    let reset = server.reset_group(conversation, &[a, b, c]);
    server.commit(&mut a1, conversation, reset).unwrap();
    let refused = server.deliver(&mut b2);
    assert_eq!(
        results(&refused),
        [json!([6, "welcome", "rejected", "member_list_mismatch"])]
    );
    assert_eq!(b2.no_group(conversation)["what"], "group");
}

#[test]
fn removed_device_keeps_to_the_record_at_a_later_generation() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], true);
    b1.remember(conversation, Some(a), &[a, b]);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A adds C after the cutover, then removes B: B1 keeps its row, without the group.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    assert_eq!(b1.no_group(conversation)["what"], "membership");

    // A resets the group and adds B back at the next generation. B1's welcome, its record beside
    // it, lists C, a user the record doesn't have: B1 refuses it, from its row as without one.
    let reset = server.reset_group(conversation, &[c]);
    server.commit(&mut a1, conversation, reset).unwrap();
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    assert_eq!(
        results(&server.deliver(&mut b1)),
        [
            json!([6, "commit", "ignored", null]),
            json!([7, "welcome", "ignored", null]),
            json!([8, "commit", "ignored", null]),
            json!([9, "welcome", "rejected", "member_list_mismatch"]),
        ]
    );
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
fn removed_device_cannot_rejoin_from_an_old_group_info() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let before = joining(&server, conversation);

    // B1 goes quiet: the API proposes its removal (B stays a member), and A1's commit takes it out.
    server.remove_device(conversation, b1.id);
    server.deliver(&mut a1);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(b1.no_group(conversation)["what"], "membership");

    // Handed the group info from before its removal, B1 won't join from it: every member of that
    // epoch, a removed one too, could read what B1 sends in the group it would make.
    let refused = error(&mut b1.core, before);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("stale_group_info"))
    );

    // From the group info of now, B1 comes back.
    let now = joining(&server, conversation);
    server.commit(&mut b1, conversation, now).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 3);
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

    // C1 is asked the same, but observes B's old list again. B's identity certified B2's leaf, which
    // the list C1 holds doesn't name: C1 takes the commit without blocking (B2 may have left B's
    // list since the server took it), and sends nothing until it has looked at B's list again.
    let asked = error(&mut c1.core, apply(conversation, &entries[2..]));
    assert_eq!((asked["code"].clone(), asked["users"].clone()), asked_for_b);
    assert_eq!(ok(&mut c1.core, old_list)["state"], "same");
    let taken = ok(&mut c1.core, apply(conversation, &entries[2..]));
    assert_eq!(results(&[taken]), [json!([3, "commit", "applied", null])]);
    assert_eq!(c1.group(conversation)["blocked"], false);
    let asked = ready(&mut c1, conversation).unwrap_err();
    assert_eq!((asked["code"].clone(), asked["users"].clone()), asked_for_b);
    ok(&mut c1.core, server.observed(b));
    assert_eq!(ready(&mut c1, conversation), Ok(()));

    // B1, once it knows its user's new list, takes it too.
    server.introduce(&mut b1);
    server.deliver(&mut b1);
    let state = same_group(&mut [&mut a1, &mut b1, &mut b2, &mut c1], conversation);
    assert_eq!(state["epoch"], 2);
}

/// `apply`'s `needs_identities`, as its code and users.
fn asked(device: &mut TestDevice, conversation: Uuid, entries: &[Value]) -> (Value, Value) {
    let asked = error(&mut device.core, apply(conversation, entries));
    (asked["code"].clone(), asked["users"].clone())
}

#[test]
fn refused_commits_ask_until_the_client_observed() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let (x, y) = (new_id(), new_id());
    for conversation in [x, y] {
        server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
        start(&mut server, &mut a1, conversation);
    }
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // B's new device joins both conversations, and C1 hasn't seen B's new list.
    let mut b2 = server.device(b);
    server.introduce(&mut b2);
    for conversation in [x, y] {
        let join = joining(&server, conversation);
        server.commit(&mut b2, conversation, join).unwrap();
    }
    let x_entries = server.entries(x)[2..].to_vec();
    let y_entries = server.entries(y)[2..].to_vec();
    let asked_for_b = (json!("needs_identities"), json!([b.to_string()]));

    // C1 is asked about B for X. Before it observes B, Y is refused for B as well: it asks too,
    // and doesn't block.
    assert_eq!(asked(&mut c1, x, &x_entries), asked_for_b);
    assert_eq!(asked(&mut c1, y, &y_entries), asked_for_b);
    // X again, still without observing: it asks again.
    assert_eq!(asked(&mut c1, x, &x_entries), asked_for_b);

    // Once C1 observes B's newer list, both apply.
    ok(&mut c1.core, server.observed(b));
    for (conversation, entries) in [(x, &x_entries), (y, &y_entries)] {
        let taken = ok(&mut c1.core, apply(conversation, entries));
        assert_eq!(results(&[taken]), [json!([3, "commit", "applied", null])]);
        assert_eq!(c1.group(conversation)["blocked"], false);
    }
}

#[test]
fn leave_signed_by_a_device_unseen_asks_first() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // B's new device joins. A1 and B1 see B's new list; C1 doesn't.
    let mut b2 = server.device(b);
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    let join = joining(&server, conversation);
    server.commit(&mut b2, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // A adds C. C1 enters by the welcome: B2's leaf is certified by B's identity, all a welcome
    // holds it to, so C1 never looked at B's list again.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);
    assert_eq!(c1.group(conversation)["blocked"], false);

    // B leaves with B2's statement, which A1's commit carries.
    server.leave(&mut b2, conversation);
    server.deliver(&mut a1);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();

    // C1 can't verify the statement, B2 being off B's list as C1 knows it: it asks about B first.
    let entries = server.entries(conversation)[5..].to_vec();
    assert_eq!(
        asked(&mut c1, conversation, &entries),
        (json!("needs_identities"), json!([b.to_string()]))
    );
    ok(&mut c1.core, server.observed(b));
    ok(&mut c1.core, apply(conversation, &entries));
    let state = same_group(&mut [&mut a1, &mut c1], conversation);
    assert_eq!(members(&state), [a, c]);
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

/// `device` adds `key_package`'s device from its own group state, without its core's rules, which
/// keeps that state as it was: the commit, the welcome and the group info of the epoch it makes.
/// `user`, when given, is listed as entered at that epoch: added, or moved there when listed.
fn add_by_hand(
    device: &mut TestDevice,
    conversation: Uuid,
    user: Option<Uuid>,
    key_package: &Value,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key_package = KeyPackageIn::tls_deserialize_exact_bytes(&bytes(key_package))
        .unwrap()
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .unwrap();
    device.rolled_back(|tx| {
        let (mut group, _) = mls::load_group(tx, conversation)?;
        let own = tx.own_device()?;
        let context = group.public_group().group_context().clone();
        group.set_aad(CommitAad::new(Vec::new()).encode());
        let provider = tx.provider();
        let mut builder = group.commit_builder().propose_adds([key_package]);
        if let Some(user) = user {
            let mut list = MemberList::from_group_context(&context).unwrap();
            let entered = Entry {
                user,
                generation: group_id_parts(context.group_id()).unwrap().1,
                epoch: context.epoch().as_u64() + 1,
            };
            match list.users.iter_mut().find(|entry| entry.user == user) {
                Some(entry) => *entry = entered,
                None => list.users.push(entered),
            }
            let mut extensions = context.extensions().clone();
            extensions.add_or_replace(list.to_extension()).unwrap();
            builder = builder
                .propose_group_context_extensions(extensions)
                .unwrap();
        }
        let bundle = builder
            .force_self_update(true)
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();
        let group_info = MlsMessageOut::from(bundle.group_info().unwrap().clone());
        Ok((
            tls(bundle.commit()),
            tls(&bundle.to_welcome_msg().unwrap()),
            tls(&group_info),
        ))
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
    let (commit, welcome, _) = add_by_hand(&mut b2, conversation, Some(c), key_package);
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
    let reset = server.reset_group(conversation, &[a, b]);
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

/// `adder`, a member who isn't the owner, adds `user` with `key_package`'s device by a commit made
/// past its core's rules, which a server that skips its validator queues: `adder` and each of
/// `members` refuse it, and their group is blocked.
fn block(
    server: &mut FakeServer,
    adder: &mut TestDevice,
    conversation: Uuid,
    user: Uuid,
    key_package: &Value,
    members: &mut [&mut TestDevice],
) {
    let (commit, welcome, _) = add_by_hand(adder, conversation, Some(user), key_package);
    server.force(conversation, "commit", commit);
    server.force(conversation, "welcome", welcome);
    server.deliver(adder);
    assert_eq!(adder.group(conversation)["blocked"], true);
    for member in members.iter_mut() {
        server.deliver(member);
        assert_eq!(member.group(conversation)["blocked"], true);
    }
}

/// `users`, entered at the start of `generation`.
fn at_start(users: &[Uuid], generation: u32) -> Vec<Entry> {
    users
        .iter()
        .map(|&user| Entry {
            user,
            generation,
            epoch: 0,
        })
        .collect()
}

/// `device` makes `conversation`'s next generation past its core's rules, from its own keys: epoch
/// 0 with `list`, and a first commit that adds the devices of `key_packages`. The commit and its
/// welcome; the device keeps nothing of it.
fn reset_by_hand(
    device: &mut TestDevice,
    conversation: Uuid,
    list: &MemberList,
    key_packages: &[Value],
) -> (Vec<u8>, Vec<u8>) {
    let key_packages: Vec<_> = key_packages
        .iter()
        .map(|key_package| {
            KeyPackageIn::tls_deserialize_exact_bytes(&bytes(key_package))
                .unwrap()
                .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
                .unwrap()
        })
        .collect();
    device.rolled_back(|tx| {
        let (group, row) = mls::load_group(tx, conversation)?;
        let api = group.extensions().external_senders().unwrap()[0].clone();
        let own = tx.own_device()?;
        let provider = tx.provider();
        let mut next = MlsGroup::new_with_group_id(
            provider,
            &own.signer,
            &group_config(list, api),
            group_id(conversation, row.generation + 1),
            own.credential()?,
        )
        .unwrap();
        let bundle = next
            .commit_builder()
            .propose_adds(key_packages)
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

/// A group of A, its owner, B and C. C leaves, which the API takes at once, and the group is
/// blocked before any commit takes C's leaf out, so none can. A resets it with the members the API
/// has: the next generation holds A and B. The API takes it as a create, the validator's, which
/// holds epoch 0 to the API's members and runs the rules on it (from epoch 0, the state it starts
/// from first): no change on its side. A reset with the group's own users, C among them, the API
/// would refuse every time, and the conversation would keep its blocked group for good.
#[test]
fn a_reset_founds_the_next_generation_with_the_apis_members() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut a2, mut b1, mut c1, d1] = new_devices(&mut server, [a, a, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut c1]);

    // C leaves: the API takes C off the conversation, and proposes the removal of C's leaf, which
    // the members keep for their next commit.
    server.leave(&mut c1, conversation);
    assert_eq!(server.chats[&conversation].users, [a, b]);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut c1]);

    // Before any commit takes C's leaf out, B, who isn't the owner, adds D past its core: the
    // group is blocked, and still lists C.
    let key_package = json!(server.last_resort(d1.id));
    block(
        &mut server,
        &mut b1,
        conversation,
        d,
        &key_package,
        &mut [&mut a1, &mut a2, &mut c1],
    );
    assert_eq!(members(&a1.group(conversation)), [a, b, c]);

    // A resets it with the members the API has, A and B, and every device of theirs enters the
    // next generation, without C's.
    let reset = server.reset_group(conversation, &[a, b]);
    let reset = server
        .commit(&mut a1, conversation, reset)
        .expect("the API's create takes the reset with its members");
    assert_eq!(reset["generation"], 1);
    assert_eq!(server.chats[&conversation].users, [a, b]);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut a2, &mut b1], conversation);
    assert_eq!(
        (&state["generation"], &state["blocked"], &state["owner"]),
        (&json!(1), &json!(false), &json!(a))
    );
    assert_eq!(members(&state), [a, b]);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, a2.id, b1.id]));
    assert_eq!(c1.group(conversation)["generation"], 0);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
}

/// A group of A, its owner, B and C. A leaves, and the API makes B, who entered first of those who
/// stay, its owner; then the group is blocked before a commit takes A's leaf out, and still names
/// A its owner. B resets it with the members and the owner the API has: B owns the next
/// generation, which B's and C's devices enter, and adds D to it.
#[test]
fn a_reset_names_the_apis_new_owner() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1, mut d1] = new_devices(&mut server, [a, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    server.leave(&mut a1, conversation);
    assert_eq!(server.chats[&conversation].owner, Some(b));
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let key_package = json!(server.last_resort(d1.id));
    block(
        &mut server,
        &mut c1,
        conversation,
        d,
        &key_package,
        &mut [&mut a1, &mut b1],
    );
    assert_eq!(b1.group(conversation)["owner"], json!(a));

    let reset = server.reset_group(conversation, &[b, c]);
    let reset = server
        .commit(&mut b1, conversation, reset)
        .expect("the API takes the reset of the owner it named");
    assert_eq!(reset["generation"], 1);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let state = same_group(&mut [&mut b1, &mut c1], conversation);
    assert_eq!(
        (&state["owner"], &state["blocked"]),
        (&json!(b), &json!(false))
    );
    assert_eq!(members(&state), [b, c]);
    assert_eq!(a1.group(conversation)["generation"], 0);

    let add = adding(&mut server, conversation, d);
    server.commit(&mut b1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut b1, &mut c1, &mut d1]);
    let state = same_group(&mut [&mut b1, &mut c1, &mut d1], conversation);
    assert_eq!(members(&state), [b, c, d]);
}

/// A reset brings no one in: a member its group doesn't list, or a DM's members other than its two
/// users, is `member_list_mismatch`, and nothing is staged.
#[test]
fn a_reset_refuses_a_user_the_group_doesnt_have() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, _c1] = new_devices(&mut server, [a, b, c]);
    let (group, dm) = (new_id(), new_id());
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    server.conversation(dm, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, group);
    start(&mut server, &mut a1, dm);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A reset without the API's members is a command the core can't read.
    let missing = error(
        &mut a1.core,
        json!({"cmd": "reset_group", "conversation_id": group, "owner": a}),
    );
    assert_eq!(
        (&missing["code"], &missing["field"]),
        (&json!("bad_command"), &json!("members"))
    );
    let reset = |conversation: Uuid, owner: Option<Uuid>, members: &[Uuid]| {
        json!({
            "cmd": "reset_group",
            "conversation_id": conversation,
            "owner": owner,
            "members": members,
        })
    };
    for command in [
        reset(group, Some(a), &[a, b, c]),
        reset(group, Some(a), &[a, c]),
        reset(dm, None, &[a, c]),
        reset(dm, None, &[a, b, c]),
        reset(dm, None, &[a]),
    ] {
        let refused = error(&mut a1.core, command);
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("member_list_mismatch"))
        );
    }
    for conversation in [group, dm] {
        let reset = server.reset_group(conversation, &[a, b]);
        server.commit(&mut a1, conversation, reset).unwrap();
    }
}

/// A group's reset names its owner among its members: the one the group has while they stay, else
/// the first of those who stay to have entered, as the API names one. Any other owner, or none, is
/// `member_list_mismatch`, and nothing is staged.
#[test]
fn a_reset_refuses_an_owner_outside_its_members() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // C outside the members; none; B while A, the owner, stays; and without A, C, who entered
    // after B.
    for (owner, members) in [
        (Some(c), vec![a, b]),
        (None, vec![a, b, c]),
        (Some(b), vec![a, b, c]),
        (Some(c), vec![b, c]),
    ] {
        let command = json!({
            "cmd": "reset_group",
            "conversation_id": conversation,
            "owner": owner,
            "members": members,
        });
        let refused = error(&mut a1.core, command);
        assert_eq!(
            (&refused["code"], &refused["rule"]),
            (&json!("rule_violation"), &json!("member_list_mismatch"))
        );
    }
    let reset = server.reset_group(conversation, &[a, b, c]);
    server.commit(&mut a1, conversation, reset).unwrap();
}

/// Members take a reset that leaves a user out only from the owner it names, as the validator holds
/// a group's epoch 0 to its owner: B, who isn't the owner, makes the next generation without C past
/// its core, which a server that skips its validator queues, and A refuses its welcome, keeping its
/// group as it was.
#[test]
fn a_reset_welcome_without_a_member_must_be_its_owners() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    let list = MemberList::new(Kind::Group, Some(a), at_start(&[a, b], 1));
    let key_package = json!(server.last_resort(a1.id));
    let (commit, welcome) = reset_by_hand(&mut b1, conversation, &list, &[key_package]);
    let commit_seq = server.force(conversation, "commit", commit);
    let welcome_seq = server.force(conversation, "welcome", welcome);
    assert_eq!(
        results(&server.deliver(&mut a1)),
        [
            json!([commit_seq, "commit", "ignored", null]),
            json!([
                welcome_seq,
                "welcome",
                "rejected",
                "members_changed_by_non_owner"
            ]),
        ]
    );
    let state = a1.group(conversation);
    assert_eq!(
        (&state["generation"], &state["blocked"]),
        (&json!(0), &json!(false))
    );
    assert_eq!(members(&state), [a, b, c]);
}

/// A reset's welcome is held to the members its group had, without those who left: one that brings
/// a user in, or names an owner other than the one who stays or else the first of those who stay,
/// is refused (`member_list_mismatch`). Each is made past its maker's core, and queued by a server
/// that skips its validator.
#[test]
fn a_reset_welcome_is_held_to_the_members_the_group_had() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1, _d1] = new_devices(&mut server, [a, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    // A, the owner, brings D in with the next generation; C makes it without A, naming C, not B,
    // its owner.
    let key_package = json!(server.last_resort(b1.id));
    let adds = MemberList::new(Kind::Group, Some(a), at_start(&[a, b, c, d], 1));
    let skips = MemberList::new(Kind::Group, Some(c), at_start(&[b, c], 1));
    let mut refused = Vec::new();
    for (maker, list) in [(&mut a1, adds), (&mut c1, skips)] {
        let (commit, welcome) = reset_by_hand(
            maker,
            conversation,
            &list,
            std::slice::from_ref(&key_package),
        );
        let commit_seq = server.force(conversation, "commit", commit);
        let welcome_seq = server.force(conversation, "welcome", welcome);
        refused.push(json!([commit_seq, "commit", "ignored", null]));
        refused.push(json!([
            welcome_seq,
            "welcome",
            "rejected",
            "member_list_mismatch"
        ]));
    }
    assert_eq!(results(&server.deliver(&mut b1)), refused);
    let state = b1.group(conversation);
    assert_eq!(state["generation"], 0);
    assert_eq!(members(&state), [a, b, c]);
}

/// The API takes A, the owner, off the conversation and names B its owner, though A never left: no
/// device holds a statement of A's. B's own core refuses B's reset without A, and C1 refuses it
/// made past B's core, keeping its group as it was: the server can't make anyone the owner.
#[test]
fn a_successors_reset_without_the_owners_statement_is_refused() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    let chat = server.chats.get_mut(&conversation).unwrap();
    chat.users.retain(|&user| user != a);
    chat.owner = Some(b);
    let reset = server.reset_group(conversation, &[b, c]);
    let refused = error(&mut b1.core, reset);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );

    let list = MemberList::new(Kind::Group, Some(b), at_start(&[b, c], 1));
    let key_package = json!(server.last_resort(c1.id));
    let (commit, welcome) = reset_by_hand(&mut b1, conversation, &list, &[key_package]);
    let commit_seq = server.force(conversation, "commit", commit);
    let welcome_seq = server.force(conversation, "welcome", welcome);
    assert_eq!(
        results(&server.deliver(&mut c1)),
        [
            json!([commit_seq, "commit", "ignored", null]),
            json!([welcome_seq, "welcome", "rejected", "member_list_mismatch"]),
        ]
    );
    let state = c1.group(conversation);
    assert_eq!(
        (&state["generation"], &state["owner"], &state["blocked"]),
        (&json!(0), &json!(a), &json!(false))
    );
    assert_eq!(members(&state), [a, b, c]);
}

/// A, the owner, leaves with a statement every device keeps. The API then takes B off too, though B
/// never left, and names C the owner. C's core refuses C's reset, as B, who entered before C, left
/// no statement; and D1 refuses it made past C's core, keeping its group as it was.
#[test]
fn a_reset_that_skips_an_earlier_member_without_their_statement_is_refused() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1, mut d1] = new_devices(&mut server, [a, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c, d], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1, &mut d1]);

    server.leave(&mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1, &mut d1]);
    let chat = server.chats.get_mut(&conversation).unwrap();
    chat.users.retain(|&user| user != b);
    chat.owner = Some(c);
    let reset = server.reset_group(conversation, &[c, d]);
    let refused = error(&mut c1.core, reset);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );

    let list = MemberList::new(Kind::Group, Some(c), at_start(&[c, d], 1));
    let key_package = json!(server.last_resort(d1.id));
    let (commit, welcome) = reset_by_hand(&mut c1, conversation, &list, &[key_package]);
    let commit_seq = server.force(conversation, "commit", commit);
    let welcome_seq = server.force(conversation, "welcome", welcome);
    assert_eq!(
        results(&server.deliver(&mut d1)),
        [
            json!([commit_seq, "commit", "ignored", null]),
            json!([welcome_seq, "welcome", "rejected", "member_list_mismatch"]),
        ]
    );
    let state = d1.group(conversation);
    assert_eq!(
        (&state["generation"], &state["owner"]),
        (&json!(0), &json!(a))
    );
    assert_eq!(members(&state), [a, b, c, d]);
}

/// A's group is blocked before A leaves: each device keeps A's statement all the same, though its
/// blocked group takes no proposal. Until it has it, B's core refuses B's reset without A; with it,
/// B's reset goes through, and C1, which keeps A's statement too, takes its welcome.
#[test]
fn an_owner_who_leaves_after_the_block_lets_the_successor_reset() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1, d1] = new_devices(&mut server, [a, b, c, d]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let key_package = json!(server.last_resort(d1.id));
    block(
        &mut server,
        &mut c1,
        conversation,
        d,
        &key_package,
        &mut [&mut a1, &mut b1],
    );

    // A leaves, from the blocked group: the API names B the owner and proposes the removal of A's
    // leaf, with A's statement. B's core, which hasn't had it yet, refuses B's reset without A.
    server.leave(&mut a1, conversation);
    assert_eq!(server.chats[&conversation].owner, Some(b));
    let proposal_seq = server.chats[&conversation].queue.len() as u64;
    let reset = server.reset_group(conversation, &[b, c]);
    let refused = error(&mut b1.core, reset);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );

    // The proposal comes: the blocked group ignores it, and keeps A's statement.
    assert_eq!(
        results(&server.deliver(&mut b1)),
        [json!([proposal_seq, "proposal", "ignored", null])]
    );
    server.deliver(&mut c1);
    assert_eq!(b1.group(conversation)["blocked"], true);
    let reset = server.reset_group(conversation, &[b, c]);
    server
        .commit(&mut b1, conversation, reset)
        .expect("the API takes the reset of the owner it named");
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let state = same_group(&mut [&mut b1, &mut c1], conversation);
    assert_eq!(
        (&state["generation"], &state["owner"], &state["blocked"]),
        (&json!(1), &json!(b), &json!(false))
    );
    assert_eq!(members(&state), [b, c]);
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
        results(std::slice::from_ref(&first)),
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
        results(std::slice::from_ref(&early)),
        [json!([8, "commit", "ignored", null])]
    );
    assert_eq!(early["applied_through"], 5);

    // The backlog brings the welcome: B1 is back, and takes the refresh after it.
    let backlog = ok(&mut b1.core, apply(conversation, &entries[5..]));
    assert_eq!(
        results(std::slice::from_ref(&backlog)),
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
fn refused_entries_out_of_the_group_keep_the_count() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A removes B, and B1 hears it.
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A adds B again (its commit and B1's welcome), and then the queue holds an entry that isn't an
    // MLS message.
    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver(&mut a1);
    let junk = server.force(conversation, "commit", b"not an MLS message".to_vec());
    let entries = server.entries(conversation);

    // The junk reaches B1 first. Out of the group, its refusal doesn't move B1's count past what
    // B1 still needs.
    let early = ok(&mut b1.core, apply(conversation, &entries[5..6]));
    assert_eq!(
        results(std::slice::from_ref(&early)),
        [json!([junk, "commit", "rejected", "malformed"])]
    );
    assert_eq!(early["applied_through"], 3);

    // The backlog brings the welcome, and B1 is back.
    let backlog = ok(&mut b1.core, apply(conversation, &entries[3..5]));
    assert_eq!(
        results(std::slice::from_ref(&backlog)),
        [
            json!([4, "commit", "ignored", null]),
            json!([5, "welcome", "applied", null]),
        ]
    );
    assert_eq!(backlog["applied_through"], 5);
    same_group(&mut [&mut a1, &mut b1], conversation);
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

#[test]
fn a_spent_key_package_still_takes_its_welcome() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);

    // The API hands one of B1's key packages out for A's group, and tells B1 so as it takes B1's
    // next upload: B1 marks it spent, and hands it out no more.
    let create = server.create_group(conversation);
    let claimed = &create["key_packages"][b.to_string().as_str()][0];
    let published = ok(&mut b1.core, json!({"cmd": "key_packages"}));
    let id = published["key_packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|kp| &kp["data"] == claimed)
        .unwrap()["id"]
        .clone();
    let marked = ok(&mut b1.core, json!({"cmd": "key_packages", "spent": [id]}));
    let shown = marked["key_packages"].as_array().unwrap();
    assert!(shown.iter().all(|kp| kp["id"] != id));

    // On the last of its 45 days B1 tops up again, which keeps its keys, and A's welcome comes:
    // B1 joins with it.
    server.clock.advance(45 * DAY_MS);
    server.publish(&mut b1);
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, b1.id]));
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

    // Loading the group fails as a storage failure, not a panic, which aborts the web's worker.
    let refused = b1.no_group(conversation);
    assert_eq!(refused["code"], "storage", "{refused}");
}

#[test]
fn a_device_that_joined_by_welcome_asks_before_taking_a_leaf_out() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    // B gets B2 once C1 has seen B's list: A1 and B1 see B's newer list, C1 doesn't.
    let mut b2 = server.device(b);
    server.publish(&mut b2);
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);

    // A adds C. C1 enters by the welcome, which holds B2's leaf to B's identity alone: C1 still
    // holds B's list without B2.
    let add = adding(&mut server, conversation, c);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);
    assert!(device_set(&c1.group(conversation)).contains(&b2.id));

    // Before it sends, C1 asks about B, and is served B's newer list: B2 is on it, and C1 sends
    // without taking B2 out.
    let asked = ready(&mut c1, conversation).unwrap_err();
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([b.to_string()]))
    );
    assert_eq!(ok(&mut c1.core, server.observed(b))["state"], "same");
    assert_eq!(ready(&mut c1, conversation), Ok(()));
    assert!(device_set(&c1.group(conversation)).contains(&b2.id));
}

/// `device` takes `conversation`'s whole queue in one `apply`, as a client does: whenever its core
/// asks to observe users first, it observes them as the server has them now, then applies again.
/// What each `observe_user` answered, and the last `apply`'s reply.
fn take_queue(
    server: &FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
) -> (Vec<Value>, Value) {
    let mut observed = Vec::new();
    loop {
        let reply = run(
            &mut device.core,
            &apply(conversation, &server.entries(conversation)),
        );
        let Some(asked) = reply.get("error") else {
            return (observed, reply["ok"].clone());
        };
        assert_eq!(asked["code"], "needs_identities", "{reply}");
        assert!(observed.len() < 3, "asked again and again: {observed:?}");
        for user in asked["users"].as_array().unwrap() {
            let user: Uuid = user.as_str().unwrap().parse().unwrap();
            observed.push(ok(&mut device.core, server.observed(user))["state"].clone());
        }
    }
}

/// While C1 is away, B2, B's new device, joins by external commit; then B takes B2 off its list,
/// and A1 commits the API's proposal of B2's removal. Back, C1 is asked about B and sees B's newest
/// list, which no longer names B2: B2's join applies all the same, as the server took it while B2
/// was listed, and C1 ends where the others are, without blocking.
#[test]
fn a_device_taken_off_its_list_while_a_member_was_away_applies_late() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    let mut b2 = server.device(b);
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    server
        .commit(&mut b2, conversation, joining(&server, conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &list["device_list"]);
    server.introduce(&mut a1);
    server.remove_device(conversation, b2.id);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);

    let (observed, taken) = take_queue(&server, &mut c1, conversation);
    assert_eq!(observed, [json!("same"), json!("same")]);
    assert_eq!(
        results(&[taken]),
        [
            json!([3, "commit", "applied", null]),
            json!([4, "proposal", "applied", null]),
            json!([5, "commit", "applied", null]),
        ]
    );
    assert_eq!(c1.group(conversation)["blocked"], false);
    let state = same_group(&mut [&mut a1, &mut b1, &mut c1], conversation);
    assert_eq!(state["epoch"], 3);
    assert!(!device_set(&state).contains(&b2.id));
}

/// B takes a device off its list and A1 takes it out of A's group, which C1 applies. While C1 is
/// away, a device of D's with the same ID joins by external commit, and then D takes it off its
/// list. Back, C1 sees D's newest list: D's device isn't the one the group took out, which was B's,
/// so its join applies, as any device's that left its list after the server took it.
#[test]
fn a_device_with_the_id_of_another_user_s_removed_one_applies_late() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1, mut d1] = new_devices(&mut server, [a, b, c, d]);
    let shared = new_id();
    let mut bx = server.device_with_id(b, shared);
    server.publish(&mut bx);
    for device in [&mut a1, &mut b1, &mut c1, &mut d1, &mut bx] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c, d], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1, &mut d1, &mut bx]);
    assert!(device_set(&c1.group(conversation)).contains(&shared));

    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [shared]}),
    );
    server.take_list(b, &list["device_list"]);
    server.introduce(&mut a1);
    server.remove_device(conversation, shared);
    server.deliver(&mut a1);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    take_queue(&server, &mut c1, conversation);
    assert!(!device_set(&c1.group(conversation)).contains(&shared));

    let mut dx = server.device_with_id(d, shared);
    server.introduce(&mut dx);
    let joined = server
        .commit(&mut dx, conversation, joining(&server, conversation))
        .unwrap();
    assert!(joined.get("commit").is_some());
    server.introduce(&mut d1);
    let list = ok(
        &mut d1.core,
        json!({"cmd": "sign_device_list", "remove": [shared]}),
    );
    server.take_list(d, &list["device_list"]);

    let (_, taken) = take_queue(&server, &mut c1, conversation);
    let taken = results(&[taken]);
    assert_eq!(taken.last().unwrap()[2], "applied", "{taken:?}");
    assert_eq!(c1.group(conversation)["blocked"], false);
    assert!(device_set(&c1.group(conversation)).contains(&shared));
}

/// A removes B, which C1 applies, and adds B back while C1 is away; then B takes B2 off its list,
/// which C1 sees before it's back (from another conversation, say). B2 left the group with its
/// user, not as a device, so the record of the devices the group took out doesn't hold it, and B's
/// return applies late, as any device's that left its list after the server took it.
#[test]
fn a_device_whose_user_left_and_came_back_applies_late() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut b2, mut c1] = new_devices(&mut server, [a, b, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);

    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    take_queue(&server, &mut c1, conversation);
    assert!(!device_set(&c1.group(conversation)).contains(&b2.id));

    let add = adding(&mut server, conversation, b);
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &list["device_list"]);
    ok(&mut c1.core, server.observed(b));

    let (_, taken) = take_queue(&server, &mut c1, conversation);
    let taken = results(&[taken]);
    let commit = taken.iter().find(|result| result[1] == "commit").unwrap();
    assert_eq!(commit[2], "applied", "{taken:?}");
    assert_eq!(c1.group(conversation)["blocked"], false);
    assert!(device_set(&c1.group(conversation)).contains(&b2.id));
}

/// While C1 is away, B leaves from B2, and A1's commit takes B out with B2's statement; then B takes
/// B2 off its list, which C1 sees. The statement holds for C1 all the same: B's identity certified
/// B2's leaf, and the server took the commit while B2 was listed.
#[test]
fn a_leave_signed_by_a_device_taken_off_its_list_later_applies_late() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut b2, mut c1] = new_devices(&mut server, [a, b, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2, &mut c1]);

    server.leave(&mut b2, conversation);
    server.deliver(&mut a1);
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver(&mut a1);
    let list = ok(
        &mut b1.core,
        json!({"cmd": "sign_device_list", "remove": [b2.id]}),
    );
    server.take_list(b, &list["device_list"]);
    server.introduce(&mut c1);

    let (observed, taken) = take_queue(&server, &mut c1, conversation);
    assert_eq!(observed, [json!("same")]);
    assert_eq!(
        results(&[taken]),
        [
            json!([3, "proposal", "applied", null]),
            json!([4, "proposal", "applied", null]),
            json!([5, "commit", "applied", null]),
        ]
    );
    assert_eq!(c1.group(conversation)["blocked"], false);
    let state = same_group(&mut [&mut a1, &mut c1], conversation);
    assert_eq!(members(&state), [a, c]);
}

/// While C1 is away, B2 joins by external commit; then B starts over on B3, with a new identity
/// whose list has B3 alone, and A1 takes B's old devices out. C1, which has seen B's new identity,
/// takes B2's join under the identity it knows B had before, B2 being off B's new list.
#[test]
fn a_leaf_from_before_its_user_started_over_applies_late() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);

    let mut b2 = server.device(b);
    for device in [&mut a1, &mut b1, &mut b2] {
        server.introduce(device);
    }
    server
        .commit(&mut b2, conversation, joining(&server, conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let mut b3 = server.bare_device(b);
    let reset = ok(&mut b3.core, json!({"cmd": "reset_identity"}));
    server.take_identity(b, &reset);
    server.introduce(&mut a1);
    let asked = ready(&mut a1, conversation).unwrap_err();
    assert_eq!(asked["code"], "needs_identities");
    ok(&mut a1.core, server.observed(b));
    server
        .commit(
            &mut a1,
            conversation,
            command("commit_pending", conversation),
        )
        .unwrap();
    server.deliver(&mut a1);
    server.introduce(&mut c1);

    let (observed, taken) = take_queue(&server, &mut c1, conversation);
    assert_eq!(observed, [json!("same")]);
    assert_eq!(
        results(&[taken]),
        [
            json!([3, "commit", "applied", null]),
            json!([4, "commit", "applied", null]),
        ]
    );
    assert_eq!(c1.group(conversation)["blocked"], false);
    let state = same_group(&mut [&mut a1, &mut c1], conversation);
    assert_eq!(state["epoch"], 3);
    assert_eq!(device_set(&state), BTreeSet::from([a1.id, c1.id]));
}

/// A1 adds C with a key package that lasts seconds, which the server's validator takes, while B1 is
/// away. B1 applies the commit once that key package has expired: the validator checked its
/// lifetime when it took the commit, and B1 takes it without blocking.
#[test]
fn a_commit_applied_after_its_key_package_expired_applies() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    let _c1 = server.device(c);
    // C's device whose key package ends in seconds: OpenMLS reads the system's clock, which the test
    // can't move.
    let short_lived = server.virtual_device(c);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut b1] {
        server.introduce(device);
    }
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    let key_package = server.virtual_key_package(short_lived, 5);
    let ends = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5;
    let add = json!({
        "cmd": "add_members",
        "conversation_id": conversation,
        "users": [{"user_id": c, "key_packages": [key_package]}],
    });
    server.commit(&mut a1, conversation, add).unwrap();
    server.deliver(&mut a1);
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= ends
    {
        std::thread::sleep(Duration::from_millis(200));
    }

    let taken = server.deliver(&mut b1);
    assert_eq!(
        results(&taken),
        [
            json!([3, "commit", "applied", null]),
            json!([4, "welcome", "ignored", null]),
        ]
    );
    assert_eq!(b1.group(conversation)["blocked"], false);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(state["epoch"], 2);
    assert!(device_set(&state).contains(&short_lived));
}

/// A1 renews its leaf, and the client loses the commit before sending it. Told then that the commit
/// wasn't taken, A1 keeps it staged for the queue to settle, and sends nothing meanwhile. Knowing it
/// never sent it, the client reports it refused by the validator: A1 drops it, and writes again.
#[test]
fn a_commit_never_sent_is_dropped_after_its_answer() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    ok(&mut a1.core, command("refresh", conversation));
    let refused =
        json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": false});
    ok(&mut a1.core, refused.clone());
    assert_eq!(
        ready(&mut a1, conversation).unwrap_err()["code"],
        "pending_commit"
    );

    let mut never_sent = refused;
    never_sent["invalid"] = json!(true);
    let dropped = ok(&mut a1.core, never_sent);
    assert_eq!(dropped["epoch"], 1);
    assert_eq!(ready(&mut a1, conversation), Ok(()));
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
}

/// A device whose group the API doesn't hold: its founding answered as taken and never kept, as a
/// lying server does, or a database restored to before it. While it holds the group it can't found
/// it again (`exists`), so it forgets it (`forget_group`), which answers the members the group had
/// as a record, and founds the group again held to it: a list the API makes up isn't taken.
#[test]
fn forget_group_leaves_a_group_the_api_doesnt_hold() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, _c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    let forget = command("forget_group", conversation);

    // Nothing to forget before there's a group.
    let none = error(&mut a1.core, forget.clone());
    assert_eq!(
        (&none["code"], &none["what"]),
        (&json!("not_found"), &json!("group"))
    );

    // The API answers A1's founding as taken, keeps nothing of it, and answers A1's message the
    // same way.
    server.found_unkept(&mut a1, conversation);
    let held = a1.group(conversation);
    assert_eq!(
        error(&mut a1.core, server.create_group(conversation))["code"],
        "exists"
    );
    let nonce = new_id().to_string();
    let typed = json!({"cmd": "encrypt", "conversation_id": conversation, "nonce": nonce, "envelope": {"text": "said before"}});
    ok(&mut a1.core, typed);
    let message_id = new_id();
    ok(
        &mut a1.core,
        json!({"cmd": "sent", "conversation_id": conversation, "nonce": nonce, "message_id": message_id, "seq": 2}),
    );

    // Not while a commit of its own waits for the server's word, nor while one the server answered
    // as refused stays staged for the queue to settle.
    ok(&mut a1.core, command("refresh", conversation));
    assert_eq!(
        error(&mut a1.core, forget.clone())["code"],
        "pending_commit"
    );
    let refused =
        json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": false});
    ok(&mut a1.core, refused.clone());
    assert_eq!(
        error(&mut a1.core, forget.clone())["code"],
        "pending_commit"
    );
    let mut never_sent = refused;
    never_sent["invalid"] = json!(true);
    ok(&mut a1.core, never_sent);
    server.clock.advance(8 * DAY_MS);
    assert_eq!(due(&mut a1), json!([conversation]));

    // A1 forgets it: the group goes, with what it held, and its record is the members it had.
    let record = ok(&mut a1.core, forget.clone());
    assert_eq!(
        record,
        json!({"expected": {"members": [a, b], "exact": true}})
    );
    assert_eq!(a1.no_group(conversation)["what"], "group");
    let again = error(&mut a1.core, forget);
    assert_eq!(
        (&again["code"], &again["what"]),
        (&json!("not_found"), &json!("group"))
    );
    assert_eq!(due(&mut a1), json!([]));
    // The messages it holds stay.
    let page = ok(
        &mut a1.core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 10}),
    );
    let shown: Vec<_> = page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| (message["message_id"].clone(), message["text"].clone()))
        .collect();
    assert_eq!(shown, [(json!(message_id), json!("said before"))]);

    // A list the API makes up is refused against the record...
    let users = |server: &mut FakeServer, users: Vec<Uuid>| {
        server.chats.get_mut(&conversation).unwrap().users = users;
    };
    users(&mut server, vec![a, c]);
    let mut planted = server.create_group(conversation);
    planted["expected"] = record["expected"].clone();
    let mismatch = error(&mut a1.core, planted);
    assert_eq!(
        (&mismatch["code"], &mismatch["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );

    // ...and the members it had found the group again, at generation 0, which B1 enters.
    users(&mut server, vec![a, b]);
    let mut create = server.create_group(conversation);
    create["expected"] = record["expected"].clone();
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(
        (&state["generation"], &state["epoch"]),
        (&json!(0), &json!(1))
    );
    assert_ne!(state["authenticator"], held["authenticator"]);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    same_group(&mut [&mut a1, &mut b1], conversation);
}

/// A device whose own group passed the API's at the same generation (a renewal the API answered as
/// taken and never kept) can't take the API's group by external commit: its group info is of an
/// epoch the device saw pass (`stale_group_info`). Once the device forgets its group it can, held
/// to the record `forget_group` answered.
#[test]
fn forget_group_lets_a_device_take_the_apis_group_past_its_own_epoch() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    server.found_unkept(&mut a1, conversation);
    ok(&mut a1.core, command("refresh", conversation));
    ok(
        &mut a1.core,
        json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": 2}),
    );
    assert_eq!(a1.group(conversation)["epoch"], 2);

    // B1 founds the group the API holds, at epoch 1.
    start(&mut server, &mut b1, conversation);
    let stale = error(&mut a1.core, joining(&server, conversation));
    assert_eq!(
        (&stale["code"], &stale["rule"]),
        (&json!("rule_violation"), &json!("stale_group_info"))
    );

    let record = ok(&mut a1.core, command("forget_group", conversation));
    let mut join = joining(&server, conversation);
    join["expected"] = record["expected"].clone();
    server.commit(&mut a1, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(
        (&state["generation"], &state["epoch"]),
        (&json!(0), &json!(2))
    );
}

/// A device founds a DM alone, with no key package of the other member's, types a message there and
/// forgets it, which leaves the message stale: the JSON
/// each binding sends in its own test (`host-tests/bun`, `duvet-e2e-wasm`'s `web.rs`, the Flutter
/// plugin's `core_test.dart`), with a key the API never signs with as the external sender.
#[test]
fn a_lone_device_forgets_the_group_it_founded() {
    let dir = tempfile::tempdir().unwrap();
    let mut core = duvet_e2e::Core::open(duvet_e2e::OpenConfig::new(
        dir.path().join("core.db"),
        [1; 32],
    ))
    .unwrap();
    let (user, other, conversation) = (new_id(), new_id(), new_id());
    let device = new_id();
    ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": device}),
    );
    ok(&mut core, json!({"cmd": "create_identity"}));
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "dm",
        "members": [user, other],
        "external_sender": b64(&[9; 32]),
    });
    assert_eq!(ok(&mut core, create.clone())["generation"], 0);
    let taken = json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": 1});
    assert_eq!(ok(&mut core, taken)["epoch"], 1);
    let typed = json!({"cmd": "encrypt", "conversation_id": conversation, "nonce": "typed", "envelope": {"text": "hello"}});
    assert_eq!(ok(&mut core, typed.clone())["epoch"], 1);

    let forget = command("forget_group", conversation);
    assert_eq!(
        ok(&mut core, forget.clone()),
        json!({"expected": {"members": [user, other], "exact": true}})
    );
    let stale = error(&mut core, typed);
    assert_eq!(
        (&stale["code"], &stale["rule"]),
        (&json!("rule_violation"), &json!("stale_message"))
    );
    let gone = error(&mut core, command("group", conversation));
    assert_eq!(
        (&gone["code"], &gone["what"]),
        (&json!("not_found"), &json!("group"))
    );
    assert_eq!(error(&mut core, forget)["what"], "group");
    // Founded again at generation 0, the group ID the forgotten one had.
    let mut again = create;
    again["expected"] = json!({"members": [user, other]});
    assert_eq!(ok(&mut core, again)["generation"], 0);
}

/// Another member's group at the generation a device holds: the API kept nothing of A1's founding,
/// and B1 founded the group the API holds. Its welcome opens with one of A1's key packages, but
/// can't be taken over the group A1 holds there: it's `rejected` for `another_group`, not passed
/// by, and its key package is spent, as any rejected welcome's. A1 forgets its group and joins the
/// API's by external commit, held to the record. A welcome A1 can't open stays passed by.
#[test]
fn a_welcome_to_another_group_at_the_devices_generation_is_rejected() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    let own = server.found_unkept(&mut a1, conversation);
    let held = a1.group(conversation);

    // B1 founds the group the API holds, with a welcome for A1, which refuses it.
    start(&mut server, &mut b1, conversation);
    let welcome = server.entries(conversation)[1].clone();
    assert_eq!(welcome["kind"], "welcome");
    let refused = server.deliver(&mut a1);
    assert_eq!(
        results(&refused),
        [json!([2, "welcome", "rejected", "another_group"])]
    );
    let kept = a1.group(conversation);
    assert_eq!(kept["authenticator"], held["authenticator"]);
    assert_ne!(
        kept["authenticator"],
        b1.group(conversation)["authenticator"]
    );

    // A1 forgets its group. The welcome's key package is spent: the same welcome brings it in no
    // more.
    let record = ok(&mut a1.core, command("forget_group", conversation));
    let again = ok(&mut a1.core, apply(conversation, &[welcome]));
    assert_eq!(results(&[again]), [json!([2, "welcome", "ignored", null])]);
    assert_eq!(a1.no_group(conversation)["what"], "group");

    // A1 joins the API's group, held to the record.
    let mut join = joining(&server, conversation);
    join["expected"] = record["expected"].clone();
    server.commit(&mut a1, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    same_group(&mut [&mut a1, &mut b1], conversation);

    // A welcome A1 can't open, at the generation it holds, is passed by: its forgotten founding's,
    // for B1.
    let next = server.entries(conversation).len() as u64 + 1;
    let forgotten = json!({"seq": next, "kind": "welcome", "data": own["welcome"]});
    let passed = ok(&mut a1.core, apply(conversation, &[forgotten]));
    assert_eq!(
        results(&[passed]),
        [json!([next, "welcome", "ignored", null])]
    );
    same_group(&mut [&mut a1, &mut b1], conversation);
}

/// The entries of `device`'s OpenMLS storage keyed by the group `id`: its tree, context, secrets,
/// queued proposals and epoch key pairs, each stored under a key that holds the ID's JSON.
fn mls_entries(device: &mut TestDevice, id: &openmls::prelude::GroupId) -> usize {
    let needle = serde_json::to_vec(id).unwrap();
    device.rolled_back(|tx| {
        let mut statement = tx.conn().prepare("SELECT key FROM openmls_kv")?;
        let keys = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut found = 0;
        for key in keys {
            found += usize::from(key?.windows(needle.len()).any(|part| part == needle));
        }
        Ok(found)
    })
}

/// A group founded again at a generation has the forgotten one's ID, which OpenMLS keeps one group
/// under: so `forget_group` leaves nothing of the group in OpenMLS's storage, whatever it went
/// through (renewals, a message, a removal the server proposed and each device kept). Here the API
/// lost a group its owner founded and its member entered, as a database restored to before the
/// founding: both forget it, the owner founds it again with the record, and the member's welcome
/// to it, held to the member's record, brings the member in.
#[test]
fn forget_group_leaves_nothing_of_the_group_in_mls_storage() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1, mut b2] = new_devices(&mut server, [a, b, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    server
        .commit(&mut a1, conversation, command("refresh", conversation))
        .unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut b2]);
    let nonce = new_id().to_string();
    let said = ok(
        &mut b1.core,
        json!({"cmd": "encrypt", "conversation_id": conversation, "nonce": nonce, "envelope": {"text": "hi"}}),
    );
    server.post_message(&b1, conversation, &nonce, bytes(&said["ciphertext"]), &[]);
    server.remove_device(conversation, b2.id);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // The API loses the group: both devices forget theirs, and nothing of it stays.
    server.lose_group(conversation);
    let id = group_id(conversation, 0);
    let mut records = Vec::new();
    for device in [&mut a1, &mut b1] {
        assert!(mls_entries(device, &id) > 0);
        let record = ok(&mut device.core, command("forget_group", conversation));
        assert_eq!(
            record["expected"],
            json!({"owner": a, "members": [a, b], "exact": true})
        );
        assert_eq!(mls_entries(device, &id), 0);
        records.push(record["expected"].clone());
    }

    // The owner founds it again with its record; the member's welcome is held to its own.
    b1.remember(conversation, Some(a), &[a, b]);
    let mut create = server.create_group(conversation);
    create["expected"] = records[0].clone();
    server.commit(&mut a1, conversation, create).unwrap();
    let joined = server.deliver(&mut b1);
    assert_eq!(results(&joined), [json!([2, "welcome", "applied", null])]);
    server.deliver(&mut a1);
    let state = same_group(&mut [&mut a1, &mut b1], conversation);
    assert_eq!(
        (&state["generation"], &state["epoch"]),
        (&json!(0), &json!(1))
    );
}

/// `device` takes `user` out of `conversation`'s group by a commit made past its core's rules,
/// with no statement of the user's leaving: the commit, and the group info of the epoch it makes.
fn remove_by_hand(device: &mut TestDevice, conversation: Uuid, user: Uuid) -> (Vec<u8>, Vec<u8>) {
    device.rolled_back(|tx| {
        let (mut group, _) = mls::load_group(tx, conversation)?;
        let own = tx.own_device()?;
        let context = group.public_group().group_context().clone();
        let theirs: Vec<openmls::prelude::LeafNodeIndex> = duvet_e2e_rules::leaves(group.members())
            .unwrap()
            .into_iter()
            .filter(|(_, leaf)| leaf.user == user)
            .map(|(index, _)| openmls::prelude::LeafNodeIndex::new(index))
            .collect();
        let mut list = MemberList::from_group_context(&context).unwrap();
        list.users.retain(|entry| entry.user != user);
        let mut extensions = context.extensions().clone();
        extensions.add_or_replace(list.to_extension()).unwrap();
        group.set_aad(CommitAad::new(Vec::new()).encode());
        let provider = tx.provider();
        let bundle = group
            .commit_builder()
            .propose_removals(theirs)
            .propose_group_context_extensions(extensions)
            .unwrap()
            .force_self_update(true)
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
            .unwrap()
            .stage_commit(provider)
            .unwrap();
        let group_info = MlsMessageOut::from(bundle.group_info().unwrap().clone());
        Ok((tls(bundle.commit()), tls(&group_info)))
    })
}

/// A forgotten group comes back with exactly its users and owner. B1, a member, takes C out
/// without C's statement, past its core's rules, and a server that skips its validator queues it:
/// A1's group blocks on it. That server then lists the conversation with no group, so A1 forgets
/// the blocked group, and it serves the group the commit made, which only lacks a user: a record
/// from before the cutover would take it, the forgotten group's record doesn't.
#[test]
fn a_forgotten_group_comes_back_with_exactly_its_users_and_owner() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let (commit, group_info) = remove_by_hand(&mut b1, conversation, c);
    let seq = server.force(conversation, "commit", commit);
    let entry = server.entries(conversation)[seq as usize - 1].clone();
    let asked = run(
        &mut a1.core,
        &apply(conversation, std::slice::from_ref(&entry)),
    );
    assert_eq!(asked["error"]["code"], "needs_identities");
    server.introduce(&mut a1);
    let blocked = ok(&mut a1.core, apply(conversation, &[entry]));
    assert_eq!(results(&[blocked])[0][2], "rejected");
    assert_eq!(a1.group(conversation)["blocked"], true);

    let record = ok(&mut a1.core, command("forget_group", conversation));
    let join = |expected: &Value| {
        json!({
            "cmd": "join_external",
            "conversation_id": conversation,
            "generation": 0,
            "group_info": b64(&group_info),
            "expected": expected,
        })
    };
    let refused = error(&mut a1.core, join(&record["expected"]));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("member_list_mismatch"))
    );
    assert_eq!(
        record["expected"],
        json!({"owner": a, "members": [a, b, c], "exact": true})
    );
    // A record from before the cutover holds no one the conversation didn't have: it takes it.
    let legacy = json!({"owner": a, "members": [a, b, c]});
    assert!(ok(&mut a1.core, join(&legacy))["commit"].is_string());
}

/// A second leaf under a device already in the group (#57): a holder of B's identity certifies a
/// new signature key under B1's ID, and A1, the owner, commits its key package past its core's
/// rules. The API's validator refuses the commit; a member that applies it from a server that skips
/// the validator blocks on it; and a device joining the group it makes refuses that group.
#[test]
fn a_second_leaf_under_one_device_is_refused() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    server.virtual_under(b, b1.id);
    let twin = json!(server.virtual_key_package(b1.id, 3600));
    let (commit, _, group_info) = add_by_hand(&mut a1, conversation, None, &twin);
    let checked = server.check(conversation, &commit, &group_info);
    assert_eq!(
        checked.error.map(|refusal| refusal.code).as_deref(),
        Some("duplicate_device")
    );
    let seq = server.force(conversation, "commit", commit);
    assert_eq!(
        results(&server.deliver(&mut b1)),
        [json!([seq, "commit", "rejected", "duplicate_device"])]
    );
    assert_eq!(b1.group(conversation)["blocked"], true);

    let mut a2 = server.device(a);
    server.introduce(&mut a2);
    let join = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": b64(&group_info),
    });
    let refused = error(&mut a2.core, join);
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("duplicate_device"))
    );
}

/// A forgotten group's record leaves out the users whose leave statements the device holds: the
/// API took them off as they left, before any commit took their leaves out. Here the owner leaves,
/// and the record names the first of those who stay as the owner, as the API does.
#[test]
fn a_forgotten_group_s_record_leaves_out_who_left() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, mut b1, mut c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b, c], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    server.leave(&mut a1, conversation);
    server.deliver(&mut b1);
    assert_eq!(members(&b1.group(conversation)), [a, b, c]);

    let record = ok(&mut b1.core, command("forget_group", conversation));
    assert_eq!(
        record["expected"],
        json!({"owner": b, "members": [b, c], "exact": true})
    );
}

/// A forget at a later generation: the group reset to generation 1 leaves nothing of either
/// generation in OpenMLS's storage once forgotten.
#[test]
fn forget_group_at_a_later_generation() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let reset = server.reset_group(conversation, &[a, b]);
    server.commit(&mut a1, conversation, reset).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    assert_eq!(a1.group(conversation)["generation"], 1);

    let record = ok(&mut a1.core, command("forget_group", conversation));
    assert_eq!(
        record["expected"],
        json!({"members": [a, b], "exact": true})
    );
    for generation in [0, 1] {
        assert_eq!(mls_entries(&mut a1, &group_id(conversation, generation)), 0);
    }
}

/// A device out of its group (removed, here) holds a row and no group: there's no group to forget.
#[test]
fn forget_group_without_the_group_is_not_found_membership() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, conversation);
    server.deliver_all(&mut [&mut a1, &mut b1]);
    let remove = json!({"cmd": "remove_members", "conversation_id": conversation, "users": [b]});
    server.commit(&mut a1, conversation, remove).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);

    let refused = error(&mut b1.core, command("forget_group", conversation));
    assert_eq!(
        (&refused["code"], &refused["what"]),
        (&json!("not_found"), &json!("membership"))
    );
}

/// A welcome to a blocked group's generation is passed by, as only a reset takes a blocked group
/// on; a blocked group can be forgotten all the same. Here the API kept nothing of A1's founding,
/// B1 founded the group the API holds and renewed its leaf, and A1 gets that renewal first: its own
/// group can't process it and blocks (#55's own case, as a renewal can follow the welcome in one
/// apply). A1 forgets the blocked group and joins the API's, which has the record's members.
#[test]
fn a_welcome_to_a_blocked_group_is_passed_by_and_the_group_forgotten() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let [mut a1, mut b1] = new_devices(&mut server, [a, b]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    server.found_unkept(&mut a1, conversation);
    start(&mut server, &mut b1, conversation);
    server
        .commit(&mut b1, conversation, command("refresh", conversation))
        .unwrap();
    let queue = server.entries(conversation);
    let mut renewal = queue[2].clone();
    renewal["seq"] = json!(2);
    let mut welcome = queue[1].clone();
    welcome["seq"] = json!(3);
    let taken = ok(&mut a1.core, apply(conversation, &[renewal, welcome]));
    assert_eq!(
        results(&[taken]),
        [
            json!([2, "commit", "rejected", "invalid_commit"]),
            json!([3, "welcome", "ignored", null])
        ]
    );
    assert_eq!(a1.group(conversation)["blocked"], true);

    let record = ok(&mut a1.core, command("forget_group", conversation));
    let mut join = joining(&server, conversation);
    join["expected"] = record["expected"].clone();
    server.commit(&mut a1, conversation, join).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    same_group(&mut [&mut a1, &mut b1], conversation);
}

/// The record of `conversation`'s forgotten group that `device`'s store keeps, as JSON: none
/// without one.
fn kept_record(device: &mut TestDevice, conversation: Uuid) -> Option<Value> {
    device.rolled_back(|tx| {
        let record: Option<String> = tx
            .conn()
            .query_row(
                "SELECT record FROM forgotten_groups WHERE conversation_id = ?1",
                [conversation.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(record.map(|record| serde_json::from_str(&record).unwrap()))
    })
}

/// A forgotten group's record is kept in the store, in `forget_group`'s own transaction (#60): a
/// client that closes before it writes its own copy finds it there, as it was answered. A second
/// forget of the conversation keeps the newer group's record in its place.
#[test]
fn forget_group_keeps_its_record_in_the_store() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let [mut a1, _b1, _c1] = new_devices(&mut server, [a, b, c]);
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    server.found_unkept(&mut a1, conversation);
    let first = ok(&mut a1.core, command("forget_group", conversation));
    assert_eq!(
        first["expected"],
        json!({"owner": a, "members": [a, b], "exact": true})
    );
    // The client closes before it keeps its own copy: the store has it.
    let mut a1 = a1.reopened(server.clock.clone());
    assert_eq!(
        kept_record(&mut a1, conversation),
        Some(first["expected"].clone())
    );

    // The person took C in, and the API keeps nothing of the group founded again either.
    server.chats.get_mut(&conversation).unwrap().users = vec![a, b, c];
    server.found_unkept(&mut a1, conversation);
    let second = ok(&mut a1.core, command("forget_group", conversation));
    assert_eq!(
        second["expected"],
        json!({"owner": a, "members": [a, b, c], "exact": true})
    );
    let mut a1 = a1.reopened(server.clock.clone());
    assert_eq!(
        kept_record(&mut a1, conversation),
        Some(second["expected"].clone())
    );
}
