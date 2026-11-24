//! Changing the user's identity, through `Core::handle` as a client drives it: starting over
//! without the recovery key (`reset_identity`), and changing the keys once a device is lost
//! (`rotate_keys`). The user's contacts see the change, and the device's groups take its leaves,
//! certified anew.

mod support;

use std::collections::BTreeSet;

use duvet_e2e::{Clock, Core, DirectMessage, Error, FakeClock, OpenConfig, mls, recovery};
use duvet_e2e_rules::{DeviceCertificate, DeviceList, Kind};
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, KeyPackageIn, MlsMessageIn, ProcessedMessageContent, ProtocolVersion,
    SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use serde::Serialize;
use serde_json::{Value, json};
use support::*;
use tempfile::TempDir;
use uuid::Uuid;

fn open(dir: &TempDir, clock: &FakeClock) -> Core {
    Core::open(OpenConfig {
        clock: Box::new(clock.clone()),
        ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
    })
    .unwrap()
}

/// A device of `user` in a database of its own: its keys, and no identity yet.
fn bare_device(user: Uuid, clock: &FakeClock) -> (Core, Uuid, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, clock);
    let device = new_id();
    ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": device}),
    );
    (core, device, dir)
}

fn rotate(remove: &[Uuid]) -> Value {
    json!({"cmd": "rotate_keys", "remove": remove})
}

fn key(value: &Value) -> [u8; 32] {
    bytes(value).try_into().expect("32 bytes")
}

/// The public key of an identity's secret.
fn public_of(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

fn signer(secret: &[u8; 32]) -> SignatureKeyPair {
    SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        secret.to_vec(),
        public_of(secret).to_vec(),
    )
}

/// What an identity's reply hands the server, opened as a recovered device opens it: the recovery
/// key opens the backup key, and the backup key the identity's secret.
fn opened(user: Uuid, reply: &Value) -> ([u8; 32], [u8; 32]) {
    let recovery_key = recovery::parse(reply["recovery_key"].as_str().unwrap()).unwrap();
    let backup_key =
        recovery::unwrap_backup_key(&recovery_key, user, &bytes(&reply["wrapped_backup_key"]))
            .unwrap();
    let secret =
        recovery::decrypt_identity(&backup_key, user, &bytes(&reply["encrypted_identity"]))
            .unwrap();
    (*backup_key, *secret)
}

/// A new identity's reply, checked: its certificate is `device`'s, its list starts at 1 with
/// `devices`, and its blobs open with its recovery key alone. The identity's key.
fn new_identity(user: Uuid, device: Uuid, devices: &[Uuid], reply: &Value) -> [u8; 32] {
    let identity_key = key(&reply["identity_key"]);
    let certificate = DeviceCertificate::verify(&bytes(&reply["certificate"]), &identity_key)
        .expect("the new identity certifies the device");
    assert_eq!((certificate.user, certificate.device), (user, device));
    let list = DeviceList::verify(&bytes(&reply["device_list"]), &identity_key)
        .expect("the new identity signs the list");
    assert_eq!((list.user, list.version), (user, 1));
    assert_eq!(list.devices, devices);
    let recovery_key = reply["recovery_key"].as_str().unwrap();
    assert_eq!(recovery_key.len(), recovery::LENGTH);
    let (_, secret) = opened(user, reply);
    assert_eq!(public_of(&secret), identity_key);
    identity_key
}

/// The identity key `status` reports.
fn identity_key(core: &mut Core) -> [u8; 32] {
    key(&ok(core, json!({"cmd": "status"}))["identity_key"])
}

/// The backup keys from before the current one, as the backup's re-encryption reads them.
fn previous_keys(core: &mut Core) -> Vec<[u8; 32]> {
    core.transaction(|tx| tx.previous_backup_keys())
        .unwrap()
        .iter()
        .map(|key| **key)
        .collect()
}

/// A row of `meta`, as stored.
fn meta(core: &mut Core, name: &str) -> Vec<u8> {
    core.transaction(|tx| {
        Ok(tx
            .conn()
            .query_row("SELECT value FROM meta WHERE key = ?1", [name], |row| {
                row.get(0)
            })?)
    })
    .unwrap()
}

/// The key packages `key_packages` hands out: each one's reference and the certificate its leaf
/// carries, checked as the device that receives it checks it.
fn key_packages(core: &mut Core) -> Vec<(Vec<u8>, Vec<u8>)> {
    let reply = ok(core, json!({"cmd": "key_packages"}));
    reply["key_packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|published| {
            let key_package = KeyPackageIn::tls_deserialize_exact_bytes(&bytes(&published["data"]))
                .unwrap()
                .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
                .unwrap();
            let certificate =
                BasicCredential::try_from(key_package.leaf_node().credential().clone()).unwrap();
            (bytes(&published["id"]), certificate.identity().to_vec())
        })
        .collect()
}

/// `observe_user` for the device's own user, with a list `identity` signs.
fn own_list(user: Uuid, identity: &SignatureKeyPair, version: u64, devices: &[Uuid]) -> Value {
    let identity_key: [u8; 32] = identity.public().try_into().unwrap();
    let list = DeviceList::new(user, identity_key, version, devices.to_vec())
        .sign(identity)
        .unwrap();
    json!({
        "cmd": "observe_user",
        "user_id": user,
        "identity_key": b64(&identity_key),
        "device_list": b64(&list),
    })
}

/// The identity's secret a device keeps, as whoever holds the device reads it.
fn held_secret(device: &mut TestDevice) -> [u8; 32] {
    let secret: Vec<u8> = device.rolled_back(|tx| {
        Ok(tx.conn().query_row(
            "SELECT value FROM meta WHERE key = 'identity_secret'",
            [],
            |row| row.get(0),
        )?)
    });
    secret.try_into().unwrap()
}

fn command(name: &str, conversation: Uuid) -> Value {
    json!({"cmd": name, "conversation_id": conversation})
}

fn apply(conversation: Uuid, entries: &[Value]) -> Value {
    json!({"cmd": "apply", "conversation_id": conversation, "entries": entries})
}

/// `creator` makes the group of `conversation`, as the API has it, and the server takes it.
fn start(server: &mut FakeServer, creator: &mut TestDevice, conversation: Uuid) {
    let command = server.create_group(conversation);
    server
        .commit(creator, conversation, command)
        .expect("the server takes epoch 0");
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

/// The conversations `refresh_due` lists.
fn due(device: &mut TestDevice) -> BTreeSet<Uuid> {
    ok(&mut device.core, json!({"cmd": "refresh_due"}))["conversations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|conversation| conversation.as_str().unwrap().parse().unwrap())
        .collect()
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

/// `device` takes `conversation`'s whole queue in one `apply`, as a client does: whenever its core
/// asks to observe users first, it observes them as the server has them, then applies again. What
/// each `observe_user` answered, and the last `apply`'s reply.
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

/// What each entry of an `apply` reply did, in order.
fn outcomes(reply: &Value) -> Vec<Value> {
    results(std::slice::from_ref(reply))
        .iter()
        .map(|result| result[2].clone())
        .collect()
}

/// `device`, holding `user`'s identity from before, takes `conversation`'s queue: its core asks to
/// observe `user` anew first, and takes the queue once it has. What `observe_user` answered.
fn deliver_observing(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    user: Uuid,
) -> Value {
    let asked = error(
        &mut device.core,
        apply(conversation, &server.entries(conversation)),
    );
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([user.to_string()]))
    );
    let observed = ok(&mut device.core, server.observed(user));
    server.deliver(device);
    observed
}

#[test]
fn rotate_keys_removes_the_lost_device() {
    let clock = FakeClock::now();
    let user = new_id();
    let (mut core, device, _dir) = bare_device(user, &clock);

    // Changing the keys takes an identity to change.
    let none = error(&mut core, rotate(&[]));
    assert_eq!(
        (&none["code"], &none["what"]),
        (&json!("not_found"), &json!("identity"))
    );

    let first = ok(&mut core, json!({"cmd": "create_identity"}));
    let old_key = key(&first["identity_key"]);
    let (old_backup, old_secret) = opened(user, &first);

    // A second device, which the identity certified and listed, and which is then lost.
    let lost = new_id();
    let old_identity = signer(&old_secret);
    let lost_certificate = DeviceCertificate::new(user, lost, [5; 32], [6; 32], 1)
        .sign(&old_identity)
        .unwrap();
    let mut listed = own_list(user, &old_identity, 2, &[device, lost]);
    listed["certificates"] = json!([first["certificate"], b64(&lost_certificate)]);
    assert_eq!(ok(&mut core, listed)["state"], "same");
    let published_before = key_packages(&mut core);

    // Only devices on the list go, and never this one, which makes the new identity. A refusal
    // changes nothing.
    let unknown = error(&mut core, rotate(&[new_id()]));
    assert_eq!(
        (&unknown["code"], &unknown["what"]),
        (&json!("not_found"), &json!("device"))
    );
    let itself = error(&mut core, rotate(&[device, lost]));
    assert_eq!(
        (&itself["code"], &itself["field"]),
        (&json!("bad_command"), &json!("remove"))
    );
    assert_eq!(identity_key(&mut core), old_key);
    assert_eq!(previous_keys(&mut core), Vec::<[u8; 32]>::new());

    let rotated = ok(&mut core, rotate(&[lost]));

    // A new identity: it certifies this device anew, with the device's own keys and the time of
    // the change, and its list starts again at 1, without the lost device.
    let new_key = new_identity(user, device, &[device], &rotated);
    assert_ne!(new_key, old_key);
    assert_eq!(identity_key(&mut core), new_key);
    let before = DeviceCertificate::verify(&bytes(&first["certificate"]), &old_key).unwrap();
    let certificate = DeviceCertificate::verify(&bytes(&rotated["certificate"]), &new_key).unwrap();
    assert_eq!(
        (&certificate.signature_key, &certificate.hpke_key),
        (&before.signature_key, &before.hpke_key)
    );
    assert_eq!(certificate.created, clock.now_ms() as u64);

    // A new recovery key, which alone opens the new backup key, which alone opens the new
    // identity: what the lost device holds (the old backup key) opens nothing new.
    assert_ne!(rotated["recovery_key"], first["recovery_key"]);
    let (new_backup, _) = opened(user, &rotated);
    assert_ne!(new_backup, old_backup);
    let old_recovery = recovery::parse(first["recovery_key"].as_str().unwrap()).unwrap();
    let refused =
        recovery::unwrap_backup_key(&old_recovery, user, &bytes(&rotated["wrapped_backup_key"]));
    assert_eq!(refused.unwrap_err().code(), "decrypt_failed");
    let refused =
        recovery::decrypt_identity(&old_backup, user, &bytes(&rotated["encrypted_identity"]));
    assert_eq!(refused.unwrap_err().code(), "decrypt_failed");

    // The old backup key stays, wrapped by the new one, never in the clear, and still opens what
    // it encrypted.
    let previous = previous_keys(&mut core);
    assert_eq!(previous, [old_backup]);
    let reopened =
        recovery::decrypt_identity(&previous[0], user, &bytes(&first["encrypted_identity"]))
            .unwrap();
    assert_eq!(public_of(&reopened), old_key);
    let stored = meta(&mut core, "previous_backup_keys");
    assert!(!stored.windows(32).any(|window| window == old_backup));

    // The key packages handed out from now on carry the new certificate; the old ones are no
    // longer handed out.
    let published = key_packages(&mut core);
    assert_eq!(published.len(), 101);
    let new_certificate = bytes(&rotated["certificate"]);
    assert!(
        published
            .iter()
            .all(|(_, carried)| *carried == new_certificate)
    );
    let old_ids: BTreeSet<&Vec<u8>> = published_before.iter().map(|(id, _)| id).collect();
    assert!(published.iter().all(|(id, _)| !old_ids.contains(id)));

    // Changing them again, once the server took the change, keeps both backup keys from before,
    // oldest first, and starts another list at 1.
    ok(&mut core, json!({"cmd": "identity_uploaded"}));
    let again = ok(&mut core, rotate(&[]));
    new_identity(user, device, &[device], &again);
    let (newest, _) = opened(user, &again);
    assert_ne!(newest, new_backup);
    assert_eq!(previous_keys(&mut core), [old_backup, new_backup]);

    // A device that took itself off its list is on its way out, and changes no keys.
    ok(
        &mut core,
        json!({"cmd": "sign_device_list", "remove": [device]}),
    );
    let unlisted = error(&mut core, rotate(&[]));
    assert_eq!(
        (&unlisted["code"], &unlisted["rule"]),
        (&json!("rule_violation"), &json!("device_not_listed"))
    );
}

#[test]
fn reset_identity_starts_a_new_list() {
    let clock = FakeClock::now();

    // Starting over takes this device's keys first.
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, &clock);
    let missing = error(&mut core, json!({"cmd": "reset_identity"}));
    assert_eq!(
        (&missing["code"], &missing["what"]),
        (&json!("not_found"), &json!("device"))
    );
    drop(core);

    // A new device of someone with neither the recovery key nor another device starts over as a
    // first device does: its list at 1, with itself.
    let user = new_id();
    let (mut fresh, device, _fresh_dir) = bare_device(user, &clock);
    let reset = ok(&mut fresh, json!({"cmd": "reset_identity"}));
    let identity = new_identity(user, device, &[device], &reset);
    assert_eq!(identity_key(&mut fresh), identity);
    assert_eq!(previous_keys(&mut fresh), Vec::<[u8; 32]>::new());

    // A device that holds the identity doesn't start over: changing the keys gives it all that
    // starting over would, and keeps the backup keys from before. Nothing changes.
    let user = new_id();
    let (mut core, _device, _dir) = bare_device(user, &clock);
    ok(&mut core, json!({"cmd": "create_identity"}));
    ok(&mut core, rotate(&[]));
    let (identity, backup) = (identity_key(&mut core), meta(&mut core, "backup_key"));
    let previous = previous_keys(&mut core);
    assert_eq!(previous.len(), 1);
    let exists = error(&mut core, json!({"cmd": "reset_identity"}));
    assert_eq!(exists["code"], "exists");
    assert_eq!(identity_key(&mut core), identity);
    assert_eq!(meta(&mut core, "backup_key"), backup);
    assert_eq!(previous_keys(&mut core), previous);

    // Nor does it create one.
    let exists = error(&mut core, json!({"cmd": "create_identity"}));
    assert_eq!(exists["code"], "exists");
}

#[test]
fn contacts_see_the_change() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut b1] {
        server.introduce(device);
    }

    // B compared the safety number with A's.
    let verified = ok(&mut b1.core, json!({"cmd": "verify_user", "user_id": a}));
    assert_eq!(verified["verified"], true);
    let safety = json!({"cmd": "safety_number", "user_id": a});
    let number = ok(&mut b1.core, safety.clone());

    // A loses A2 and changes its keys without it. B sees the change: an identity it hasn't
    // verified, under another safety number, whose certificate verifies.
    let rotated = ok(&mut a1.core, rotate(&[a2.id]));
    server.take_identity(a, &rotated);
    let seen = ok(&mut b1.core, server.observed(a));
    assert_eq!(
        (&seen["state"], &seen["verified"]),
        (&json!("changed"), &json!(false))
    );
    assert_ne!(ok(&mut b1.core, safety.clone())["digits"], number["digits"]);

    // What the lost device's identity signs no longer passes quietly: a newer list of it, with a
    // device of its own making, is a change again, which B sees.
    let lost_identity = signer(&held_secret(&mut a2));
    let rogue = new_id();
    let mut forged = own_list(a, &lost_identity, 9, &[a2.id, rogue]);
    forged["certificates"] = json!([b64(&DeviceCertificate::new(a, rogue, [7; 32], [8; 32], 1)
        .sign(&lost_identity)
        .unwrap())]);
    let seen = ok(&mut b1.core, forged);
    assert_eq!(
        (&seen["state"], &seen["verified"]),
        (&json!("changed"), &json!(false))
    );
    assert_eq!(ok(&mut b1.core, server.observed(a))["state"], "changed");

    // Someone who never saw A pins the new identity as A's first.
    let mut c1 = server.device(c);
    assert_eq!(ok(&mut c1.core, server.observed(a))["state"], "new");

    // Starting over is a change too: on a new device of A's, with neither the recovery key nor
    // another device.
    let mut fresh = server.bare_device(a);
    let reset = ok(&mut fresh.core, json!({"cmd": "reset_identity"}));
    server.take_identity(a, &reset);
    for device in [&mut b1, &mut c1] {
        let seen = ok(&mut device.core, server.observed(a));
        assert_eq!(
            (&seen["state"], &seen["verified"]),
            (&json!("changed"), &json!(false))
        );
    }
}

#[test]
fn new_members_join_before_and_after_the_leaves_are_certified_anew() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    // A group B owns, with A, and a DM of A and B.
    let (group, dm) = (new_id(), new_id());
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    server.conversation(dm, Kind::Dm, None, &[a, b], false);
    start(&mut server, &mut b1, group);
    start(&mut server, &mut a1, dm);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    assert_eq!(due(&mut a1), BTreeSet::new());

    // A loses A2 and changes its keys without it. The server takes the new identity and list, and
    // proposes A2's removal from each of its groups.
    let rotated = ok(&mut a1.core, rotate(&[a2.id]));
    server.take_identity(a, &rotated);
    for conversation in [group, dm] {
        server.remove_device(conversation, a2.id);
    }

    // Every group of A1's is due for its leaf at once: each still carries the certificate of the
    // identity before.
    assert_eq!(due(&mut a1), BTreeSet::from([group, dm]));

    // Meanwhile, whoever pinned the new identity takes A1's leaf, as the new identity certifies the
    // same device and key: B adds C (its commit takes A2 out), and C's welcome takes the group.
    let mut c1 = server.device(c);
    server.publish(&mut c1);
    server.introduce(&mut c1);
    ok(&mut b1.core, server.observed(c));
    server.deliver(&mut b1);
    let add = adding(&mut server, group, c);
    server.commit(&mut b1, group, add).unwrap();
    let joined = results(&server.deliver(&mut c1));
    assert_eq!(
        (&joined[0][1], &joined[0][2]),
        (&json!("welcome"), &json!("applied")),
        "{joined:?}"
    );

    // A1 renews its leaf in each group: the commits carry the new certificate, which the server's
    // validator holds to the new identity, and takes. Nothing is due any more.
    ok(&mut a1.core, server.observed(c));
    server.deliver(&mut a1);
    for conversation in [group, dm] {
        server
            .commit(&mut a1, conversation, command("refresh", conversation))
            .unwrap();
    }
    server.deliver(&mut a1);
    assert_eq!(due(&mut a1), BTreeSet::new());

    // B, which pinned the identity before, takes them once it observes A anew, as its core asks.
    let observed = deliver_observing(&mut server, &mut b1, group, a);
    assert_eq!(observed["state"], "changed");
    for conversation in [group, dm] {
        let state = same_group(&mut [&mut a1, &mut b1], conversation);
        assert!(!devices(&state).contains(&a2.id), "A2 is out");
    }

    // Now a new member's welcome takes the group: B adds D.
    let mut d1 = server.device(d);
    server.publish(&mut d1);
    server.introduce(&mut d1);
    for device in [&mut a1, &mut b1] {
        ok(&mut device.core, server.observed(d));
    }
    let add = adding(&mut server, group, d);
    server.commit(&mut b1, group, add).unwrap();
    let joined = results(&server.deliver(&mut d1));
    assert_eq!(
        (&joined[0][1], &joined[0][2]),
        (&json!("welcome"), &json!("applied")),
        "{joined:?}"
    );

    // And C, in since the window, follows.
    ok(&mut c1.core, server.observed(d));
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1, &mut d1]);
    let state = same_group(&mut [&mut a1, &mut b1, &mut c1, &mut d1], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a1.id, b1.id, c1.id, d1.id])
    );
}

#[test]
fn commits_made_before_the_change_leave_their_group_due() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut b1] {
        server.introduce(device);
    }
    let group = new_id();
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A1 renews its leaf and changes its keys before the server's word on the commit. The server
    // took it before the change reached it, under the identity that certified the leaf it brings.
    // Merged now, that leaf carries the certificate from before: the group is due still.
    let made = ok(&mut a1.core, command("refresh", group));
    let rotated = ok(&mut a1.core, rotate(&[]));
    server.submit(&mut a1, group, &made).unwrap();
    server.take_identity(a, &rotated);
    ok(&mut a1.core, json!({"cmd": "identity_uploaded"}));
    assert_eq!(due(&mut a1), BTreeSet::from([group]));
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // The same through the queue: A1 renews its leaf, with the new certificate, then changes its
    // keys again before the server's word, which it hears as a refusal (a lost answer, then the
    // retry's 409). The group isn't due while the commit waits. B, keeping up, takes the commit.
    let made = ok(&mut a1.core, command("refresh", group));
    let again = ok(&mut a1.core, rotate(&[]));
    let seq = server.take_unheard(&mut a1, group, &made);
    let observed = deliver_observing(&mut server, &mut b1, group, a);
    assert_eq!(observed["state"], "changed");
    server.take_identity(a, &again);
    assert_eq!(due(&mut a1), BTreeSet::new());

    // The queue brings the commit back, and A1 merges it: its leaf is the one it made before
    // changing the keys again, so the group is due again.
    let merged = results(&server.deliver(&mut a1));
    assert_eq!(merged, [json!([seq, "commit", "own", null])]);
    assert_eq!(due(&mut a1), BTreeSet::from([group]));

    // The refresh carries the newest certificate, which the server and B take.
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    assert_eq!(due(&mut a1), BTreeSet::new());
    let observed = deliver_observing(&mut server, &mut b1, group, a);
    assert_eq!(observed["state"], "changed");
    same_group(&mut [&mut a1, &mut b1], group);
}

/// Each of `devices` publishes its key packages, then observes every user.
fn meet(server: &mut FakeServer, devices: &mut [&mut TestDevice]) {
    for device in devices.iter_mut() {
        server.publish(device);
    }
    for device in devices.iter_mut() {
        server.introduce(device);
    }
}

#[test]
fn a_commit_from_before_the_change_applies_after_it() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // While B1 is away, A1 renews its leaf under the identity it has, changes its keys, and renews
    // its leaf again under the new identity. The server takes both commits.
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    let rotated = ok(&mut a1.core, rotate(&[]));
    server.take_identity(a, &rotated);
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();

    // B1 takes the whole queue at once. It asks to observe A once, for the leaf the new identity
    // certifies, then applies both: the commit from before brings A1's leaf as it was, which
    // asserts nothing new.
    let (observed, reply) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, [json!("changed")]);
    assert_eq!(outcomes(&reply), [json!("applied"), json!("applied")]);
    same_group(&mut [&mut a1, &mut b1], group);
    assert_eq!(b1.group(group)["blocked"], false);
}

#[test]
fn commits_from_before_the_change_apply_in_any_conversation() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut b1]);
    let (x, y) = (new_id(), new_id());
    for conversation in [x, y] {
        server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
        start(&mut server, &mut a1, conversation);
    }
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // While B1 is away, A1 renews its leaf in Y, changes its keys, and renews its leaf in X.
    server.commit(&mut a1, y, command("refresh", y)).unwrap();
    let rotated = ok(&mut a1.core, rotate(&[]));
    server.take_identity(a, &rotated);
    server.commit(&mut a1, x, command("refresh", x)).unwrap();

    // B1 takes X first, where it observes A anew.
    let (observed, reply) = take_queue(&server, &mut b1, x);
    assert_eq!(observed, [json!("changed")]);
    assert_eq!(outcomes(&reply), [json!("applied")]);

    // Then Y, whose commit from before applies under the identity B1 pins now, with nothing to ask.
    let (observed, reply) = take_queue(&server, &mut b1, y);
    assert_eq!(observed, Vec::<Value>::new());
    assert_eq!(outcomes(&reply), [json!("applied")]);
    for conversation in [x, y] {
        same_group(&mut [&mut a1, &mut b1], conversation);
        assert_eq!(b1.group(conversation)["blocked"], false);
    }
}

#[test]
fn the_rotating_device_applies_what_the_lost_one_committed_before() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A2 renews its leaf, which the server takes, before A1 changes the keys without A2 and the
    // server proposes A2's removal.
    server
        .commit(&mut a2, group, command("refresh", group))
        .unwrap();
    let rotated = ok(&mut a1.core, rotate(&[a2.id]));
    server.take_identity(a, &rotated);
    server.remove_device(group, a2.id);

    // A1 takes the queue: A2's commit brings A2's leaf as it was, which no identity certifies
    // again, so it applies with nothing to ask, and so does the proposal.
    let (observed, reply) = take_queue(&server, &mut a1, group);
    assert_eq!(observed, Vec::<Value>::new());
    assert_eq!(outcomes(&reply), [json!("applied"), json!("applied")]);
    assert_eq!(a1.group(group)["blocked"], false);

    // A1 renews its leaf, which takes A2 out, and B1 takes it all.
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    let (observed, _) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, [json!("changed")]);
    let state = same_group(&mut [&mut a1, &mut b1], group);
    assert!(!devices(&state).contains(&a2.id), "A2 is out");
}

/// `rotate_keys` without `remove`, with the certificates of `user`'s devices as the server serves
/// them, which the devices that stay are certified anew from.
fn rotating(server: &FakeServer, user: Uuid, remove: &[Uuid]) -> Value {
    let mut command = rotate(remove);
    command["certificates"] = server.observed(user)["certificates"].clone();
    command
}

/// `receive_direct` of `message`, with the identity the server serves for the device's own user.
fn receiving(message: &[u8], identity_key: &[u8; 32]) -> Value {
    json!({
        "cmd": "receive_direct",
        "message": b64(message),
        "identity_key": b64(identity_key),
    })
}

/// The certificate the server serves for `device`, among those `observed` (an `observe_user`
/// command) holds.
fn served_certificate(observed: &Value, device: Uuid) -> Vec<u8> {
    observed["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .find(|certificate| {
            DeviceCertificate::read_unverified(certificate)
                .unwrap()
                .device
                == device
        })
        .expect("the device's certificate")
}

#[test]
fn devices_that_stay_take_the_new_identity() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut a3 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut a3, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    start(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut a3, &mut b1]);
    let served = server.observed(a);

    // A loses A2 and changes its keys on A1, without A2. A3 stays: A1 certifies A3's own keys with
    // the new identity, for the server, and seals the identity to A3, for its inbox.
    let rotated = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    let new_key = new_identity(a, a1.id, &[a1.id, a3.id], &rotated);
    let handed = rotated["transfers"].as_array().expect("transfers");
    assert_eq!(handed.len(), 1);
    assert_eq!(handed[0]["device_id"], json!(a3.id));
    let before = DeviceCertificate::read_unverified(&served_certificate(&served, a3.id)).unwrap();
    let certificate =
        DeviceCertificate::verify(&bytes(&handed[0]["certificate"]), &new_key).unwrap();
    assert_eq!(
        (
            certificate.user,
            certificate.device,
            &certificate.signature_key,
            &certificate.hpke_key
        ),
        (a, a3.id, &before.signature_key, &before.hpke_key)
    );
    server.take_identity(a, &rotated);
    server.remove_device(group, a2.id);

    // A3 takes the transfer from its inbox, as the identity it brings is the one the server serves.
    let inbox = server.inbox(a3.id);
    assert_eq!(inbox.len(), 1);
    let taken = ok(&mut a3.core, receiving(&inbox[0], &new_key));
    assert_eq!(
        (&taken["type"], &taken["certificate"]),
        (&json!("rotation.transfer"), &handed[0]["certificate"])
    );
    assert_eq!(key(&taken["identity_key"]), new_key);
    assert_eq!(identity_key(&mut a3.core), new_key);

    // Its backup key is the new one, and it keeps the backup keys from before as A1 does.
    let (new_backup, _) = opened(a, &rotated);
    assert_eq!(meta(&mut a3.core, "backup_key"), new_backup);
    let earlier = previous_keys(&mut a1.core);
    assert!(!earlier.is_empty());
    assert_eq!(previous_keys(&mut a3.core), earlier);

    // Its groups are due at once, for leaves the new identity certifies.
    assert_eq!(due(&mut a3), BTreeSet::from([group]));
    server.deliver(&mut a1);
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    server.deliver(&mut a3);
    server
        .commit(&mut a3, group, command("refresh", group))
        .unwrap();
    assert_eq!(due(&mut a3), BTreeSet::new());
    server.deliver(&mut a1);
    let (observed, _) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, [json!("changed")]);
    let state = same_group(&mut [&mut a1, &mut a3, &mut b1], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a1.id, a3.id, b1.id])
    );

    // Now B adds C, whose welcome takes the group: every leaf in it carries a certificate of the
    // identity C pins for A.
    let mut c1 = server.device(c);
    server.publish(&mut c1);
    server.introduce(&mut c1);
    for device in [&mut a1, &mut a3, &mut b1] {
        ok(&mut device.core, server.observed(c));
    }
    let add = adding(&mut server, group, c);
    server.commit(&mut b1, group, add).unwrap();
    let joined = results(&server.deliver(&mut c1));
    assert_eq!(
        (&joined[0][1], &joined[0][2]),
        (&json!("welcome"), &json!("applied")),
        "{joined:?}"
    );
    server.deliver_all(&mut [&mut a1, &mut a3, &mut b1]);
    same_group(&mut [&mut a1, &mut a3, &mut b1, &mut c1], group);
}

/// A rotation's transfer as the core writes it, for a test to make one of its own: `{v: 1,
/// identity, backup_key, previous_backup_keys, certificate, device_list, previous_list, sender}`.
#[derive(Serialize)]
struct TransferPayload {
    v: u32,
    #[serde(with = "serde_bytes")]
    identity: Vec<u8>,
    #[serde(with = "serde_bytes")]
    backup_key: Vec<u8>,
    /// The earlier backup keys, `[{key, until}]`: none here.
    previous_backup_keys: Vec<()>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    previous_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sender: Vec<u8>,
}

/// `payload` as a rotation's transfer from `from` to device `to`: sealed to `to`'s HPKE key, and
/// signed with `from`'s own device key, as any device of the user could send it.
fn sealed_by(
    from: &mut TestDevice,
    to: Uuid,
    to_hpke: &[u8; 32],
    payload: &TransferPayload,
) -> Vec<u8> {
    let mut encoded = Vec::new();
    ciborium::into_writer(payload, &mut encoded).unwrap();
    from.rolled_back(|tx| {
        let own = tx.own_device()?;
        DirectMessage::seal(
            tx.provider(),
            &own.signer,
            own.device,
            to,
            to_hpke,
            "rotation.transfer",
            &encoded,
        )
    })
}

#[test]
fn a_device_takes_only_a_transfer_that_holds_up() {
    let mut server = FakeServer::new();
    let a = new_id();
    let mut a1 = server.device(a);
    let a2 = server.device(a);
    let mut a3 = server.device(a);
    let mut a4 = server.device(a);
    meet(&mut server, &mut [&mut a1, &mut a3, &mut a4]);
    let old_key = identity_key(&mut a3.core);
    let served = server.observed(a);

    // Changing the keys takes the certificate of each device that stays, verified by the identity
    // this device holds. A refusal changes nothing.
    let missing = error(&mut a1.core, rotate(&[a2.id]));
    assert_eq!(
        (&missing["code"], &missing["field"]),
        (&json!("bad_command"), &json!("certificates"))
    );
    let mut forged = rotating(&server, a, &[a2.id]);
    let stranger = signer(&[7; 32]);
    forged["certificates"]
        .as_array_mut()
        .unwrap()
        .push(json!(b64(&DeviceCertificate::new(
            a, a3.id, [1; 32], [2; 32], 1
        )
        .sign(&stranger)
        .unwrap())));
    let refused = error(&mut a1.core, forged);
    assert_eq!(
        (&refused["code"], &refused["what"]),
        (&json!("invalid_signature"), &json!("certificate"))
    );
    assert_eq!(identity_key(&mut a1.core), old_key);

    // A4 took A1 off the list as it knows it, before A1 changes the keys without A2.
    ok(
        &mut a4.core,
        json!({"cmd": "sign_device_list", "remove": [a1.id]}),
    );
    let rotated = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    let new_key = key(&rotated["identity_key"]);
    server.take_identity(a, &rotated);
    let to_a3 = server.inbox(a3.id).remove(0);
    let to_a4 = server.inbox(a4.id).remove(0);

    // A device off the receiver's list: A4 no longer lists A1.
    let refused = error(&mut a4.core, receiving(&to_a4, &new_key));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("device_not_listed"))
    );
    assert_eq!(identity_key(&mut a4.core), old_key);

    // An identity other than the one the server serves for A.
    let refused = error(&mut a3.core, receiving(&to_a3, &old_key));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("identity_mismatch"))
    );
    assert_eq!(identity_key(&mut a3.core), old_key);

    // A list that doesn't name the receiver, though the identity it brings is the one served: a
    // transfer A1's device key signs, whose new list has A1 alone.
    let (_, new_secret) = opened(a, &rotated);
    let new_identity = signer(&new_secret);
    let a3_certificate =
        DeviceCertificate::read_unverified(&served_certificate(&served, a3.id)).unwrap();
    let a3_hpke: [u8; 32] = a3_certificate.hpke_key.as_slice().try_into().unwrap();
    let payload = TransferPayload {
        v: 1,
        identity: new_secret.to_vec(),
        backup_key: vec![3; 32],
        previous_backup_keys: Vec::new(),
        certificate: DeviceCertificate::new(
            a,
            a3.id,
            a3_certificate.signature_key.as_slice().try_into().unwrap(),
            a3_hpke,
            1,
        )
        .sign(&new_identity)
        .unwrap(),
        device_list: DeviceList::new(a, new_key, 1, vec![a1.id])
            .sign(&new_identity)
            .unwrap(),
        previous_list: bytes(&served["device_list"]),
        sender: served_certificate(&served, a1.id),
    };
    let unlisted = sealed_by(&mut a1, a3.id, &a3_hpke, &payload);
    let refused = error(&mut a3.core, receiving(&unlisted, &new_key));
    assert_eq!(
        (&refused["code"], &refused["rule"]),
        (&json!("rule_violation"), &json!("device_not_listed"))
    );
    assert_eq!(identity_key(&mut a3.core), old_key);

    // The transfer itself holds up: A3 takes it, once.
    ok(&mut a3.core, receiving(&to_a3, &new_key));
    assert_eq!(identity_key(&mut a3.core), new_key);
    let again = error(&mut a3.core, receiving(&to_a3, &new_key));
    assert_eq!(again["code"], "exists");
}

/// What `encrypt` checks before it encrypts: whether the device may send now.
fn ready(device: &mut TestDevice, conversation: Uuid) -> Result<(), Value> {
    device
        .core
        .transaction(|tx| mls::ready_to_send(tx, conversation))
        .map_err(|error| error.to_reply()["error"].clone())
}

/// An application message `device` sends in its group of `conversation`.
fn send(device: &mut TestDevice, conversation: Uuid, text: &[u8]) -> Vec<u8> {
    device
        .core
        .transaction(|tx| {
            let (mut group, _) = mls::load_group(tx, conversation)?;
            let own = tx.own_device()?;
            let message = group
                .create_message(tx.provider(), &own.signer, text)
                .map_err(|error| Error::Internal(error.to_string()))?;
            Ok(message.tls_serialize_detached().unwrap())
        })
        .unwrap()
}

/// What a client without the rules would do with `commit` in its group of `conversation`: process
/// and merge it with OpenMLS alone.
fn merge_unchecked(device: &mut TestDevice, conversation: Uuid, commit: &[u8]) {
    device
        .core
        .transaction(|tx| {
            let (mut group, _) = mls::load_group(tx, conversation)?;
            let message = MlsMessageIn::tls_deserialize_exact_bytes(commit)
                .unwrap()
                .try_into_protocol_message()
                .unwrap();
            let processed = group
                .process_message(tx.provider(), message)
                .map_err(|error| Error::Internal(error.to_string()))?;
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            group
                .merge_staged_commit(tx.provider(), *staged)
                .map_err(|error| Error::Internal(error.to_string()))
        })
        .unwrap();
}

/// What an application message says, as `device` decrypts it in its group of `conversation`, when
/// it can.
fn read(device: &mut TestDevice, conversation: Uuid, message: &[u8]) -> Result<Vec<u8>, Error> {
    device.core.transaction(|tx| {
        let (mut group, _) = mls::load_group(tx, conversation)?;
        let message = MlsMessageIn::tls_deserialize_exact_bytes(message)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let processed = group
            .process_message(tx.provider(), message)
            .map_err(|error| Error::Internal(error.to_string()))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            _ => Err(Error::Internal("not an application message".into())),
        }
    })
}

#[test]
fn a_lost_device_leaves_the_groups_without_the_server() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    let mut b2 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    start(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut b2]);
    assert_eq!(ready(&mut a1, group), Ok(()));

    // A loses A2 and changes its keys without it. The server takes the new identity and list, but
    // proposes no removal.
    let rotated = ok(&mut a1.core, rotate(&[a2.id]));
    server.take_identity(a, &rotated);

    // A1 sends nothing while A2's leaf is in the group. Its core first asks to observe its own user,
    // as a device of A's may have come since it last saw the list; the list doesn't have A2, so A1
    // commits A2's removal first, which the server's validator takes.
    let asked = ready(&mut a1, group).unwrap_err();
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a.to_string()]))
    );
    assert_eq!(ok(&mut a1.core, server.observed(a))["state"], "same");
    let wait = ready(&mut a1, group).unwrap_err();
    assert_eq!(
        (&wait["code"], &wait["message"]),
        (
            &json!("pending_proposals"),
            &json!("removals are pending: commit them first with commit_pending")
        )
    );
    server
        .commit(&mut a1, group, command("commit_pending", group))
        .unwrap();
    assert_eq!(ready(&mut a1, group), Ok(()));
    assert!(!devices(&a1.group(group)).contains(&a2.id));

    // What A1 sends next, A2 can't read. B's devices take the commit, once they observe A anew, and
    // read it.
    let next = send(&mut a1, group, b"after the change");
    let removal = server.chats[&group]
        .queue
        .iter()
        .rev()
        .find(|entry| entry.kind == "commit")
        .unwrap()
        .data
        .clone();
    merge_unchecked(&mut a2, group, &removal);
    assert!(
        matches!(read(&mut a2, group, &next), Err(Error::NotFound { what }) if what == "membership")
    );
    for device in [&mut b1, &mut b2] {
        let (observed, reply) = take_queue(&server, device, group);
        assert_eq!(observed, [json!("changed")]);
        assert_eq!(outcomes(&reply), [json!("applied")]);
        assert_eq!(read(device, group, &next).unwrap(), b"after the change");
    }
    let state = same_group(&mut [&mut a1, &mut b1, &mut b2], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a1.id, b1.id, b2.id])
    );
}

#[test]
fn a_device_signed_off_the_list_leaves_without_the_server() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A1 takes A2 off A's list, which the server takes; it proposes no removal. A1 asks to observe
    // its own user first, then commits it.
    let list = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &list["device_list"]);
    let asked = ready(&mut a1, group).unwrap_err();
    assert_eq!(asked["code"], "needs_identities");
    assert_eq!(ok(&mut a1.core, server.observed(a))["state"], "same");
    let wait = ready(&mut a1, group).unwrap_err();
    assert_eq!(wait["code"], "pending_proposals");
    server
        .commit(&mut a1, group, command("commit_pending", group))
        .unwrap();
    assert_eq!(ready(&mut a1, group), Ok(()));

    // B1, whose copy of A's list still has A2, asks to observe A first, then takes the commit.
    let (observed, reply) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, [json!("same")]);
    assert_eq!(outcomes(&reply), [json!("applied")]);
    let state = same_group(&mut [&mut a1, &mut b1], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a1.id, b1.id])
    );
}

/// `observed` (an `observe_user` command) with `device`'s certificate in place of `certificate`.
fn serving(mut observed: Value, device: Uuid, certificate: &[u8]) -> Value {
    for served in observed["certificates"].as_array_mut().unwrap() {
        if DeviceCertificate::read_unverified(&bytes(served))
            .unwrap()
            .device
            == device
        {
            *served = json!(b64(certificate));
        }
    }
    observed
}

#[test]
fn a_device_set_up_before_the_change_keeps_its_groups() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    let mut c1 = server.device(c);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut b1, &mut c1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a, c], false);
    start(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1, &mut c1]);

    // B1 and C1 are away from now on. A sets up a replacement phone, A3, under the identity A has
    // (as an approval or a recovery gives it), and it joins the group by external commit.
    let mut a3 = server.device(a);
    server.introduce(&mut a3);
    let join = joining(&server, group);
    server.commit(&mut a3, group, join).unwrap();
    let (observed, _) = take_queue(&server, &mut a2, group);
    assert_eq!(observed, [json!("same")]);

    // Then A1 is lost: A2 changes the keys without it, and A3 takes its transfer. Both renew their
    // leaves, with the server's removal of A1.
    let rotated = ok(&mut a2.core, rotating(&server, a, &[a1.id]));
    let new_key = key(&rotated["identity_key"]);
    server.take_identity(a, &rotated);
    let transfer = server.inbox(a3.id).remove(0);
    ok(&mut a3.core, receiving(&transfer, &new_key));
    server.remove_device(group, a1.id);
    for device in [&mut a2, &mut a3] {
        take_queue(&server, device, group);
        server
            .commit(device, group, command("refresh", group))
            .unwrap();
    }
    take_queue(&server, &mut a2, group);

    // B1 comes back, observes A under the new identity first, then takes the whole queue. A3's
    // join, made under the identity before, applies: the new identity certifies the same device
    // with the same key. Nothing blocks.
    assert_eq!(ok(&mut b1.core, server.observed(a))["state"], "changed");
    let (observed, reply) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, Vec::<Value>::new());
    assert!(
        outcomes(&reply).iter().all(|outcome| outcome == "applied"),
        "{reply}"
    );
    assert_eq!(b1.group(group)["blocked"], false);
    let state = same_group(&mut [&mut a2, &mut a3, &mut b1], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a2.id, a3.id, b1.id, c1.id])
    );

    // C1 comes back to a server that serves, for A3, a certificate the new identity signed for
    // other keys. A3's join, under the identity before, isn't that device then, and it's refused as
    // before: C1 asks about A once, then the same knowledge blocks the group.
    let (_, new_secret) = opened(a, &rotated);
    let other_keys = DeviceCertificate::new(a, a3.id, [1; 32], [2; 32], 1)
        .sign(&signer(&new_secret))
        .unwrap();
    let served = serving(server.observed(a), a3.id, &other_keys);
    assert_eq!(ok(&mut c1.core, served.clone())["state"], "changed");
    let entries = server.entries(group);
    let asked = error(&mut c1.core, apply(group, &entries));
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a.to_string()]))
    );
    assert_eq!(ok(&mut c1.core, served)["state"], "same");
    let refused = ok(&mut c1.core, apply(group, &entries));
    assert!(outcomes(&refused).contains(&json!("rejected")), "{refused}");
    assert_eq!(c1.group(group)["blocked"], true);
}

#[test]
fn a_staying_device_waits_for_its_transfer() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let a2 = server.device(a);
    let mut a3 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a3, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    start(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut a3, &mut b1]);

    // A1 changes the keys without A2, and renews its leaf under the new identity.
    let rotated = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    let new_key = key(&rotated["identity_key"]);
    server.take_identity(a, &rotated);
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();

    // A3 takes the queue before its transfer. Its core asks to observe its own user, whom the
    // server serves under the identity A3 doesn't hold yet; applied again, it asks again, and blocks
    // nothing.
    let entries = server.entries(group);
    for _ in 0..2 {
        let asked = error(&mut a3.core, apply(group, &entries));
        assert_eq!(
            (&asked["code"], &asked["users"]),
            (&json!("needs_identities"), &json!([a.to_string()]))
        );
        let seen = ok(&mut a3.core, server.observed(a));
        assert_eq!(seen["reason"], "not_own_identity");
    }
    assert_eq!(a3.group(group)["blocked"], false);

    // Once it takes its transfer, the queue applies.
    let transfer = server.inbox(a3.id).remove(0);
    ok(&mut a3.core, receiving(&transfer, &new_key));
    let applied = ok(&mut a3.core, apply(group, &entries));
    assert_eq!(outcomes(&applied), [json!("applied")]);
    same_group(&mut [&mut a1, &mut a3], group);
}

#[test]
fn a_tablet_with_an_old_list_takes_the_transfer() {
    let mut server = FakeServer::new();
    let a = new_id();
    let a1 = server.device(a);
    let mut a2 = server.device(a);
    meet(&mut server, &mut [&mut a2]);

    // While A2, a tablet, is off, A sets up A3 under the identity it has: A2's list doesn't have A3.
    let mut a3 = server.device(a);
    server.introduce(&mut a3);

    // A1 is lost, and A3 changes the keys without it. A3 isn't on the list A2 holds, but the
    // transfer brings A's list from before the change, newer than A2's, which has it: A2 takes it.
    let rotated = ok(&mut a3.core, rotating(&server, a, &[a1.id]));
    let new_key = key(&rotated["identity_key"]);
    server.take_identity(a, &rotated);
    let transfer = server.inbox(a2.id).remove(0);
    let taken = ok(&mut a2.core, receiving(&transfer, &new_key));
    assert_eq!(key(&taken["identity_key"]), new_key);
    assert_eq!(identity_key(&mut a2.core), new_key);
}

#[test]
fn a_stale_own_list_asks_before_taking_a_device_out() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut b1]);

    // A3 is set up while A2 is away, and B, who sees A's newer list, starts a group with A: its
    // welcome brings A3's leaf to A2.
    let mut a3 = server.device(a);
    server.publish(&mut a3);
    ok(&mut b1.core, server.observed(a));
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    start(&mut server, &mut b1, group);
    server.deliver(&mut a2);
    assert!(devices(&a2.group(group)).contains(&a3.id));

    // A3 isn't on the list A2 holds. Before taking it out, A2's core asks to observe its own user;
    // the list it gets has A3, and A2 may send.
    let asked = ready(&mut a2, group).unwrap_err();
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a.to_string()]))
    );
    assert_eq!(ok(&mut a2.core, server.observed(a))["state"], "same");
    assert_eq!(ready(&mut a2, group), Ok(()));
}

#[test]
fn new_members_join_past_a_leaf_from_before_the_change() {
    let mut server = FakeServer::new();
    let (a, b, c, d) = (new_id(), new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let a2 = server.device(a);
    let mut a3 = server.device(a);
    let mut b1 = server.device(b);
    meet(&mut server, &mut [&mut a1, &mut a3, &mut b1]);
    let group = new_id();
    server.conversation(group, Kind::Group, Some(b), &[b, a], false);
    start(&mut server, &mut b1, group);
    server.deliver_all(&mut [&mut a1, &mut a3, &mut b1]);

    // A1 changes the keys without A2 and renews its leaf. A3, a tablet that stays, is off: its leaf
    // keeps the certificate from before.
    let rotated = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    server.take_identity(a, &rotated);
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    let (observed, _) = take_queue(&server, &mut b1, group);
    assert_eq!(observed, [json!("changed")]);

    // B adds C, who saw A only under the new identity, with its certificates: C's welcome takes the
    // group, A3's leaf with it.
    let mut c1 = server.device(c);
    server.publish(&mut c1);
    server.introduce(&mut c1);
    ok(&mut b1.core, server.observed(c));
    let add = adding(&mut server, group, c);
    server.commit(&mut b1, group, add).unwrap();
    let joined = results(&server.deliver(&mut c1));
    assert_eq!(
        (&joined[0][1], &joined[0][2]),
        (&json!("welcome"), &json!("applied")),
        "{joined:?}"
    );

    // So does B2, a new device of B's, joining by external commit.
    let mut b2 = server.device(b);
    server.introduce(&mut b2);
    let join = joining(&server, group);
    server.commit(&mut b2, group, join).unwrap();

    // D is served, for A3, a certificate the new identity signed for other keys: D's welcome is
    // refused, after D asks about A once.
    let (_, new_secret) = opened(a, &rotated);
    let other_keys = DeviceCertificate::new(a, a3.id, [1; 32], [2; 32], 1)
        .sign(&signer(&new_secret))
        .unwrap();
    let mut d1 = server.device(d);
    server.publish(&mut d1);
    server.introduce(&mut d1);
    let served = serving(server.observed(a), a3.id, &other_keys);
    assert_eq!(ok(&mut d1.core, served.clone())["state"], "same");
    take_queue(&server, &mut b1, group);
    ok(&mut b1.core, server.observed(d));
    let add = adding(&mut server, group, d);
    server.commit(&mut b1, group, add).unwrap();
    let entries = server.entries(group);
    let asked = error(&mut d1.core, apply(group, &entries));
    assert_eq!(asked["code"], "needs_identities");
    assert_eq!(ok(&mut d1.core, served)["state"], "same");
    let refused = results(&[ok(&mut d1.core, apply(group, &entries))]);
    assert_eq!(
        refused.last().unwrap(),
        &json!([entries.len(), "welcome", "rejected", "leaf_not_signed"])
    );
    assert_eq!(d1.no_group(group)["what"], "group");
}

/// A1 changes A's keys, and its reply is lost before the upload. Run again with the certificates
/// the server still serves, the identity before's, it answers the same new identity, recovery key
/// and blobs, and seals the transfers again, which A3 takes; with other devices to remove it's
/// refused. Once the client confirmed the upload, a rotation is a new one again.
#[test]
fn a_rotation_run_again_reseals_its_transfers() {
    let mut server = FakeServer::new();
    let a = new_id();
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut a3 = server.device(a);
    meet(&mut server, &mut [&mut a1, &mut a2, &mut a3]);

    let lost = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    // A2, lost, holds the identity before: A3's certificate it signs with keys of its own gets
    // nothing sealed to them.
    let forged = DeviceCertificate::new(a, a3.id, [7; 32], [8; 32], 1)
        .sign(&signer(&held_secret(&mut a2)))
        .unwrap();
    let mut swapped = rotating(&server, a, &[a2.id]);
    swapped["certificates"] = json!([b64(&forged)]);
    let refused = error(&mut a1.core, swapped);
    assert_eq!(
        (&refused["code"], &refused["field"]),
        (&json!("bad_command"), &json!("certificates"))
    );
    let rotated = ok(&mut a1.core, rotating(&server, a, &[a2.id]));
    for field in [
        "identity_key",
        "certificate",
        "device_list",
        "recovery_key",
        "wrapped_backup_key",
        "encrypted_identity",
        "wrapped_previous_backup_keys",
    ] {
        assert_eq!(rotated[field], lost[field], "{field}");
    }
    let other = error(&mut a1.core, rotating(&server, a, &[]));
    assert_eq!(
        (&other["code"], &other["field"]),
        (&json!("bad_command"), &json!("remove"))
    );

    server.take_identity(a, &rotated);
    let new_key = key(&rotated["identity_key"]);
    let transfer = server.inbox(a3.id).pop().expect("A3's transfer");
    let taken = ok(&mut a3.core, receiving(&transfer, &new_key));
    assert_eq!(taken["identity_key"], rotated["identity_key"]);

    ok(&mut a1.core, json!({"cmd": "identity_uploaded"}));
    let next = ok(&mut a1.core, rotating(&server, a, &[]));
    assert_ne!(next["identity_key"], rotated["identity_key"]);
}
