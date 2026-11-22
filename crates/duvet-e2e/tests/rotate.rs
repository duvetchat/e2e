//! Changing the user's identity, through `Core::handle` as a client drives it: starting over
//! without the recovery key (`reset_identity`), and changing the keys once a device is lost
//! (`rotate_keys`). The user's contacts see the change, and the device's groups take its leaves,
//! certified anew, before anyone new can join them.

mod support;

use std::collections::BTreeSet;

use duvet_e2e::{Clock, Core, FakeClock, OpenConfig, recovery};
use duvet_e2e_rules::{DeviceCertificate, DeviceList, Kind};
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{BasicCredential, KeyPackageIn, ProtocolVersion, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
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

    // Changing them again keeps both backup keys from before, oldest first, and starts another
    // list at 1.
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

    // A device that had the identity, its keys changed once and its list at version 3, starts
    // over from 1, alone, and keeps no backup key from before.
    let user = new_id();
    let (mut core, device, _dir) = bare_device(user, &clock);
    ok(&mut core, json!({"cmd": "create_identity"}));
    let rotated = ok(&mut core, rotate(&[]));
    assert_eq!(previous_keys(&mut core).len(), 1);
    let (rotated_backup, rotated_secret) = opened(user, &rotated);
    let rotated_identity = signer(&rotated_secret);
    let (other, third) = (new_id(), new_id());
    for (version, devices) in [(2, vec![device, other]), (3, vec![device, other, third])] {
        let listed = own_list(user, &rotated_identity, version, &devices);
        assert_eq!(ok(&mut core, listed)["state"], "same");
    }

    let reset = ok(&mut core, json!({"cmd": "reset_identity"}));
    let identity = new_identity(user, device, &[device], &reset);
    assert_ne!(identity, key(&rotated["identity_key"]));
    assert_eq!(identity_key(&mut core), identity);
    assert_eq!(previous_keys(&mut core), Vec::<[u8; 32]>::new());
    let refused =
        recovery::decrypt_identity(&rotated_backup, user, &bytes(&reset["encrypted_identity"]));
    assert_eq!(refused.unwrap_err().code(), "decrypt_failed");

    // Only starting over replaces an identity: creating one still refuses to.
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

    // Starting over is a change too.
    let reset = ok(&mut a1.core, json!({"cmd": "reset_identity"}));
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
fn new_members_join_once_the_leaves_are_certified_anew() {
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

    // Meanwhile, whoever pinned the new identity can't take A1's leaf. B adds C, whose device
    // asks to observe A anew, then refuses the welcome.
    let mut c1 = server.device(c);
    server.publish(&mut c1);
    server.introduce(&mut c1);
    ok(&mut b1.core, server.observed(c));
    server.deliver(&mut b1);
    let add = adding(&mut server, group, c);
    server.commit(&mut b1, group, add).unwrap();
    let entries = server.entries(group);
    let asked = error(&mut c1.core, apply(group, &entries));
    assert_eq!(
        (&asked["code"], &asked["users"]),
        (&json!("needs_identities"), &json!([a.to_string()]))
    );
    assert_eq!(ok(&mut c1.core, server.observed(a))["state"], "same");
    let refused = results(&[ok(&mut c1.core, apply(group, &entries))]);
    assert_eq!(
        refused.last().unwrap(),
        &json!([entries.len(), "welcome", "rejected", "leaf_not_signed"])
    );
    assert_eq!(c1.no_group(group)["what"], "group");

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

    // And C, whom the welcome in between left out, comes in by external commit.
    ok(&mut c1.core, server.observed(d));
    let join = joining(&server, group);
    server.commit(&mut c1, group, join).unwrap();
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
    assert_eq!(due(&mut a1), BTreeSet::from([group]));
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // The same through the queue: A1 renews its leaf, with the new certificate, then starts over
    // before the server's word, which it hears as a refusal (a lost answer, then the retry's 409).
    // The group isn't due while the commit waits. B, keeping up, takes the commit.
    let made = ok(&mut a1.core, command("refresh", group));
    let reset = ok(&mut a1.core, json!({"cmd": "reset_identity"}));
    let seq = server.take_unheard(&mut a1, group, &made);
    let observed = deliver_observing(&mut server, &mut b1, group, a);
    assert_eq!(observed["state"], "changed");
    server.take_identity(a, &reset);
    assert_eq!(due(&mut a1), BTreeSet::new());

    // The queue brings the commit back, and A1 merges it: its leaf is the one it made before
    // starting over, so the group is due again.
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

#[test]
fn reset_identity_keeps_the_groups_and_renews_them() {
    let mut server = FakeServer::new();
    let (a, b, c) = (new_id(), new_id(), new_id());
    let mut a1 = server.device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    let group = new_id();
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // A starts over on A1: a new identity, whose list has A1 alone. The server proposes A2's
    // removal, as A2 is off the list.
    let reset = ok(&mut a1.core, json!({"cmd": "reset_identity"}));
    server.take_identity(a, &reset);
    server.remove_device(group, a2.id);

    // A1 stays in its group, which is due for its leaf at once. The refresh certifies the leaf
    // anew and takes A2 out; B takes it once it observes A anew.
    assert_eq!(due(&mut a1), BTreeSet::from([group]));
    server.deliver(&mut a1);
    server
        .commit(&mut a1, group, command("refresh", group))
        .unwrap();
    assert_eq!(due(&mut a1), BTreeSet::new());
    let observed = deliver_observing(&mut server, &mut b1, group, a);
    assert_eq!(observed["state"], "changed");

    // A, the owner, adds C, whose welcome takes the group.
    let mut c1 = server.device(c);
    server.publish(&mut c1);
    server.introduce(&mut c1);
    for device in [&mut a1, &mut b1] {
        ok(&mut device.core, server.observed(c));
    }
    let add = adding(&mut server, group, c);
    server.commit(&mut a1, group, add).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1, &mut c1]);
    let state = same_group(&mut [&mut a1, &mut b1, &mut c1], group);
    assert_eq!(
        devices(&state).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([a1.id, b1.id, c1.id])
    );
}
