//! Identity, devices, contacts and key packages, through `Core::handle` as a client drives them.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e::{Clock, Core, FakeClock, OpenConfig, recovery};
use duvet_e2e_rules::{
    BindProof, DEVICE_BIND, DeviceCertificate, DeviceList, MEMBER_LIST_EXTENSION, RuleViolation,
    SUITE,
};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::storage::StorageProvider as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn new_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0000_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

fn open(dir: &TempDir, clock: &FakeClock) -> Core {
    Core::open(OpenConfig {
        clock: Box::new(clock.clone()),
        ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
    })
    .unwrap()
}

fn run(core: &mut Core, command: &Value) -> Value {
    serde_json::from_str(&core.handle(&command.to_string())).expect("a JSON reply")
}

fn ok(core: &mut Core, command: Value) -> Value {
    let reply = run(core, &command);
    reply
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{command} failed: {reply}"))
}

fn error(core: &mut Core, command: Value) -> Value {
    let reply = run(core, &command);
    reply
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("{command} didn't fail: {reply}"))
}

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("base64 text"))
        .expect("padded base64")
}

fn key(value: &Value) -> [u8; 32] {
    bytes(value).try_into().expect("32 bytes")
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// The recovery key as an app shows it: 11 groups of 4, apart by `separator`.
fn format_in_groups(key: &str, separator: &str) -> String {
    key.as_bytes()
        .chunks(4)
        .map(|group| std::str::from_utf8(group).unwrap())
        .collect::<Vec<_>>()
        .join(separator)
}

/// A device with its user's identity, in a database of its own.
struct Person {
    core: Core,
    user: Uuid,
    device: Uuid,
    /// `create_identity`'s reply.
    identity: Value,
    _dir: TempDir,
}

impl Person {
    fn new(user: Uuid, clock: &FakeClock) -> Person {
        let dir = tempfile::tempdir().unwrap();
        let mut core = open(&dir, clock);
        let device = new_id();
        ok(
            &mut core,
            json!({"cmd": "create_device", "user_id": user, "device_id": device}),
        );
        let identity = ok(&mut core, json!({"cmd": "create_identity"}));
        Person {
            core,
            user,
            device,
            identity,
            _dir: dir,
        }
    }

    fn identity_key(&self) -> [u8; 32] {
        key(&self.identity["identity_key"])
    }

    /// What the server hands out about this person, as `observe_user` takes it.
    fn observed(&self) -> Value {
        json!({
            "cmd": "observe_user",
            "user_id": self.user,
            "identity_key": self.identity["identity_key"],
            "device_list": self.identity["device_list"],
            "certificates": [self.identity["certificate"]],
        })
    }

    /// The identity's signing key, recovered as a new device would: the recovery key opens the
    /// backup key, and the backup key the identity.
    fn identity_signer(&self) -> SignatureKeyPair {
        let recovery_key =
            recovery::parse(self.identity["recovery_key"].as_str().unwrap()).unwrap();
        let backup_key = recovery::unwrap_backup_key(
            &recovery_key,
            self.user,
            &bytes(&self.identity["wrapped_backup_key"]),
        )
        .unwrap();
        let secret = recovery::decrypt_identity(
            &backup_key,
            self.user,
            &bytes(&self.identity["encrypted_identity"]),
        )
        .unwrap();
        SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            secret.to_vec(),
            self.identity_key().to_vec(),
        )
    }

    fn safety_number(&mut self, user: Uuid) -> Value {
        ok(
            &mut self.core,
            json!({"cmd": "safety_number", "user_id": user}),
        )
    }
}

/// Someone else's identity, held by the test, which signs whatever lists and certificates a step needs.
struct Contact {
    user: Uuid,
    identity: SignatureKeyPair,
}

impl Contact {
    fn new(user: Uuid) -> Contact {
        Contact {
            user,
            identity: SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
        }
    }

    fn identity_key(&self) -> [u8; 32] {
        self.identity.public().try_into().unwrap()
    }

    fn list(&self, version: u64, devices: &[Uuid]) -> Vec<u8> {
        DeviceList::new(self.user, self.identity_key(), version, devices.to_vec())
            .sign(&self.identity)
            .unwrap()
    }

    fn certificate(&self, device: Uuid) -> Vec<u8> {
        DeviceCertificate::new(self.user, device, [3; 32], [4; 32], 1)
            .sign(&self.identity)
            .unwrap()
    }

    /// `observe_user` with a list of `version` and the certificates of its devices.
    fn observed(&self, version: u64, devices: &[Uuid]) -> Value {
        let certificates: Vec<String> = devices
            .iter()
            .map(|device| b64(&self.certificate(*device)))
            .collect();
        json!({
            "cmd": "observe_user",
            "user_id": self.user,
            "identity_key": b64(&self.identity_key()),
            "device_list": b64(&self.list(version, devices)),
            "certificates": certificates,
        })
    }
}

struct Published {
    id: Vec<u8>,
    data: Vec<u8>,
    key_package: KeyPackage,
    expires_at: i64,
    last_resort: bool,
}

/// `key_packages`, each one checked as the device that receives it checks it.
fn key_packages(core: &mut Core) -> Vec<Published> {
    read_key_packages(ok(core, json!({"cmd": "key_packages"})))
}

/// `key_packages` with `spent`: the IDs of key packages the API says it handed out.
fn spending(core: &mut Core, spent: &[&[u8]]) -> Vec<Published> {
    let spent: Vec<String> = spent.iter().map(|id| b64(id)).collect();
    read_key_packages(ok(core, json!({"cmd": "key_packages", "spent": spent})))
}

/// A `key_packages` reply's key packages, each one checked as the device that receives it checks
/// it.
fn read_key_packages(reply: Value) -> Vec<Published> {
    let crypto = RustCrypto::default();
    reply["key_packages"]
        .as_array()
        .expect("a list")
        .iter()
        .map(|published| {
            let data = bytes(&published["data"]);
            let key_package = KeyPackageIn::tls_deserialize_exact_bytes(&data)
                .expect("a key package")
                .validate(&crypto, ProtocolVersion::Mls10)
                .expect("a key package that validates");
            Published {
                id: bytes(&published["id"]),
                data,
                key_package,
                expires_at: published["expires_at"].as_i64().expect("Unix ms"),
                last_resort: published["last_resort"].as_bool().expect("a flag"),
            }
        })
        .collect()
}

fn last_resorts(published: &[Published]) -> usize {
    published.iter().filter(|kp| kp.last_resort).count()
}

/// The key packages of a reply, by ID: what the API keeps of each.
fn by_id(published: &[Published]) -> BTreeMap<&[u8], (&[u8], i64, bool)> {
    published
        .iter()
        .map(|kp| {
            (
                kp.id.as_slice(),
                (kp.data.as_slice(), kp.expires_at, kp.last_resort),
            )
        })
        .collect()
}

/// The key packages the device keeps a row of.
fn key_package_rows(core: &mut Core) -> i64 {
    core.transaction(|tx| {
        Ok(tx
            .conn()
            .query_row("SELECT count(*) FROM key_packages", [], |row| row.get(0))?)
    })
    .unwrap()
}

/// The key packages the device keeps a row of as spent.
fn spent_rows(core: &mut Core) -> i64 {
    core.transaction(|tx| {
        Ok(tx.conn().query_row(
            "SELECT count(*) FROM key_packages WHERE spent_at IS NOT NULL",
            [],
            |row| row.get(0),
        )?)
    })
    .unwrap()
}

/// Whether OpenMLS's storage still holds the key package, with its private keys.
fn stored(core: &mut Core, key_package: &KeyPackage) -> bool {
    let hash_ref = key_package.hash_ref(&RustCrypto::default()).unwrap();
    core.transaction(|tx| {
        Ok(tx
            .provider()
            .storage()
            .key_package::<KeyPackageRef, KeyPackageBundle>(&hash_ref)
            .map_err(|error| duvet_e2e::Error::Internal(error.to_string()))?
            .is_some())
    })
    .unwrap()
}

#[test]
fn create_identity_signs_own_device() {
    let clock = FakeClock::now();
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, &clock);

    // An identity needs this device first.
    let missing = error(&mut core, json!({"cmd": "create_identity"}));
    assert_eq!(missing["code"], "not_found", "{missing}");
    assert_eq!(missing["what"], "device", "{missing}");

    let (user, device) = (new_id(), new_id());
    let created = ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": device}),
    );
    let signature_key = key(&created["signature_key"]);
    let hpke_key = key(&created["hpke_key"]);
    assert_ne!(signature_key, hpke_key);
    let again = error(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": new_id()}),
    );
    assert_eq!(again["code"], "exists", "{again}");

    let identity = ok(&mut core, json!({"cmd": "create_identity"}));
    let identity_key = key(&identity["identity_key"]);

    // The certificate: this device's keys, signed by the identity.
    let certificate_bytes = bytes(&identity["certificate"]);
    let certificate = DeviceCertificate::verify(&certificate_bytes, &identity_key).unwrap();
    assert_eq!(certificate.user, user);
    assert_eq!(certificate.device, device);
    assert_eq!(certificate.signature_key, signature_key);
    assert_eq!(certificate.hpke_key, hpke_key);
    let created_at = i64::try_from(certificate.created).unwrap();
    assert!((created_at - clock.now_ms()).abs() < 60_000, "{created_at}");

    // The list: version 1, with this device alone.
    let list = DeviceList::verify(&bytes(&identity["device_list"]), &identity_key).unwrap();
    assert_eq!(list.user, user);
    assert_eq!(list.version, 1);
    assert_eq!(list.devices, vec![device]);

    // The recovery key: 48 characters of bitcoin's base58 alphabet.
    let recovery_key = identity["recovery_key"].as_str().unwrap();
    assert_eq!(recovery_key.len(), 48, "{recovery_key}");
    assert!(
        recovery_key.chars().all(|c| BASE58.contains(c)),
        "{recovery_key}"
    );

    // Run again before the client confirms its upload, it answers the same; once confirmed, it's
    // `exists`.
    assert_eq!(ok(&mut core, json!({"cmd": "create_identity"})), identity);
    ok(&mut core, json!({"cmd": "identity_uploaded"}));
    let again = error(&mut core, json!({"cmd": "create_identity"}));
    assert_eq!(again["code"], "exists", "{again}");

    let status = ok(&mut core, json!({"cmd": "status"}));
    assert_eq!(status["has_identity"], true);
    assert_eq!(status["identity_key"], identity["identity_key"]);
    assert_eq!(status["user_id"], json!(user));
    assert_eq!(status["device_id"], json!(device));

    // What later tasks read: the device, its identity and its list.
    core.transaction(|tx| {
        let own = tx.own_device()?;
        assert_eq!((own.user, own.device), (user, device));
        assert_eq!(own.signer.public(), signature_key);
        assert_eq!(own.hpke.public, hpke_key);
        assert_eq!(
            own.certificate.as_deref(),
            Some(certificate_bytes.as_slice())
        );
        let credential = own.credential()?;
        assert_eq!(
            credential.credential,
            Credential::from(BasicCredential::new(certificate_bytes.clone()))
        );
        assert_eq!(tx.identity_of(user)?, Some(identity_key));
        assert_eq!(tx.device_list_of(user)?, Some(list.clone()));
        assert_eq!(tx.identity_of(new_id())?, None);
        assert_eq!(tx.device_list_of(new_id())?, None);
        Ok(())
    })
    .unwrap();
}

const NOT_A_KEY: &str = "the recovery key isn't valid";
const CHECK_MISMATCH: &str = "the recovery key's check doesn't match";

/// A recovery key's 35 bytes, as the format has them apart from the core: its 32 bytes, then the
/// first 3 of SHA-256("duvet recovery checksum v1" || the 32 bytes).
fn checked(key: &[u8; 32]) -> Vec<u8> {
    let check = Sha256::new()
        .chain_update(b"duvet recovery checksum v1")
        .chain_update(key)
        .finalize();
    let mut bytes = key.to_vec();
    bytes.extend_from_slice(&check[..3]);
    bytes
}

/// A recovery key's text: its 35 bytes in bitcoin's base58.
fn recovery_text(key: &[u8; 32]) -> String {
    bs58::encode(checked(key)).into_string()
}

/// How `parse` refuses `text`: `bad_command` on `recovery_key`, with a fixed message, which it returns.
fn refusal(text: &str) -> String {
    let reply = recovery::parse(text).unwrap_err().to_reply();
    assert_eq!(reply["error"]["code"], "bad_command", "{text}");
    assert_eq!(reply["error"]["field"], "recovery_key", "{text}");
    reply["error"]["message"].as_str().unwrap().to_owned()
}

#[test]
fn recovery_key_round_trip() {
    let rand = RustCrypto::default();
    for _ in 0..50 {
        let key = recovery::generate(&rand).unwrap();
        assert_eq!(key.len(), 48, "{}", *key);
        assert!(key.chars().all(|c| BASE58.contains(c)), "{}", *key);
        let bytes = recovery::parse(&key).unwrap();
        assert_eq!(recovery_text(&bytes), *key);
        assert_eq!(format_in_groups(&key, " ").split(' ').count(), 12);
        for written in [
            format_in_groups(&key, " "),
            format_in_groups(&key, "-"),
            format_in_groups(&key, " - "),
            format!("  {}\n", format_in_groups(&key, "\t")),
        ] {
            assert_eq!(*recovery::parse(&written).unwrap(), *bytes, "{written}");
        }
    }

    // A fixed key, so every run walks the same changes.
    let bytes: [u8; 32] = std::array::from_fn(|i| 0xa5u8.wrapping_add((i as u8).wrapping_mul(29)));
    let key = recovery_text(&bytes);
    assert_eq!(key.len(), 48, "{key}");
    assert_eq!(*recovery::parse(&key).unwrap(), bytes);

    // Every one-letter change is refused: its check doesn't match, or it isn't 35 bytes in base58.
    let mut caught_by_the_check = 0;
    for at in 0..key.len() {
        for letter in BASE58.chars().filter(|&c| c != key.as_bytes()[at] as char) {
            let mut changed = key.clone();
            changed.replace_range(at..=at, &letter.to_string());
            let message = refusal(&changed);
            assert!(
                message == CHECK_MISMATCH || message == NOT_A_KEY,
                "{message}"
            );
            caught_by_the_check += usize::from(message == CHECK_MISMATCH);
        }
    }
    assert!(caught_by_the_check > 0);

    // A check that doesn't match says so.
    let mut wrong_check = checked(&bytes);
    *wrong_check.last_mut().unwrap() ^= 1;
    let wrong_check = bs58::encode(wrong_check).into_string();
    assert_eq!(wrong_check.len(), 48);
    assert_eq!(refusal(&wrong_check), CHECK_MISMATCH);

    // Another key, with its own right check, reads, and opens nothing this one wrapped.
    let user = new_id();
    let wrapped = recovery::wrap_backup_key(&rand, &bytes, user, &[9; 32]).unwrap();
    assert_eq!(
        *recovery::unwrap_backup_key(&bytes, user, &wrapped).unwrap(),
        [9; 32]
    );
    let mut other_bytes = bytes;
    other_bytes[31] ^= 1;
    let other = recovery::parse(&recovery_text(&other_bytes)).unwrap();
    assert_eq!(*other, other_bytes);
    let opened = recovery::unwrap_backup_key(&other, user, &wrapped);
    assert_eq!(opened.err().map(|e| e.code()), Some("decrypt_failed"));

    // Characters outside the alphabet, the wrong lengths (a key from before the check's 44 among
    // them), and nothing at all.
    for bad in [
        format!("0{}", &key[1..]),
        format!("O{}", &key[1..]),
        format!("I{}", &key[1..]),
        format!("l{}", &key[1..]),
        format!("é{}", &key[2..]),
        format!("+{}", &key[1..]),
        key[1..].to_string(),
        format!("{key}2"),
        key[..44].to_string(),
        String::new(),
    ] {
        assert_eq!(refusal(&bad), NOT_A_KEY, "{bad}");
    }
}

#[test]
fn backup_key_unwraps_only_with_its_recovery_key() {
    let clock = FakeClock::now();
    let alice = Person::new(new_id(), &clock);
    let rand = RustCrypto::default();
    let recovery_key = recovery::parse(alice.identity["recovery_key"].as_str().unwrap()).unwrap();
    let wrapped = bytes(&alice.identity["wrapped_backup_key"]);

    // The format: {v: 1, nonce, ct}.
    let value: ciborium::Value = ciborium::from_reader(wrapped.as_slice()).unwrap();
    let fields: Vec<(String, ciborium::Value)> = value
        .into_map()
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k.into_text().unwrap(), v))
        .collect();
    let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["v", "nonce", "ct"]);
    assert_eq!(fields[0].1, ciborium::Value::Integer(1.into()));
    assert_eq!(fields[1].1.as_bytes().unwrap().len(), 12);
    assert_eq!(fields[2].1.as_bytes().unwrap().len(), 32 + 16);

    let backup_key = recovery::unwrap_backup_key(&recovery_key, alice.user, &wrapped).unwrap();

    // Another recovery key, another user (the associated data), or a byte changed: refused.
    let other_key = recovery::parse(&recovery::generate(&rand).unwrap()).unwrap();
    for (recovery_key, user, wrapped) in [
        (&other_key, alice.user, wrapped.clone()),
        (&recovery_key, new_id(), wrapped.clone()),
        (&recovery_key, alice.user, {
            let mut changed = wrapped.clone();
            *changed.last_mut().unwrap() ^= 1;
            changed
        }),
    ] {
        let error = recovery::unwrap_backup_key(recovery_key, user, &wrapped).unwrap_err();
        assert_eq!(error.code(), "decrypt_failed");
    }
    for malformed in [Vec::new(), b"not cbor".to_vec(), {
        let mut longer = wrapped.clone();
        longer.push(0);
        longer
    }] {
        let error = recovery::unwrap_backup_key(&recovery_key, alice.user, &malformed).unwrap_err();
        assert_eq!(error.code(), "bad_command");
    }

    // Wrapped again under a new nonce, it still opens to the same key.
    let again = recovery::wrap_backup_key(&rand, &recovery_key, alice.user, &backup_key).unwrap();
    assert_ne!(again, wrapped);
    assert_eq!(
        *recovery::unwrap_backup_key(&recovery_key, alice.user, &again).unwrap(),
        *backup_key
    );
}

#[test]
fn identity_decrypts_only_with_its_backup_key() {
    let clock = FakeClock::now();
    let alice = Person::new(new_id(), &clock);
    let rand = RustCrypto::default();
    let recovery_key = recovery::parse(alice.identity["recovery_key"].as_str().unwrap()).unwrap();
    let backup_key = recovery::unwrap_backup_key(
        &recovery_key,
        alice.user,
        &bytes(&alice.identity["wrapped_backup_key"]),
    )
    .unwrap();
    let encrypted = bytes(&alice.identity["encrypted_identity"]);

    // The format: {v: 1, key_id, nonce, ct}, key_id the first 8 bytes of
    // SHA-256("duvet backup key id v1" || backup key).
    let value: ciborium::Value = ciborium::from_reader(encrypted.as_slice()).unwrap();
    let fields: Vec<(String, ciborium::Value)> = value
        .into_map()
        .unwrap()
        .into_iter()
        .map(|(k, v)| (k.into_text().unwrap(), v))
        .collect();
    let names: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(names, ["v", "key_id", "nonce", "ct"]);
    let key_id = Sha256::new()
        .chain_update(b"duvet backup key id v1")
        .chain_update(*backup_key)
        .finalize();
    assert_eq!(fields[1].1.as_bytes().unwrap().as_slice(), &key_id[..8]);
    assert_eq!(recovery::key_id(&backup_key).as_slice(), &key_id[..8]);
    assert_eq!(fields[2].1.as_bytes().unwrap().len(), 12);

    // It opens to the identity: its key signs what the identity key verifies.
    let secret = recovery::decrypt_identity(&backup_key, alice.user, &encrypted).unwrap();
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        secret.to_vec(),
        alice.identity_key().to_vec(),
    );
    let list = DeviceList::new(alice.user, alice.identity_key(), 7, vec![alice.device])
        .sign(&signer)
        .unwrap();
    assert_eq!(
        DeviceList::verify(&list, &alice.identity_key())
            .unwrap()
            .version,
        7
    );
    assert_eq!(alice.identity_signer().public(), alice.identity_key());

    // Another backup key, another user, or a byte changed: refused.
    let mut changed = encrypted.clone();
    *changed.last_mut().unwrap() ^= 1;
    for (backup_key, user, encrypted) in [
        (&[5u8; 32], alice.user, encrypted.clone()),
        (&*backup_key, new_id(), encrypted.clone()),
        (&*backup_key, alice.user, changed),
    ] {
        let error = recovery::decrypt_identity(backup_key, user, &encrypted).unwrap_err();
        assert_eq!(error.code(), "decrypt_failed");
    }
    let error = recovery::decrypt_identity(&backup_key, alice.user, b"\x01").unwrap_err();
    assert_eq!(error.code(), "bad_command");

    // Encrypted again under a new nonce, it opens to the same identity.
    let again = recovery::encrypt_identity(&rand, &backup_key, alice.user, &secret).unwrap();
    assert_ne!(again, encrypted);
    assert_eq!(
        *recovery::decrypt_identity(&backup_key, alice.user, &again).unwrap(),
        *secret
    );
}

#[test]
fn key_packages_top_up_to_100_plus_last_resort() {
    let clock = FakeClock::now();
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, &clock);

    // A key package carries the device's certificate: none before an identity.
    let (user, device) = (new_id(), new_id());
    ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": device}),
    );
    let missing = error(&mut core, json!({"cmd": "key_packages"}));
    assert_eq!(missing["code"], "not_found", "{missing}");
    assert_eq!(missing["what"], "identity", "{missing}");
    let identity = ok(&mut core, json!({"cmd": "create_identity"}));
    let certificate = bytes(&identity["certificate"]);
    let signature_key = core
        .transaction(|tx| Ok(tx.own_device()?.signer.public().to_vec()))
        .unwrap();

    let first = key_packages(&mut core);
    assert_eq!(first.len(), 101);
    assert_eq!(last_resorts(&first), 1);
    let crypto = RustCrypto::default();
    let ids: BTreeSet<&[u8]> = first.iter().map(|kp| kp.id.as_slice()).collect();
    assert_eq!(ids.len(), 101, "each key package once");
    for published in &first {
        let key_package = &published.key_package;
        assert_eq!(key_package.ciphersuite(), SUITE);
        assert_eq!(
            published.id,
            key_package.hash_ref(&crypto).unwrap().as_slice()
        );
        assert_eq!(key_package.last_resort(), published.last_resort);
        let capabilities = key_package.leaf_node().capabilities();
        assert!(
            capabilities
                .extensions()
                .contains(&ExtensionType::LastResort)
        );
        assert!(
            capabilities
                .extensions()
                .contains(&ExtensionType::Unknown(MEMBER_LIST_EXTENSION))
        );
        assert_eq!(
            key_package.leaf_node().credential(),
            &Credential::from(BasicCredential::new(certificate.clone()))
        );
        assert_eq!(
            key_package.leaf_node().signature_key().as_slice(),
            signature_key
        );
        // OpenMLS's default lifetime: 84 days.
        let not_after = i64::try_from(key_package.life_time().not_after()).unwrap();
        assert_eq!(published.expires_at, not_after * 1000);
        let left = published.expires_at - clock.now_ms();
        assert!((left - 84 * DAY_MS).abs() < 60_000, "{left}");
    }

    // Nothing is due: none made, and the same 101 again, so a reply the client lost costs nothing.
    let again = key_packages(&mut core);
    assert_eq!(by_id(&again), by_id(&first));
    assert_eq!(key_package_rows(&mut core), 101);

    // 71 days on, every one has 13 days left, the last resort's included: a whole new set, and only
    // that one.
    clock.advance(71 * DAY_MS);
    let renewed = key_packages(&mut core);
    assert_eq!(renewed.len(), 101);
    assert_eq!(last_resorts(&renewed), 1);
    assert!(renewed.iter().all(|kp| !ids.contains(kp.id.as_slice())));
    // The old ones stay meanwhile, not handed out: a welcome to one of them may be on its way.
    assert!(first.iter().all(|kp| stored(&mut core, &kp.key_package)));
}

#[test]
fn welcomes_use_up_single_use_key_packages_only() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let published = key_packages(&mut alice.core);
    let single = published.iter().find(|kp| !kp.last_resort).unwrap();
    let last_resort = published.iter().find(|kp| kp.last_resort).unwrap();

    // Someone adds this device with a single-use key package, which its welcome uses up: one new
    // one takes its place, and it's no longer handed out.
    join(&mut alice.core, welcome_to(single.key_package.clone()));
    assert!(!stored(&mut alice.core, &single.key_package));
    let topped_up = key_packages(&mut alice.core);
    assert_eq!(topped_up.len(), 101);
    assert_eq!(last_resorts(&topped_up), 1);
    let before = by_id(&published);
    let made: Vec<&Published> = topped_up
        .iter()
        .filter(|kp| !before.contains_key(kp.id.as_slice()))
        .collect();
    assert_eq!(made.len(), 1);
    assert!(!made[0].last_resort);
    assert!(topped_up.iter().all(|kp| kp.id != single.id));

    // The last resort stays for the next one: none made.
    join(&mut alice.core, welcome_to(last_resort.key_package.clone()));
    assert!(stored(&mut alice.core, &last_resort.key_package));
    assert_eq!(by_id(&key_packages(&mut alice.core)), by_id(&topped_up));
}

/// A welcome from a group someone else creates and adds `key_package` to.
fn welcome_to(key_package: KeyPackage) -> Welcome {
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(b"someone".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let mut group = MlsGroup::new(&provider, &signer, &config, credential).unwrap();
    let (_, welcome, _) = group
        .add_members(&provider, &signer, &[key_package])
        .unwrap();
    let welcome = welcome.tls_serialize_detached().unwrap();
    match MlsMessageIn::tls_deserialize_exact_bytes(&welcome)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("a welcome"),
    }
}

fn join(core: &mut Core, welcome: Welcome) {
    core.transaction(|tx| {
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        StagedWelcome::new_from_welcome(tx.provider(), &config, welcome, None)
            .and_then(|staged| staged.into_group(tx.provider()))
            .map_err(|error| duvet_e2e::Error::Internal(error.to_string()))?;
        Ok(())
    })
    .unwrap();
}

#[test]
fn key_packages_are_deleted_once_no_welcome_can_use_them() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let first = key_packages(&mut alice.core);

    // 16 days past their end, a welcome to one of them may still wait in the server's queue,
    // which keeps entries 45 days.
    clock.advance(100 * DAY_MS);
    let second = key_packages(&mut alice.core);
    assert_eq!(second.len(), 101);
    assert!(
        first
            .iter()
            .all(|kp| stored(&mut alice.core, &kp.key_package))
    );

    // 46 days past their end, no welcome can: their private keys go.
    clock.advance(30 * DAY_MS);
    let third = key_packages(&mut alice.core);
    assert_eq!(third.len(), 101);
    for gone in first.iter().chain(&second) {
        assert!(!stored(&mut alice.core, &gone.key_package));
    }
    assert!(
        third
            .iter()
            .all(|kp| stored(&mut alice.core, &kp.key_package))
    );
    assert_eq!(key_package_rows(&mut alice.core), 101);
}

#[test]
fn spent_key_packages_make_room() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let first = key_packages(&mut alice.core);

    // The API handed out 10 of the single-use ones: they stop counting and leave the reply, 10 new
    // ones take their place, and the rest stay as they were.
    let spent: Vec<&Published> = first.iter().filter(|kp| !kp.last_resort).take(10).collect();
    let ids: Vec<&[u8]> = spent.iter().map(|kp| kp.id.as_slice()).collect();
    let marked = spending(&mut alice.core, &ids);
    assert_eq!(marked.len(), 101);
    assert_eq!(last_resorts(&marked), 1);
    assert!(marked.iter().all(|kp| !ids.contains(&kp.id.as_slice())));
    let before = by_id(&first);
    let made: Vec<&Published> = marked
        .iter()
        .filter(|kp| !before.contains_key(kp.id.as_slice()))
        .collect();
    assert_eq!(made.len(), 10);
    assert!(made.iter().all(|kp| !kp.last_resort));

    // Their keys stay, with their rows, for a welcome the API's hand-out may bring.
    assert!(
        spent
            .iter()
            .all(|kp| stored(&mut alice.core, &kp.key_package))
    );
    assert_eq!(key_package_rows(&mut alice.core), 111);

    // They stay out: the next call gives the same set, and naming them again changes nothing.
    assert_eq!(by_id(&key_packages(&mut alice.core)), by_id(&marked));
    assert_eq!(by_id(&spending(&mut alice.core, &ids)), by_id(&marked));
}

#[test]
fn a_spent_key_packages_keys_go_45_days_after() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let first = key_packages(&mut alice.core);
    let mut singles = first.iter().filter(|kp| !kp.last_resort);
    let (spent, late) = (singles.next().unwrap(), singles.next().unwrap());
    spending(&mut alice.core, &[&spent.id]);

    // Named again 30 days on, it keeps the day it was first spent.
    clock.advance(30 * DAY_MS);
    spending(&mut alice.core, &[&spent.id]);

    // On the last of its 45 days its keys stay, for the welcome of whoever the API handed it to.
    clock.advance(15 * DAY_MS);
    key_packages(&mut alice.core);
    assert!(stored(&mut alice.core, &spent.key_package));
    assert_eq!(key_package_rows(&mut alice.core), 102);

    // A moment later no welcome can come for it: its keys go, and its row.
    clock.advance(1);
    key_packages(&mut alice.core);
    assert!(!stored(&mut alice.core, &spent.key_package));
    assert_eq!(key_package_rows(&mut alice.core), 101);

    // Spent after its end, a key package still goes 45 days after its end: being spent never keeps
    // keys longer. On day 100 the first ones ended 16 days ago; on day 130, 46 days ago, and only
    // 30 since `late` was spent.
    clock.advance(55 * DAY_MS - 1);
    spending(&mut alice.core, &[&late.id]);
    assert!(stored(&mut alice.core, &late.key_package));
    clock.advance(30 * DAY_MS);
    key_packages(&mut alice.core);
    assert!(!stored(&mut alice.core, &late.key_package));
}

#[test]
fn spent_ignores_what_it_does_not_hold() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let first = key_packages(&mut alice.core);
    let mut singles = first.iter().filter(|kp| !kp.last_resort);
    let (used, live) = (singles.next().unwrap(), singles.next().unwrap());
    let last_resort = first.iter().find(|kp| kp.last_resort).unwrap();

    // One a welcome used up, which the next call forgets and replaces.
    join(&mut alice.core, welcome_to(used.key_package.clone()));
    let topped_up = key_packages(&mut alice.core);

    // Named with a live single-use one: an ID the device never had, the last resort's and the
    // used-up one's change nothing. Only the live one is spent, and only it is replaced.
    let unknown = [7; 32];
    let named: [&[u8]; 4] = [&unknown, &last_resort.id, &used.id, &live.id];
    let marked = spending(&mut alice.core, &named);
    assert!(marked.iter().all(|kp| kp.id != live.id));
    let mut kept = by_id(&topped_up);
    kept.remove(live.id.as_slice());
    let mut made = by_id(&marked);
    made.retain(|id, kp| kept.get(id) != Some(kp));
    assert_eq!(made.len(), 1);
    assert!(made.values().all(|(_, _, last_resort)| !last_resort));
    assert_eq!(marked.len(), kept.len() + 1);

    // The last resort still goes out, its keys stay, and naming it again changes nothing.
    assert!(marked.iter().any(|kp| kp.id == last_resort.id));
    assert!(stored(&mut alice.core, &last_resort.key_package));
    let again = spending(&mut alice.core, &[&unknown, &last_resort.id]);
    assert_eq!(by_id(&again), by_id(&marked));
    assert_eq!(key_package_rows(&mut alice.core), 102);
}

#[test]
fn spent_takes_200_at_most() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let first = key_packages(&mut alice.core);
    let mut singles = first.iter().filter(|kp| !kp.last_resort);
    let (taken, refused) = (singles.next().unwrap(), singles.next().unwrap());
    let unknown: Vec<Vec<u8>> = (0..200u8).map(|byte| vec![byte; 32]).collect();

    // 200 IDs: 199 the device never had, and one it holds, which is spent.
    let mut most: Vec<&[u8]> = unknown[..199].iter().map(Vec::as_slice).collect();
    most.push(&taken.id);
    let marked = spending(&mut alice.core, &most);
    assert!(marked.iter().all(|kp| kp.id != taken.id));

    // 201 are too many, and none is spent, the one it holds included.
    let mut many: Vec<String> = unknown.iter().map(|id| b64(id)).collect();
    many.push(b64(&refused.id));
    let too_many = error(
        &mut alice.core,
        json!({"cmd": "key_packages", "spent": many}),
    );
    assert_eq!(
        (&too_many["code"], &too_many["limit"]),
        (&json!("too_large"), &json!(200))
    );
    assert_eq!(by_id(&key_packages(&mut alice.core)), by_id(&marked));
}

#[test]
fn a_device_keeps_1000_spent_key_packages_at_most() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let mut live = key_packages(&mut alice.core);
    let oldest = live.iter().find(|kp| !kp.last_resort).unwrap().id.clone();

    // An API that names every single-use one it was sent, 11 rounds a minute apart. Round 1 names
    // all but the oldest, which round 2 names: it's marked after round 1's, though its row is older.
    let mut rounds: Vec<Vec<Published>> = Vec::new();
    for round in 0..11 {
        let mut named: Vec<Published> = live.into_iter().filter(|kp| !kp.last_resort).collect();
        if round == 0 {
            named.retain(|kp| kp.id != oldest);
        }
        let ids: Vec<&[u8]> = named.iter().map(|kp| kp.id.as_slice()).collect();
        live = spending(&mut alice.core, &ids);
        rounds.push(named);
        clock.advance(60 * 1000);
    }
    assert!(rounds[1].iter().any(|kp| kp.id == oldest));

    // 1099 marked: the 99 marked first lose their keys and rows, and the 1000 since stay.
    assert_eq!(spent_rows(&mut alice.core), 1000);
    assert!(
        rounds[0]
            .iter()
            .all(|kp| !stored(&mut alice.core, &kp.key_package))
    );
    assert!(
        rounds[1..]
            .iter()
            .flatten()
            .all(|kp| stored(&mut alice.core, &kp.key_package))
    );
    assert_eq!(key_package_rows(&mut alice.core), 1101);

    // The reply's own keep their keys: the cap takes spent ones alone.
    assert_eq!(live.len(), 101);
    assert!(
        live.iter()
            .all(|kp| stored(&mut alice.core, &kp.key_package))
    );

    // The newest marked one still takes its welcome.
    let newest = rounds[10].last().unwrap();
    join(&mut alice.core, welcome_to(newest.key_package.clone()));
}

#[test]
fn sign_device_list_removes_devices() {
    let clock = FakeClock::now();

    // Without an identity there's nothing to sign with.
    let dir = tempfile::tempdir().unwrap();
    let mut bare = open(&dir, &clock);
    ok(
        &mut bare,
        json!({"cmd": "create_device", "user_id": new_id(), "device_id": new_id()}),
    );
    let missing = error(&mut bare, json!({"cmd": "sign_device_list", "remove": []}));
    assert_eq!(missing["code"], "not_found", "{missing}");
    assert_eq!(missing["what"], "identity", "{missing}");

    // Another device of the user joins the list, signed by the identity elsewhere (as a recovery
    // or an approval does), and this device learns of it from the server.
    let mut alice = Person::new(new_id(), &clock);
    let identity = alice.identity_signer();
    let identity_key = b64(&alice.identity_key());
    let other = new_id();
    let list = DeviceList::new(
        alice.user,
        alice.identity_key(),
        2,
        vec![alice.device, other],
    )
    .sign(&identity)
    .unwrap();
    let other_certificate = DeviceCertificate::new(alice.user, other, [5; 32], [6; 32], 1)
        .sign(&identity)
        .unwrap();
    let observed = json!({
        "cmd": "observe_user",
        "user_id": alice.user,
        "identity_key": identity_key,
        "device_list": b64(&list),
        "certificates": [alice.identity["certificate"], b64(&other_certificate)],
    });
    let seen = ok(&mut alice.core, observed);
    assert_eq!(seen, json!({"state": "same", "verified": true}));

    // Taken off: version 3, without it.
    let signed = ok(
        &mut alice.core,
        json!({"cmd": "sign_device_list", "remove": [other]}),
    );
    let list = DeviceList::verify(&bytes(&signed["device_list"]), &alice.identity_key()).unwrap();
    assert_eq!(list.version, 3);
    assert_eq!(list.devices, vec![alice.device]);
    let user = alice.user;
    let kept = alice
        .core
        .transaction(|tx| tx.device_list_of(user))
        .unwrap();
    assert_eq!(kept, Some(list));

    // A device the list doesn't have.
    let missing = error(
        &mut alice.core,
        json!({"cmd": "sign_device_list", "remove": [other]}),
    );
    assert_eq!(missing["code"], "not_found", "{missing}");
    assert_eq!(missing["what"], "device", "{missing}");
    let kept = alice
        .core
        .transaction(|tx| tx.device_list_of(user))
        .unwrap();
    assert_eq!(kept.map(|list| list.version), Some(3));

    // The user's own lists from the server: an older one, or another identity's, are refused.
    let older = DeviceList::new(alice.user, alice.identity_key(), 2, vec![alice.device])
        .sign(&identity)
        .unwrap();
    let observed = json!({
        "cmd": "observe_user",
        "user_id": alice.user,
        "identity_key": identity_key,
        "device_list": b64(&older),
        "certificates": [],
    });
    let seen = ok(&mut alice.core, observed);
    assert_eq!(seen["state"], "rejected", "{seen}");
    assert_eq!(seen["reason"], "older_list", "{seen}");
    let impostor = Contact {
        user: alice.user,
        identity: SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
    };
    let seen = ok(&mut alice.core, impostor.observed(9, &[alice.device]));
    assert_eq!(seen["state"], "rejected", "{seen}");
    assert_eq!(seen["reason"], "not_own_identity", "{seen}");
    let pinned = alice.core.transaction(|tx| tx.identity_of(user)).unwrap();
    assert_eq!(pinned, Some(alice.identity_key()));
}

#[test]
fn observe_user_pins_then_detects_change() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let bob = Contact::new(new_id());
    let (first, second) = (new_id(), new_id());

    let seen = ok(&mut alice.core, bob.observed(1, &[first]));
    assert_eq!(seen, json!({"state": "new", "verified": false}));

    // A newer list of the same identity, or the same list again.
    let seen = ok(&mut alice.core, bob.observed(2, &[first, second]));
    assert_eq!(seen, json!({"state": "same", "verified": false}));
    let seen = ok(&mut alice.core, bob.observed(2, &[first, second]));
    assert_eq!(seen["state"], "same", "{seen}");

    // An older list, or another list under the same version.
    let seen = ok(&mut alice.core, bob.observed(1, &[first]));
    assert_eq!(
        seen,
        json!({"state": "rejected", "verified": false, "reason": "older_list"})
    );
    let seen = ok(&mut alice.core, bob.observed(2, &[first]));
    assert_eq!(seen["state"], "rejected", "{seen}");
    assert_eq!(seen["reason"], "conflicting_list", "{seen}");

    // Lists and certificates the identity didn't sign, or that aren't the user's.
    let mut forged = bob.observed(3, &[first]);
    forged["device_list"] = json!(b64(&Contact::new(bob.user).list(3, &[first])));
    let refused = error(&mut alice.core, forged);
    assert_eq!(refused["code"], "invalid_signature", "{refused}");
    assert_eq!(refused["what"], "device_list", "{refused}");
    let mut forged = bob.observed(3, &[first]);
    forged["certificates"] = json!([b64(&Contact::new(bob.user).certificate(first))]);
    let refused = error(&mut alice.core, forged);
    assert_eq!(refused["code"], "invalid_signature", "{refused}");
    assert_eq!(refused["what"], "certificate", "{refused}");
    let mut short = bob.observed(3, &[first]);
    short["identity_key"] = json!(b64(&[1; 31]));
    let refused = error(&mut alice.core, short);
    assert_eq!(refused["code"], "bad_command", "{refused}");
    assert_eq!(refused["field"], "identity_key", "{refused}");
    let stranger = Contact {
        user: new_id(),
        identity: SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
    };
    let mut theirs = stranger.observed(3, &[first]);
    theirs["user_id"] = json!(bob.user);
    theirs["identity_key"] = json!(b64(&stranger.identity_key()));
    let seen = ok(&mut alice.core, theirs);
    assert_eq!(seen["state"], "rejected", "{seen}");
    assert_eq!(seen["reason"], "wrong_user", "{seen}");
    let mut unlisted = bob.observed(3, &[first]);
    unlisted["certificates"] = json!([b64(&bob.certificate(new_id()))]);
    let seen = ok(&mut alice.core, unlisted);
    assert_eq!(seen["state"], "rejected", "{seen}");
    assert_eq!(seen["reason"], "unlisted_device", "{seen}");

    // None of that changed what's pinned.
    let user = bob.user;
    let (identity, list) = alice
        .core
        .transaction(|tx| Ok((tx.identity_of(user)?, tx.device_list_of(user)?)))
        .unwrap();
    assert_eq!(identity, Some(bob.identity_key()));
    assert_eq!(list.map(|list| list.version), Some(2));

    // Another identity: a change, the previous one kept.
    let new_bob = Contact::new(bob.user);
    let third = new_id();
    let seen = ok(&mut alice.core, new_bob.observed(1, &[third]));
    assert_eq!(
        seen,
        json!({"state": "changed", "verified": false, "was_verified": false})
    );
    let (identity, list) = alice
        .core
        .transaction(|tx| Ok((tx.identity_of(user)?, tx.device_list_of(user)?)))
        .unwrap();
    assert_eq!(identity, Some(new_bob.identity_key()));
    let list = list.unwrap();
    assert_eq!((list.version, list.devices), (1, vec![third]));
    assert_eq!(
        past_identities(&mut alice.core, user),
        vec![bob.identity_key().to_vec()]
    );

    // The new identity numbers its lists from 1. Going back to the earlier identity is another
    // change, as recovering an identity from before a reset looks.
    let seen = ok(&mut alice.core, new_bob.observed(2, &[third]));
    assert_eq!(seen["state"], "same", "{seen}");
    let seen = ok(&mut alice.core, bob.observed(5, &[first]));
    assert_eq!(
        seen,
        json!({"state": "changed", "verified": false, "was_verified": false})
    );
    assert_eq!(
        past_identities(&mut alice.core, user),
        vec![new_bob.identity_key().to_vec()]
    );
}

/// A change says whether the person had verified the identity it replaced, which a strong warning
/// goes by; the new one starts unverified either way. Nothing else says it.
#[test]
fn changed_says_the_contact_was_verified() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let bob = Person::new(new_id(), &clock);
    ok(&mut alice.core, bob.observed());
    let verified = ok(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user}),
    );
    assert_eq!(verified, json!({"verified": true}));

    // Bob starts over: the identity Alice verified is replaced.
    let new_bob = Person::new(bob.user, &clock);
    let seen = ok(&mut alice.core, new_bob.observed());
    assert_eq!(
        seen,
        json!({"state": "changed", "verified": false, "was_verified": true})
    );

    // Again, from an identity she never verified.
    let newer_bob = Person::new(bob.user, &clock);
    let seen = ok(&mut alice.core, newer_bob.observed());
    assert_eq!(
        seen,
        json!({"state": "changed", "verified": false, "was_verified": false})
    );
    let seen = ok(&mut alice.core, newer_bob.observed());
    assert_eq!(seen, json!({"state": "same", "verified": false}));
}

/// The identities `user` had before the one pinned now.
fn past_identities(core: &mut Core, user: Uuid) -> Vec<Vec<u8>> {
    core.transaction(|tx| {
        let mut statement = tx
            .conn()
            .prepare("SELECT identity_key FROM contact_identities WHERE user_id = ?1")?;
        let keys = statement
            .query_map([user.as_bytes().as_slice()], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(keys)
    })
    .unwrap()
}

#[test]
fn safety_number_is_symmetric() {
    let clock = FakeClock::now();
    let mut alice = Person::new(new_id(), &clock);
    let mut bob = Person::new(new_id(), &clock);
    let carol = Person::new(new_id(), &clock);

    // A user not observed yet: their identity is missing.
    let missing = error(
        &mut alice.core,
        json!({"cmd": "safety_number", "user_id": bob.user}),
    );
    assert_eq!(missing["code"], "needs_identities", "{missing}");
    assert_eq!(missing["users"], json!([bob.user]), "{missing}");

    ok(&mut alice.core, bob.observed());
    ok(&mut bob.core, alice.observed());
    ok(&mut alice.core, carol.observed());

    let alice_sees = alice.safety_number(bob.user);
    let bob_sees = bob.safety_number(alice.user);
    assert_eq!(alice_sees, bob_sees);
    let digits = alice_sees["digits"].as_str().unwrap();
    let groups: Vec<&str> = digits.split(' ').collect();
    assert_eq!(groups.len(), 12, "{digits}");
    assert!(
        groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())),
        "{digits}"
    );

    // The QR: {v: 1, users: [{user, identity_key}]}, the two users in order.
    let qr = bytes(&alice_sees["qr"]);
    let value: ciborium::Value = ciborium::from_reader(qr.as_slice()).unwrap();
    let map = value.into_map().unwrap();
    assert_eq!(map[0].0.as_text(), Some("v"));
    assert_eq!(map[1].0.as_text(), Some("users"));
    let users: Vec<(Vec<u8>, Vec<u8>)> = map[1]
        .1
        .as_array()
        .unwrap()
        .iter()
        .map(|user| {
            let user = user.as_map().unwrap();
            assert_eq!(user[0].0.as_text(), Some("user"));
            assert_eq!(user[1].0.as_text(), Some("identity_key"));
            (
                user[0].1.as_bytes().unwrap().clone(),
                user[1].1.as_bytes().unwrap().clone(),
            )
        })
        .collect();
    let mut expected = vec![
        (
            alice.user.as_bytes().to_vec(),
            alice.identity_key().to_vec(),
        ),
        (bob.user.as_bytes().to_vec(), bob.identity_key().to_vec()),
    ];
    expected.sort();
    assert_eq!(users, expected);

    // Scanning the other's QR verifies; the QR of another pair doesn't.
    let verified = ok(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user, "qr": bob_sees["qr"]}),
    );
    assert_eq!(verified, json!({"verified": true}));
    let carols = alice.safety_number(carol.user);
    let verified = ok(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user, "qr": carols["qr"]}),
    );
    assert_eq!(verified, json!({"verified": false}));
    let seen = ok(&mut alice.core, bob.observed());
    assert_eq!(seen, json!({"state": "same", "verified": true}));

    // Bob starts over with a new identity: a change, and no longer verified.
    let mut new_bob = Person::new(bob.user, &clock);
    let seen = ok(&mut alice.core, new_bob.observed());
    assert_eq!(
        seen,
        json!({"state": "changed", "verified": false, "was_verified": true})
    );
    ok(&mut new_bob.core, alice.observed());
    let alice_sees = alice.safety_number(bob.user);
    assert_ne!(alice_sees["digits"], bob_sees["digits"]);
    assert_eq!(alice_sees, new_bob.safety_number(alice.user));

    // Comparing the digits by eye verifies too.
    let verified = ok(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user}),
    );
    assert_eq!(verified, json!({"verified": true}));

    // A QR of the same two users with another key for one of them: they aren't who the pin says.
    let verified = ok(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user, "qr": bob_sees["qr"]}),
    );
    assert_eq!(verified, json!({"verified": false}));
    let seen = ok(&mut alice.core, new_bob.observed());
    assert_eq!(seen, json!({"state": "same", "verified": false}));

    // A QR that isn't one.
    let refused = error(
        &mut alice.core,
        json!({"cmd": "verify_user", "user_id": bob.user, "qr": b64(b"hello")}),
    );
    assert_eq!(refused["code"], "bad_command", "{refused}");
    assert_eq!(refused["field"], "qr", "{refused}");
}

/// The bind proof's fixture, which the API's Go test reads too: a seed for the device's key, what
/// the proof says, and the proof.
const BIND_PROOF_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/bind-proof.json"
);

/// The Ed25519 key pair of `seed`, as OpenMLS holds a device's.
fn seed_signer(seed: &[u8; 32]) -> SignatureKeyPair {
    let public = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec())
}

fn bind_proof(core: &mut Core, challenge: &[u8]) -> Value {
    run(
        core,
        &json!({"cmd": "bind_proof", "challenge": b64(challenge)}),
    )
}

#[test]
fn bind_proof_signs_the_challenge_with_the_device_key() {
    let clock = FakeClock::now();
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, &clock);
    let (user, device) = (new_id(), new_id());
    let created = ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": user, "device_id": device}),
    );
    let signature_key = key(&created["signature_key"]);
    let challenge = [0xc4; 32];
    let says = BindProof::new(user, device, key(&created["hpke_key"]), challenge);

    // From its start, before it has a certificate: the device binds its HPKE key itself.
    let proof = bytes(&bind_proof(&mut core, &challenge)["ok"]["proof"]);
    assert_eq!(BindProof::verify(&proof, &signature_key), Ok(says.clone()));

    // With a certificate the same: the device's key signs it, not the identity's.
    let identity = ok(&mut core, json!({"cmd": "create_identity"}));
    let proof = bytes(&bind_proof(&mut core, &challenge)["ok"]["proof"]);
    assert_eq!(BindProof::verify(&proof, &signature_key), Ok(says));
    assert_eq!(
        BindProof::verify(&proof, &key(&identity["identity_key"])),
        Err(RuleViolation::InvalidSignature)
    );

    // Each session's challenge is in its own proof.
    let other = [0x3d; 32];
    let proof = bytes(&bind_proof(&mut core, &other)["ok"]["proof"]);
    assert_eq!(
        BindProof::verify(&proof, &signature_key).map(|bound| bound.challenge),
        Ok(other.to_vec())
    );
}

#[test]
fn bind_proof_needs_32_bytes() {
    let clock = FakeClock::now();
    let dir = tempfile::tempdir().unwrap();
    let mut core = open(&dir, &clock);

    // Without a device there's no key to sign with.
    let missing = bind_proof(&mut core, &[0xc4; 32])["error"].clone();
    assert_eq!(
        (&missing["code"], &missing["what"]),
        (&json!("not_found"), &json!("device")),
        "{missing}"
    );

    ok(
        &mut core,
        json!({"cmd": "create_device", "user_id": new_id(), "device_id": new_id()}),
    );
    for length in [0, 16, 31, 33, 64] {
        let refused = bind_proof(&mut core, &vec![0xc4; length])["error"].clone();
        assert_eq!(
            (&refused["code"], &refused["field"]),
            (&json!("bad_command"), &json!("challenge")),
            "{length} bytes: {refused}"
        );
    }
    let without = error(&mut core, json!({"cmd": "bind_proof"}));
    assert_eq!(
        (&without["code"], &without["field"]),
        (&json!("bad_command"), &json!("challenge")),
        "{without}"
    );
    assert!(bind_proof(&mut core, &[0xc4; 32])["ok"]["proof"].is_string());
}

/// The fixture's seed makes the fixture's proof: Ed25519 signs deterministically, and the proof's
/// body has one encoding. The API's Go test verifies the same proof.
#[test]
fn bind_proof_matches_its_fixture() {
    let fixture: Value =
        serde_json::from_str(&std::fs::read_to_string(BIND_PROOF_FIXTURE).unwrap()).unwrap();
    assert_eq!(fixture["label"], DEVICE_BIND);
    let signer = seed_signer(&key(&fixture["seed"]));
    let signature_key = key(&fixture["signature_key"]);
    assert_eq!(signer.public(), signature_key);
    let uuid = |field: &str| -> Uuid { fixture[field].as_str().unwrap().parse().unwrap() };
    let says = BindProof::new(
        uuid("user"),
        uuid("device"),
        key(&fixture["hpke_key"]),
        key(&fixture["challenge"]),
    );
    let proof = bytes(&fixture["proof"]);
    assert_eq!(says.sign(&signer).unwrap(), proof);
    assert_eq!(BindProof::verify(&proof, &signature_key), Ok(says));
}

#[test]
#[ignore = "writes tests/fixtures/bind-proof.json, which the API's Go test reads too"]
fn write_bind_proof_fixture() {
    let seed = [0x5b; 32];
    let signer = seed_signer(&seed);
    let user = Uuid::from_u128(0x0193_8a5c_4e00_7b3a_9c1d_2e3f_4a5b_6c7d);
    let device = Uuid::from_u128(0x0193_8a5c_4e01_7d2e_8f30_4152_6374_8596);
    let (hpke_key, challenge) = ([0x11; 32], [0xc4; 32]);
    let proof = BindProof::new(user, device, hpke_key, challenge)
        .sign(&signer)
        .unwrap();
    let fixture = json!({
        "label": DEVICE_BIND,
        "seed": b64(&seed),
        "signature_key": b64(signer.public()),
        "user": user,
        "device": device,
        "hpke_key": b64(&hpke_key),
        "challenge": b64(&challenge),
        "proof": b64(&proof),
    });
    let text = serde_json::to_string_pretty(&fixture).unwrap() + "\n";
    std::fs::write(BIND_PROOF_FIXTURE, text).unwrap();
}
