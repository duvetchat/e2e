//! The local database, the entry point and OpenMLS's storage.

use duvet_e2e::{Core, Error, OpenConfig};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde_json::Value;
use tempfile::TempDir;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn config(dir: &TempDir, key: u8) -> OpenConfig {
    OpenConfig::new(dir.path().join("core.db"), [key; 32])
}

fn reply(core: &mut Core, command: &str) -> Value {
    serde_json::from_str(&core.handle(command)).expect("a JSON reply")
}

fn ok(core: &mut Core, command: &str) -> Value {
    let reply = reply(core, command);
    reply
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{command} failed: {reply}"))
}

#[test]
fn second_open_is_locked() {
    let dir = tempfile::tempdir().unwrap();
    let first = Core::open(config(&dir, 1)).unwrap();

    let second = Core::open(config(&dir, 1));
    assert_eq!(second.err().map(|e| e.code()), Some("locked"));

    first.close();
    Core::open(config(&dir, 1)).unwrap();
}

#[test]
fn wrong_key_is_bad_key() {
    let dir = tempfile::tempdir().unwrap();
    Core::open(config(&dir, 1)).unwrap().close();

    let wrong = Core::open(config(&dir, 2));
    assert_eq!(wrong.err().map(|e| e.code()), Some("bad_key"));

    let mut core = Core::open(config(&dir, 1)).unwrap();
    assert_eq!(ok(&mut core, r#"{"cmd":"status"}"#)["protocol"], 1);
}

#[test]
fn status_before_anything() {
    let dir = tempfile::tempdir().unwrap();
    let mut core = Core::open(config(&dir, 1)).unwrap();

    let status = ok(&mut core, r#"{"cmd":"status"}"#);
    assert_eq!(status["protocol"], 1);
    assert_eq!(status["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(status["has_identity"], false);
    assert_eq!(status["key_storage"], "provided");
    assert!(status.get("user_id").is_none(), "{status}");
    assert!(status.get("device_id").is_none(), "{status}");
    assert!(status.get("identity_key").is_none(), "{status}");
}

#[test]
fn unknown_command_is_bad_command() {
    let dir = tempfile::tempdir().unwrap();
    let mut core = Core::open(config(&dir, 1)).unwrap();

    for command in [r#"{"cmd":"nope"}"#, r#"{"command":"status"}"#, "{", "[]"] {
        let error = &reply(&mut core, command)["error"];
        assert_eq!(error["code"], "bad_command", "{command}: {error}");
        assert!(
            error["message"].as_str().is_some_and(|m| !m.is_empty()),
            "{error}"
        );
    }
}

#[test]
fn mls_state_survives_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let group_id = GroupId::from_slice(b"a conversation and its generation");

    let mut core = Core::open(config(&dir, 1)).unwrap();
    core.transaction(|tx| {
        let provider = tx.provider();
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"device".to_vec()).into(),
            signature_key: signer.public().into(),
        };
        let config = MlsGroupCreateConfig::builder().ciphersuite(SUITE).build();
        let mut group =
            MlsGroup::new_with_group_id(provider, &signer, &config, group_id.clone(), credential)
                .unwrap();
        group
            .self_update(provider, &signer, LeafNodeParameters::default())
            .unwrap();
        group.merge_pending_commit(provider).unwrap();
        assert_eq!(group.epoch().as_u64(), 1);
        Ok(())
    })
    .unwrap();
    core.close();

    let mut core = Core::open(config(&dir, 1)).unwrap();
    let epoch = core
        .transaction(|tx| {
            let group = MlsGroup::load(tx.provider().storage(), &group_id)
                .unwrap()
                .expect("the group");
            Ok(group.epoch().as_u64())
        })
        .unwrap();
    assert_eq!(epoch, 1);
}

#[test]
fn failed_command_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut core = Core::open(config(&dir, 1)).unwrap();

    let failed: Result<(), Error> = core.transaction(|tx| {
        tx.conn().execute(
            "INSERT INTO meta (key, value) VALUES ('witness', x'01')",
            [],
        )?;
        let signer = SignatureKeyPair::new(SUITE.signature_algorithm()).unwrap();
        signer.store(tx.provider().storage()).unwrap();
        Err(Error::Internal("forced".into()))
    });
    assert_eq!(failed.err().map(|e| e.code()), Some("internal"));

    let counts = core
        .transaction(|tx| {
            let meta: i64 = tx.conn().query_row(
                "SELECT count(*) FROM meta WHERE key = 'witness'",
                [],
                |r| r.get(0),
            )?;
            let kv: i64 = tx
                .conn()
                .query_row("SELECT count(*) FROM openmls_kv", [], |r| r.get(0))?;
            Ok((meta, kv))
        })
        .unwrap();
    assert_eq!(counts, (0, 0));
}
