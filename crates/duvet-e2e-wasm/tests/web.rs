//! The core's WebAssembly build, run under Node by `wasm-pack test --node` on SQLite's in-memory VFS
//! (OPFS exists only in a browser's dedicated worker), which `memory-vfs` lets `WasmCore` open.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use duvet_e2e::{Core, OpenConfig};
use duvet_e2e_wasm::{WasmCore, use_memory_vfs};
use serde_json::{Value, json};
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

/// One token, so it shows in the file whether SQLite stores it as a value or FTS5 as a term.
const WITNESS: &str = "duvetwitnessword";

fn reply(text: &str) -> Value {
    serde_json::from_str(text).expect("a JSON reply")
}

fn ok(core: &mut WasmCore, command: &str) -> Value {
    let reply = reply(&core.handle(command));
    reply
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{command} failed: {reply}"))
}

/// The code of an error `open` threw: the reply's JSON, as a string.
fn code(error: JsValue) -> String {
    let text = error.as_string().expect("the error reply, as a string");
    reply(&text)["error"]["code"]
        .as_str()
        .expect("a code")
        .to_owned()
}

/// The bytes the in-memory VFS holds for a database.
fn file(name: &str) -> Vec<u8> {
    // Safety: the tests run on the one thread that installed the VFS.
    let vfs = unsafe { MemVfsUtil::get() }.expect("the in-memory VFS");
    vfs.export_db(name).expect("the database's file")
}

fn holds(bytes: &[u8], text: &str) -> bool {
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

#[wasm_bindgen_test]
fn status_through_wasm() {
    use_memory_vfs();
    let mut core = WasmCore::open(r#"{"path":"status.db"}"#, &[1; 32]).unwrap();

    let status = ok(&mut core, r#"{"cmd":"status"}"#);
    assert_eq!(status["protocol"], 1);
    assert_eq!(status["has_identity"], false);
    assert_eq!(status["key_storage"], "provided");

    // A broken command is an error reply: a panic would trap the whole module here.
    assert_eq!(reply(&core.handle("{"))["error"]["code"], "bad_command");
    assert_eq!(ok(&mut core, r#"{"cmd":"status"}"#)["protocol"], 1);
    core.close();
}

#[wasm_bindgen_test]
fn open_checks_its_config() {
    for config in ["{", "[]", r#"{"path":"x.db","db_key":"AA=="}"#, "{}"] {
        let error = WasmCore::open(config, &[1; 32]).err().expect(config);
        assert_eq!(code(error), "bad_command", "{config}");
    }
    let short = WasmCore::open(r#"{"path":"x.db"}"#, &[1; 31])
        .err()
        .unwrap();
    let text = short.as_string().unwrap();
    assert_eq!(reply(&text)["error"]["field"], "db_key", "{text}");
}

#[wasm_bindgen_test]
fn sqlcipher_encrypts_in_wasm() {
    // The check can see plaintext: a database opened without a key shows the witness.
    let plain = rusqlite::Connection::open("plain.db").unwrap();
    plain
        .execute_batch(&format!(
            "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('{WITNESS}');"
        ))
        .unwrap();
    drop(plain);
    assert!(holds(&file("plain.db"), WITNESS));

    // The core's database: the witness as a value and as a term of the FTS5 index the schema made.
    let mut core = Core::open(OpenConfig::new("cipher.db", [1; 32])).unwrap();
    let found = core
        .transaction(|tx| {
            tx.conn().execute(
                "INSERT INTO meta (key, value) VALUES ('witness', ?1)",
                [WITNESS],
            )?;
            tx.conn().execute(
                "INSERT INTO messages_fts (rowid, text) VALUES (1, ?1)",
                [WITNESS],
            )?;
            Ok(tx.conn().query_row(
                "SELECT count(*) FROM messages_fts WHERE messages_fts MATCH ?1",
                [WITNESS],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .unwrap();
    assert_eq!(found, 1, "FTS5 finds the witness");
    core.close();

    let bytes = file("cipher.db");
    assert!(bytes.len() >= 4096, "{} bytes", bytes.len());
    assert!(!bytes.starts_with(b"SQLite format 3\0"));
    assert!(!holds(&bytes, WITNESS), "the witness is in the file");

    use_memory_vfs();
    let wrong = WasmCore::open(r#"{"path":"cipher.db"}"#, &[2; 32]).err();
    assert_eq!(wrong.map(code).as_deref(), Some("bad_key"));

    let mut core = WasmCore::open(r#"{"path":"cipher.db"}"#, &[1; 32]).unwrap();
    assert_eq!(ok(&mut core, r#"{"cmd":"status"}"#)["protocol"], 1);
    core.close();
}

/// A group command through the same JSON: a device founds a DM alone, with no key package of the
/// other member's, types a message there and forgets it, which leaves the message stale
/// (`groups.rs`' `a_lone_device_forgets_the_group_it_founded`).
#[wasm_bindgen_test]
fn forget_group_through_wasm() {
    use base64::Engine as _;

    use_memory_vfs();
    let mut core = WasmCore::open(r#"{"path":"forget.db"}"#, &[1; 32]).unwrap();
    let user = "01930000-0000-7000-8000-000000000551";
    let other = "01930000-0000-7000-8000-000000000552";
    let conversation = "01930000-0000-7000-8000-000000000553";
    let device = "01930000-0000-7000-8000-000000000554";
    let run = |core: &mut WasmCore, command: Value| reply(&core.handle(&command.to_string()));
    let created = json!({"cmd": "create_device", "user_id": user, "device_id": device});
    assert!(run(&mut core, created)["ok"].is_object());
    assert!(run(&mut core, json!({"cmd": "create_identity"}))["ok"].is_object());
    let external_sender = base64::engine::general_purpose::STANDARD.encode([9; 32]);
    let create = json!({
        "cmd": "create_group",
        "conversation_id": conversation,
        "kind": "dm",
        "members": [user, other],
        "external_sender": external_sender,
    });
    assert_eq!(run(&mut core, create.clone())["ok"]["generation"], 0);
    let taken = json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": 1});
    assert_eq!(run(&mut core, taken)["ok"]["epoch"], 1);
    let typed = json!({"cmd": "encrypt", "conversation_id": conversation, "nonce": "typed", "envelope": {"text": "hello"}});
    assert_eq!(run(&mut core, typed.clone())["ok"]["epoch"], 1);

    let forget = json!({"cmd": "forget_group", "conversation_id": conversation});
    assert_eq!(
        run(&mut core, forget.clone()),
        json!({"ok": {"expected": {"members": [user, other]}}})
    );
    let stale = run(&mut core, typed);
    assert_eq!(stale["error"]["rule"], "stale_message", "{stale}");
    let gone = run(
        &mut core,
        json!({"cmd": "group", "conversation_id": conversation}),
    );
    assert_eq!(gone["error"]["what"], "group", "{gone}");
    assert_eq!(run(&mut core, forget)["error"]["code"], "not_found");
    // Founded again at generation 0, the group ID the forgotten one had.
    let mut again = create;
    again["expected"] = json!({"members": [user, other]});
    assert_eq!(run(&mut core, again)["ok"]["generation"], 0);
    core.close();
}
