//! `WasmCore.open` keeps a database only in OPFS. Run under Node by `wasm-pack test --node`, which has
//! no OPFS: in an instance of its own (this file), where nothing opens SQLite's in-memory VFS as the
//! other tests do.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use duvet_e2e_wasm::{WasmCore, install_opfs};
use serde_json::Value;
use sqlite_wasm_rs::vfs::memvfs::MemVfsUtil;
use sqlite_wasm_rs::vfs::transfer::DbTransfer;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

/// The code of an error `open` threw: the reply's JSON, as a string.
fn code(error: JsValue) -> String {
    let text = error.as_string().expect("the error reply, as a string");
    let reply: Value = serde_json::from_str(&text).expect("a JSON reply");
    reply["error"]["code"].as_str().expect("a code").to_owned()
}

#[wasm_bindgen_test]
async fn open_refuses_without_opfs() {
    let config = r#"{"path":"no-opfs.db"}"#;
    // Before any install_opfs, open would make the database in memory, gone at the next reload.
    let refused = WasmCore::open(config, &[1; 32]).err();
    assert_eq!(refused.map(code).as_deref(), Some("storage"));

    // An install that failed (Node has no OPFS) installs nothing.
    assert!(install_opfs().await.is_err());
    let refused = WasmCore::open(config, &[1; 32]).err();
    assert_eq!(refused.map(code).as_deref(), Some("storage"));

    // Nothing was made in memory.
    // Safety: the test runs on the one thread SQLite's in-memory VFS lives on.
    let memory = unsafe { MemVfsUtil::get() }.expect("the in-memory VFS");
    assert!(memory.export_db("no-opfs.db").is_err());
}
