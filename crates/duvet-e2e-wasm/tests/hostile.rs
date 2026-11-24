//! Hostile nesting in WebAssembly, whose stack is 1 MiB: CBOR 10 000 levels deep through one reader
//! of each family the workspace reads CBOR with (the core's, the rules' and the validator's), each
//! refused with its bounded error, with no trap.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e_rules::DeviceList;
use duvet_e2e_validator::{Response, validate_bytes};
use duvet_e2e_wasm::{WasmCore, use_memory_vfs};
use serde_json::{Value, json};
use wasm_bindgen_test::wasm_bindgen_test;

/// Arrays, maps (under a key no format has) and tags, each nested 10 000 levels deep.
fn nestings() -> [(&'static str, Vec<u8>); 3] {
    let nested = |level: &[u8], last: u8| [level.repeat(10_000), vec![last]].concat();
    [
        ("arrays", nested(&[0x81], 0x80)),
        ("maps", nested(&[0xa1, 0x61, b'x'], 0xa0)),
        ("tags", nested(&[0xc6], 0x00)),
    ]
}

#[wasm_bindgen_test]
fn nesting_is_refused_without_a_trap() {
    // Node has no OPFS: SQLite's in-memory VFS.
    use_memory_vfs();
    let mut core = WasmCore::open(r#"{"path":"hostile.db"}"#, &[1; 32]).unwrap();
    for (shape, cbor) in nestings() {
        // The core's: a direct message's header, read before anything checks it.
        let command = json!({"cmd": "receive_direct", "message": STANDARD.encode(&cbor)});
        let reply: Value = serde_json::from_str(&core.handle(&command.to_string())).unwrap();
        assert_eq!(reply["error"]["code"], "decrypt_failed", "{shape}: {reply}");
        // The rules': a device list, a signed object.
        assert!(DeviceList::verify(&cbor, &[0; 32]).is_err(), "{shape}");
        // The validator's: its request.
        let response: Response = ciborium::from_reader(validate_bytes(&cbor).as_slice()).unwrap();
        let code = response.error.map(|failure| failure.code);
        assert_eq!(code.as_deref(), Some("bad_request"), "{shape}");
    }
    core.close();
}
