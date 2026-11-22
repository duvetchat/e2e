//! The core's WebAssembly build, for the web's worker.
//!
//! The worker calls [`install_opfs`] once, then opens the core with the key it unwrapped. A
//! failure is the core's error reply, `{"error": {...}}`, as a JSON string: `open` throws it and
//! `handle` returns it. Nothing locks the database here: the web picks one tab with a Web Lock.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use duvet_e2e::{Core, Error, OpenConfig};
use serde::Deserialize;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::sahpool::{self, OpfsSAHPoolCfg};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Makes OPFS, through SQLite's `opfs-sahpool` VFS, the place of every database opened after it.
/// Only a dedicated worker has OPFS's synchronous access handles.
#[wasm_bindgen]
pub async fn install_opfs() -> Result<(), JsValue> {
    sahpool::install::<WasmOsCallback>(&OpfsSAHPoolCfg::default(), true)
        .await
        .map(|_| ())
        .map_err(|error| reply(&Error::Storage(format!("OPFS: {error}"))))
}

/// What `open`'s `config_json` holds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    /// The database's name in the VFS.
    path: String,
}

/// The core over one open database.
#[wasm_bindgen]
pub struct WasmCore(Core);

#[wasm_bindgen]
impl WasmCore {
    /// Opens the database `config_json` names (`{"path"}`) with its raw 32-byte key, or creates it.
    pub fn open(config_json: &str, db_key: &[u8]) -> Result<WasmCore, JsValue> {
        let config: Config =
            serde_json::from_str(config_json).map_err(|error| reply(&Error::bad_command(error)))?;
        if db_key.len() != 32 {
            return Err(reply(&Error::BadCommand {
                message: "db_key must be 32 bytes",
                field: Some("db_key".into()),
            }));
        }
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(db_key);
        Core::open(OpenConfig::new(config.path, key))
            .map(WasmCore)
            .map_err(|error| reply(&error))
    }

    /// Runs one JSON command and returns its JSON reply.
    pub fn handle(&mut self, command: &str) -> String {
        self.0.handle(command)
    }

    /// Closes the database.
    pub fn close(self) {
        self.0.close();
    }
}

fn reply(error: &Error) -> JsValue {
    JsValue::from_str(&error.to_reply().to_string())
}
