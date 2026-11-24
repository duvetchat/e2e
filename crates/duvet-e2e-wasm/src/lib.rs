//! The core's WebAssembly build, for the web's worker.
//!
//! The worker calls [`install_opfs`] once, then opens the core with the key it unwrapped. A
//! failure is the core's error reply, `{"error": {...}}`, as a JSON string: `open` throws it and
//! `handle` returns it. Nothing locks the database here: the web picks one tab with a Web Lock.
//!
//! On wasm32 a panic traps: nothing unwinds, and the instance, with the OPFS access handles it
//! holds, is unusable from then on. The worker ends, and a new one installs OPFS and opens again.

#![cfg(all(target_family = "wasm", target_os = "unknown"))]

use std::sync::atomic::{AtomicBool, Ordering};

use duvet_e2e::{Core, Error, OpenConfig};
use serde::Deserialize;
use sqlite_wasm_rs::WasmOsCallback;
use sqlite_wasm_vfs::sahpool::{self, OpfsSAHPoolCfg};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

/// Whether a VFS that keeps databases is SQLite's default in this instance: OPFS, once
/// [`install_opfs`] succeeded. Until then the default is SQLite's in-memory VFS, whose databases
/// are gone at the next reload.
static VFS_READY: AtomicBool = AtomicBool::new(false);

/// Makes OPFS, through SQLite's `opfs-sahpool` VFS, the place of every database opened after it.
/// Only a dedicated worker has OPFS's synchronous access handles.
#[wasm_bindgen]
pub async fn install_opfs() -> Result<(), JsValue> {
    sahpool::install::<WasmOsCallback>(&OpfsSAHPoolCfg::default(), true)
        .await
        .map(|_| VFS_READY.store(true, Ordering::Relaxed))
        .map_err(|error| reply(&Error::Storage(format!("OPFS: {error}"))))
}

/// For the tests under Node, which has no OPFS: `open` takes SQLite's in-memory VFS from then on.
#[cfg(feature = "memory-vfs")]
pub fn use_memory_vfs() {
    VFS_READY.store(true, Ordering::Relaxed);
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
    /// `storage` until [`install_opfs`] succeeded in this instance: a database kept in memory
    /// would be gone at the next reload, with its device already on the user's list.
    pub fn open(config_json: &str, db_key: &[u8]) -> Result<WasmCore, JsValue> {
        let config: Config =
            serde_json::from_str(config_json).map_err(|error| reply(&Error::bad_command(error)))?;
        if db_key.len() != 32 {
            return Err(reply(&Error::BadCommand {
                message: "db_key must be 32 bytes",
                field: Some("db_key".into()),
            }));
        }
        if !VFS_READY.load(Ordering::Relaxed) {
            return Err(reply(&Error::Storage(
                "OPFS isn't installed: call install_opfs first".into(),
            )));
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
