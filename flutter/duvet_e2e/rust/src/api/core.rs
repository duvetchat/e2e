//! What the plugin's Dart calls. Each function runs on one of flutter_rust_bridge's worker
//! threads, so a command never blocks the isolate that calls it.

use std::path::Path;
use std::sync::{Mutex, PoisonError};

use duvet_e2e_core::{lock_database, Core, Error, OpenConfig};
use flutter_rust_bridge::frb;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// The core over one open database. Its mutex runs one command at a time; it's empty once closed.
#[frb(opaque)]
pub struct OpenCore(Mutex<Option<Core>>);

/// A failed `open` or `destroy`: the core's error reply, `{"error": {...}}`.
pub struct OpenError {
    pub reply: String,
}

/// What `open`'s `config_json` holds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    path: String,
}

impl OpenCore {
    /// Opens the database `config_json` names (`{"path"}`) with its raw 32-byte key, or creates
    /// it. Another open of the same database, in this process or another, is `locked`.
    pub fn open(config_json: String, mut db_key: Vec<u8>) -> Result<OpenCore, OpenError> {
        let opened = open(&config_json, &db_key);
        db_key.zeroize();
        opened
            .map(|core| OpenCore(Mutex::new(Some(core))))
            .map_err(|error| OpenError {
                reply: error.to_reply().to_string(),
            })
    }

    /// Runs one JSON command and returns its JSON reply: `not_found` once closed.
    pub fn handle(&self, command: String) -> String {
        let mut core = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match core.as_mut() {
            Some(core) => core.handle(&command),
            None => Error::NotFound {
                what: "handle".into(),
            }
            .to_reply()
            .to_string(),
        }
    }

    /// Closes the database and lets another instance open it.
    pub fn close(&self) {
        let core = self.0.lock().unwrap_or_else(PoisonError::into_inner).take();
        if let Some(core) = core {
            core.close();
        }
    }

    /// Deletes the database `config_json` names (`{"path"}`) and SQLite's files beside it, holding
    /// the lock an open core holds: `locked` while one, in this process or another, has it open,
    /// and nothing is deleted then. The deletion is on the disk once it returns. The lock file
    /// stays, as `duvet_e2e_destroy` leaves it: an open waiting for it would otherwise lock a deleted
    /// file while the next one locked a new file. No key is deleted: the app keeps the database's
    /// key, and deletes it after.
    pub fn destroy(config_json: String) -> Result<(), OpenError> {
        destroy(&config_json).map_err(|error| OpenError {
            reply: error.to_reply().to_string(),
        })
    }
}

fn open(config_json: &str, db_key: &[u8]) -> Result<Core, Error> {
    let config: Config = serde_json::from_str(config_json).map_err(Error::bad_command)?;
    if db_key.len() != 32 {
        return Err(Error::BadCommand {
            message: "db_key must be 32 bytes",
            field: Some("db_key".into()),
        });
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(db_key);
    Core::open(OpenConfig::new(config.path, key))
}

fn destroy(config_json: &str) -> Result<(), Error> {
    let config: Config = serde_json::from_str(config_json).map_err(Error::bad_command)?;
    let path = Path::new(&config.path);
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Without its folder there's no database, and no lock to take.
    if !std::fs::exists(folder).map_err(|error| folder_failed(&error))? {
        return Ok(());
    }
    let _open = lock_database(path)?;
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut file = path.as_os_str().to_owned();
        file.push(suffix);
        match std::fs::remove_file(file) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(Error::Storage(format!(
                    "the database's files: {}",
                    error.kind()
                )));
            }
            _ => {}
        }
    }
    // On the disk before the app deletes the key, so a power loss can't bring the database back
    // without it. Windows has no folder sync.
    #[cfg(unix)]
    std::fs::File::open(folder)
        .and_then(|folder| folder.sync_all())
        .map_err(|error| folder_failed(&error))?;
    Ok(())
}

fn folder_failed(error: &std::io::Error) -> Error {
    Error::Storage(format!("the database's folder: {}", error.kind()))
}
