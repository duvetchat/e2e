//! The core's C ABI, which the desktop's Bun loads.
//!
//! Strings go both ways as NUL-terminated UTF-8 JSON. Each string a function returns is the
//! caller's to hand back to [`duvet_e2e_free`]. No panic crosses the boundary: one becomes an
//! `internal` error reply.

mod keyring;

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char};
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e::{Core, Error, OpenConfig};
use serde::Deserialize;
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

/// A core shared by its handle: its own mutex lets other handles run meanwhile, and it's `None`
/// once closed.
type Shared = Arc<Mutex<Option<Core>>>;

static CORES: LazyLock<Mutex<HashMap<u64, Shared>>> = LazyLock::new(Default::default);
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

const VERSION: &CStr =
    match CStr::from_bytes_with_nul(concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes()) {
        Ok(version) => version,
        Err(_) => panic!("the version holds a NUL"),
    };

/// What `duvet_e2e_open`'s `config_json` holds: the database's path, and either its raw key or
/// the keyring entry that keeps it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    path: PathBuf,
    /// The raw 32-byte key, in base64.
    db_key: Option<String>,
    keyring: Option<KeyringEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyringEntry {
    service: String,
    account: String,
}

/// Opens the database, or creates it, and answers `{"ok":{"handle":N}}` or the error reply
/// (`locked`, `bad_key`, `bad_command`...).
///
/// `config_json` is `{"path", "db_key"}`, the raw 32-byte key in base64, or
/// `{"path", "keyring": {"service", "account"}}`, which takes the key from the system's keyring
/// and makes it on the database's first open.
///
/// # Safety
///
/// `config_json` is a NUL-terminated string that stays valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duvet_e2e_open(config_json: *const c_char) -> *mut c_char {
    answer(|| {
        // Safety: as the caller promised.
        let config = unsafe { read(config_json) }?;
        let mut config: Config = serde_json::from_str(config).map_err(Error::bad_command)?;
        let opened = open(&config);
        if let Some(db_key) = &mut config.db_key {
            db_key.zeroize();
        }
        let core = opened?;
        let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
        cores().insert(handle, Arc::new(Mutex::new(Some(core))));
        Ok(json!({ "ok": { "handle": handle } }).to_string())
    })
}

/// Runs one JSON command on an open core and answers its reply. An unknown or closed handle is
/// `not_found`. Each handle runs one command at a time; different handles run side by side.
///
/// # Safety
///
/// `command_json` is a NUL-terminated string that stays valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duvet_e2e_handle(handle: u64, command_json: *const c_char) -> *mut c_char {
    answer(|| {
        // Safety: as the caller promised.
        let command = unsafe { read(command_json) }?;
        let shared = cores().get(&handle).cloned().ok_or_else(unknown_handle)?;
        let mut core = shared.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(core.as_mut().ok_or_else(unknown_handle)?.handle(command))
    })
}

/// Closes a core and lets another instance open its database. It waits for a command the
/// handle is running; an unknown handle does nothing.
#[unsafe(no_mangle)]
pub extern "C" fn duvet_e2e_close(handle: u64) {
    // Nothing to answer: a panic while closing only leaves the core closed.
    panic::catch_unwind(|| {
        let shared = cores().remove(&handle);
        if let Some(shared) = shared {
            let core = shared.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(core) = core {
                core.close();
            }
        }
    })
    .ok();
}

/// Hands back a string the library returned. NULL does nothing.
///
/// # Safety
///
/// `text` is NULL or a string this library returned, not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn duvet_e2e_free(text: *mut c_char) {
    if !text.is_null() {
        // Safety: as the caller promised, it came from `CString::into_raw`.
        let text = unsafe { CString::from_raw(text) };
        // A reply may hold a secret (a recovery key, a key in an approval or a transfer): its bytes
        // are wiped before the block goes back.
        text.into_bytes_with_nul().zeroize();
    }
}

/// The core's version, as `status` reports it. The string is static: never free it.
#[unsafe(no_mangle)]
pub extern "C" fn duvet_e2e_version() -> *const c_char {
    VERSION.as_ptr()
}

fn cores() -> MutexGuard<'static, HashMap<u64, Shared>> {
    CORES.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unknown_handle() -> Error {
    Error::NotFound {
        what: "handle".into(),
    }
}

fn bad_command(message: &'static str, field: &str) -> Error {
    Error::BadCommand {
        message,
        field: Some(field.into()),
    }
}

/// The caller's string, as UTF-8.
///
/// # Safety
///
/// `text` is NULL or a NUL-terminated string that outlives the returned borrow.
unsafe fn read<'a>(text: *const c_char) -> Result<&'a str, Error> {
    if text.is_null() {
        return Err(Error::BadCommand {
            message: "the string is NULL",
            field: None,
        });
    }
    // Safety: as the caller promised.
    unsafe { CStr::from_ptr(text) }
        .to_str()
        .map_err(|_| Error::BadCommand {
            message: "the string isn't UTF-8",
            field: None,
        })
}

fn open(config: &Config) -> Result<Core, Error> {
    match (&config.db_key, &config.keyring) {
        (Some(db_key), None) => {
            Core::open(OpenConfig::new(config.path.clone(), decode_key(db_key)?))
        }
        (None, Some(entry)) => keyring::open(&config.path, &entry.service, &entry.account),
        _ => Err(bad_command("give either db_key or keyring", "db_key")),
    }
}

fn decode_key(encoded: &str) -> Result<keyring::Key, Error> {
    let refused = || bad_command("db_key must be 32 bytes, in base64", "db_key");
    let bytes = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| refused())?);
    if bytes.len() != 32 {
        return Err(refused());
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Runs `f` and returns its JSON as a string the caller frees, an error as its reply, and a panic
/// as `internal`.
fn answer(f: impl FnOnce() -> Result<String, Error>) -> *mut c_char {
    let text = match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(text)) => text,
        Ok(Err(error)) => error.to_reply().to_string(),
        Err(_) => Error::Internal("the binding panicked".into())
            .to_reply()
            .to_string(),
    };
    // serde_json escapes every control character, so a reply never holds a NUL.
    CString::new(text).map_or(std::ptr::null_mut(), CString::into_raw)
}
