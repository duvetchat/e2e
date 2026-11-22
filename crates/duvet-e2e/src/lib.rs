//! Duvet's end-to-end encryption core: MLS groups for DMs and groups, the local SQLCipher database, and the formats around them.
//!
//! The core has no network of its own. Clients hand it what the server sent and send what it returns,
//! through one entry point that takes and returns JSON: [`Core::handle`].

mod error;
mod identity;
mod protocol;
mod provider;
mod store;

use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use openmls_rust_crypto::RustCrypto;
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub use error::Error;
pub use identity::{OwnDevice, recovery};
pub use provider::Provider;
pub use store::{SqlStorage, SqlStorageError, Tx};

/// The version of the JSON protocol, which `status` reports.
pub const PROTOCOL: u32 = 1;

/// Where the database's key is kept, as `status` reports it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStorage {
    /// The client handed the key over: the web keeps it wrapped by WebCrypto, Android by the Keystore.
    #[default]
    Provided,
    /// The system's keyring (the desktop).
    Keyring,
    /// A file only its user reads, where the system has no keyring (Linux without Secret Service).
    File,
}

/// The time the core goes by: key package lifetimes, leaf refreshes, backup days.
pub trait Clock: Send {
    /// The Unix time, in milliseconds.
    fn now_ms(&self) -> i64;
}

/// The system's clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
        use std::time::{SystemTime, UNIX_EPOCH};
        #[cfg(all(target_family = "wasm", target_os = "unknown"))]
        use web_time::{SystemTime, UNIX_EPOCH};

        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                i64::try_from(since.as_millis()).unwrap_or(i64::MAX)
            })
    }
}

/// A clock tests set by hand. Its clones share one time, so a test keeps one and moves the core's.
///
/// OpenMLS checks lifetimes against the system's clock, not this one: a test that needs one of
/// those checks to fail gives the leaf or key package a lifetime of seconds instead.
#[derive(Clone, Debug)]
pub struct FakeClock(Arc<AtomicI64>);

impl FakeClock {
    /// A clock at `now_ms`.
    pub fn at(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    /// A clock at the system's time, so it starts where OpenMLS's own checks are.
    pub fn now() -> Self {
        Self::at(SystemClock.now_ms())
    }

    pub fn set(&self, now_ms: i64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }

    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// How to open the core.
pub struct OpenConfig {
    /// The database's file. On the web, its name in the VFS.
    pub path: PathBuf,
    /// The database's raw 256-bit key, used as it is (SQLCipher derives nothing from it), and
    /// wiped when the configuration drops.
    pub db_key: Zeroizing<[u8; 32]>,
    /// Where the key is kept, for `status`.
    pub key_storage: KeyStorage,
    pub clock: Box<dyn Clock>,
}

impl OpenConfig {
    /// A database whose key the client provides, on the system's clock.
    pub fn new(path: impl Into<PathBuf>, db_key: impl Into<Zeroizing<[u8; 32]>>) -> Self {
        Self {
            path: path.into(),
            db_key: db_key.into(),
            key_storage: KeyStorage::Provided,
            clock: Box::new(SystemClock),
        }
    }
}

/// The core over one open database, which no other instance opens meanwhile.
pub struct Core {
    db: store::Db,
    crypto: RustCrypto,
    clock: Box<dyn Clock>,
    key_storage: KeyStorage,
}

// The C ABI and the Flutter plugin keep each `Core` behind a mutex that any thread may take.
const _: () = {
    const fn send<T: Send>() {}
    send::<Core>();
};

impl Core {
    /// Opens the database, or creates it. Fails with `locked` when another instance has it open,
    /// and with `bad_key` when the key doesn't open it.
    pub fn open(config: OpenConfig) -> Result<Core, Error> {
        let db = store::Db::open(&config.path, &config.db_key)?;
        Ok(Core {
            db,
            crypto: RustCrypto::default(),
            clock: config.clock,
            key_storage: config.key_storage,
        })
    }

    /// Runs one JSON command, and answers `{"ok": {...}}` or `{"error": {"code", "message", ...}}`.
    ///
    /// Each command is one transaction: whatever fails, a panic included, leaves the database as it was.
    pub fn handle(&mut self, command: &str) -> String {
        let reply = match panic::catch_unwind(AssertUnwindSafe(|| self.run(command))) {
            Ok(Ok(value)) => json!({ "ok": value }),
            Ok(Err(error)) => error.to_reply(),
            Err(_) => Error::Internal("the core panicked".into()).to_reply(),
        };
        reply.to_string()
    }

    /// Closes the database and lets another instance open it.
    pub fn close(self) {}

    /// Runs `f` in one `BEGIN IMMEDIATE` transaction, committed only when it returns `Ok`.
    pub fn transaction<T>(
        &mut self,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.db
            .transaction(&self.crypto, self.clock.now_ms(), self.key_storage, f)
    }

    fn run(&mut self, command: &str) -> Result<Value, Error> {
        let command = protocol::parse(command)?;
        self.transaction(|tx| protocol::dispatch(tx, command))
    }
}
