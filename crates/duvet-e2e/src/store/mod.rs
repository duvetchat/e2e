//! The local database: SQLCipher, a lock while it's open, and one transaction per command.

mod migrations;
mod openmls_kv;

use std::path::Path;

use openmls_rust_crypto::RustCrypto;
use rusqlite::{Connection, ErrorCode, TransactionBehavior};

pub use openmls_kv::{SqlStorage, SqlStorageError};

use crate::{Error, KeyStorage, Provider};

/// The open database. The connection is dropped before the lock, so the database is closed
/// before another instance can take it.
pub(crate) struct Db {
    conn: Connection,
    #[cfg(not(target_family = "wasm"))]
    _lock: std::fs::File,
}

impl Db {
    pub(crate) fn open(path: &Path, key: &[u8; 32]) -> Result<Db, Error> {
        #[cfg(not(target_family = "wasm"))]
        let lock = lock(path)?;
        let mut conn = Connection::open(path)?;
        unlock(&conn, key)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        migrations::run(&mut conn)?;
        Ok(Db {
            conn,
            #[cfg(not(target_family = "wasm"))]
            _lock: lock,
        })
    }

    pub(crate) fn transaction<T>(
        &mut self,
        crypto: &RustCrypto,
        now: i64,
        key_storage: KeyStorage,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&mut Tx {
            conn: &txn,
            provider: Provider::new(crypto, SqlStorage::new(&txn)),
            now,
            key_storage,
        })?;
        txn.commit()?;
        Ok(value)
    }
}

/// One command's transaction: its connection, OpenMLS's provider over it, and the time the command began.
pub struct Tx<'a> {
    conn: &'a Connection,
    provider: Provider<'a>,
    now: i64,
    key_storage: KeyStorage,
}

impl<'a> Tx<'a> {
    /// OpenMLS's provider, which stores into this transaction.
    pub fn provider(&self) -> &Provider<'a> {
        &self.provider
    }

    pub fn conn(&self) -> &Connection {
        self.conn
    }

    /// The Unix time the command began, in milliseconds, by the core's clock.
    pub fn now(&self) -> i64 {
        self.now
    }

    pub(crate) fn key_storage(&self) -> KeyStorage {
        self.key_storage
    }
}

/// Takes `<path>.lock` for as long as the database is open. Another instance, in another
/// process or in this one (another Flutter engine), gets `locked`.
#[cfg(not(target_family = "wasm"))]
fn lock(path: &Path) -> Result<std::fs::File, Error> {
    use std::fs::{OpenOptions, TryLockError};

    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|error| Error::Storage(format!("the lock file: {error}")))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(Error::Locked),
        Err(TryLockError::Error(error)) => Err(Error::Storage(format!("the lock file: {error}"))),
    }
}

/// Hands SQLCipher the raw key and checks it: SQLCipher reads nothing until the first query.
fn unlock(conn: &Connection, key: &[u8; 32]) -> Result<(), Error> {
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    conn.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))?;
    match conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    }) {
        Ok(_) => Ok(()),
        Err(rusqlite::Error::SqliteFailure(error, _)) if error.code == ErrorCode::NotADatabase => {
            Err(Error::BadKey)
        }
        Err(error) => Err(error.into()),
    }
}
