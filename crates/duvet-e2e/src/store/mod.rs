//! The local database: SQLCipher, a lock while it's open, and one transaction per command.

mod migrations;
mod openmls_kv;

use std::cell::RefCell;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use openmls_rust_crypto::RustCrypto;
use rusqlite::{Connection, ErrorCode, TransactionBehavior};
use zeroize::{Zeroize, Zeroizing};

pub use openmls_kv::{SqlStorage, SqlStorageError};

use crate::{Error, KeyStorage, Provider};

/// The open database. The connection is dropped before the lock, so the database is closed
/// before another instance can take it.
pub(crate) struct Db {
    conn: Connection,
    #[cfg(not(target_family = "wasm"))]
    _lock: std::fs::File,
    /// Tests only: the next transaction fails right before its commit.
    #[cfg(feature = "test-hooks")]
    fail_next_commit: bool,
}

impl Db {
    pub(crate) fn open(path: &Path, key: &[u8; 32]) -> Result<Db, Error> {
        #[cfg(not(target_family = "wasm"))]
        let lock = lock(path)?;
        initialize_sqlite()?;
        let mut conn = Connection::open(path)?;
        unlock(&conn, key)?;
        // What's deleted (a message's text, a key OpenMLS used) is overwritten, not left in the
        // pages' free space.
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;")?;
        migrations::run(&mut conn)?;
        Ok(Db {
            conn,
            #[cfg(not(target_family = "wasm"))]
            _lock: lock,
            #[cfg(feature = "test-hooks")]
            fail_next_commit: false,
        })
    }

    /// Tests only: the next transaction does all its work, then fails just before its commit.
    #[cfg(feature = "test-hooks")]
    pub(crate) fn fail_next_commit(&mut self) {
        self.fail_next_commit = true;
    }

    /// Runs `f` in one transaction, committed only when it returns `Ok`. What `f` asked to keep
    /// ([`Tx::keep`]) is written either way: with the rest, or after the rollback, on its own.
    pub(crate) fn transaction<T>(
        &mut self,
        crypto: &RustCrypto,
        now: i64,
        key_storage: KeyStorage,
        f: impl FnOnce(&mut Tx<'_>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        #[cfg(feature = "test-hooks")]
        let fail = std::mem::take(&mut self.fail_next_commit);
        let txn = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut tx = Tx {
            conn: &txn,
            provider: Provider::new(crypto, SqlStorage::new(&txn)),
            now,
            key_storage,
            kept: RefCell::new(Vec::new()),
        };
        let result = f(&mut tx);
        #[cfg(feature = "test-hooks")]
        let result = match result {
            Ok(_) if fail => Err(Error::Internal("the test hook failed this commit".into())),
            result => result,
        };
        let kept = tx.kept.take();
        drop(tx);
        match result {
            Ok(value) => {
                for write in kept {
                    write(&txn)?;
                }
                txn.commit()?;
                Ok(value)
            }
            Err(error) => {
                drop(txn);
                if !kept.is_empty() {
                    let txn = self
                        .conn
                        .transaction_with_behavior(TransactionBehavior::Immediate)?;
                    for write in kept {
                        write(&txn)?;
                    }
                    txn.commit()?;
                }
                Err(error)
            }
        }
    }
}

/// A write a command keeps whether it succeeds or fails.
type KeptWrite = Box<dyn FnOnce(&Connection) -> rusqlite::Result<usize>>;

/// One command's transaction: its connection, OpenMLS's provider over it, and the time the command began.
pub struct Tx<'a> {
    conn: &'a Connection,
    provider: Provider<'a>,
    now: i64,
    key_storage: KeyStorage,
    kept: RefCell<Vec<KeptWrite>>,
}

impl<'a> Tx<'a> {
    /// Writes `write` whether the command succeeds or fails: with the rest of its transaction, or
    /// in one of its own after the rollback. For what a failure must leave behind, such as having
    /// asked the client for something once.
    pub(crate) fn keep(
        &self,
        write: impl FnOnce(&Connection) -> rusqlite::Result<usize> + 'static,
    ) {
        self.kept.borrow_mut().push(Box::new(write));
    }

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
pub(crate) fn lock(path: &Path) -> Result<std::fs::File, Error> {
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

/// Initializes SQLite once, before any open. SQLite marks itself initialized before it runs
/// SQLCipher's initialization (`SQLITE_EXTRA_INIT`), outside its own mutex, so an open on another
/// thread in between found SQLCipher not ready and its key couldn't be set. Every open waits here
/// instead, until one initialization has run whole; one that failed is tried again by the next.
fn initialize_sqlite() -> Result<(), Error> {
    static INITIALIZED: Mutex<bool> = Mutex::new(false);
    let mut initialized = INITIALIZED.lock().unwrap_or_else(PoisonError::into_inner);
    if !*initialized {
        // SAFETY: `sqlite3_initialize` takes no arguments and may be called from any thread.
        let code = unsafe { rusqlite::ffi::sqlite3_initialize() };
        if code != rusqlite::ffi::SQLITE_OK {
            return Err(Error::Storage(format!(
                "SQLite couldn't be initialized ({code})"
            )));
        }
        *initialized = true;
    }
    Ok(())
}

/// Hands SQLCipher the raw key and checks it: SQLCipher reads nothing until the first query.
fn unlock(conn: &Connection, key: &[u8; 32]) -> Result<(), Error> {
    // SQLCipher writes its own errors to stderr, a wrong key's included: the core logs nothing.
    conn.execute_batch("PRAGMA cipher_log_level = NONE;")?;
    set_key(conn, &key_pragma(key))?;
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

/// `PRAGMA key = "x'<hex>'";`, the key's hex written straight into a buffer of the statement's
/// exact size, so no other copy is made, and wiped as it drops.
fn key_pragma(key: &[u8; 32]) -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    const START: &str = "PRAGMA key = \"x'";
    const END: &str = "'\";";
    let mut pragma = Zeroizing::new(String::with_capacity(
        START.len() + 2 * key.len() + END.len(),
    ));
    pragma.push_str(START);
    for byte in key {
        pragma.push(char::from(DIGITS[usize::from(byte >> 4)]));
        pragma.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    pragma.push_str(END);
    pragma
}

/// Runs the statement that hands SQLCipher its key. Its error can quote the statement, so it
/// becomes a fixed message, and the copies it holds are wiped.
fn set_key(conn: &Connection, pragma: &str) -> Result<(), Error> {
    conn.execute_batch(pragma).map_err(|mut error| {
        match &mut error {
            rusqlite::Error::SqlInputError { msg, sql, .. } => {
                msg.zeroize();
                sql.zeroize();
            }
            rusqlite::Error::SqliteFailure(_, Some(msg)) => msg.zeroize(),
            _ => {}
        }
        Error::Storage("the database's key couldn't be set".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_statement_is_sqlciphers_raw_key() {
        let key: [u8; 32] = std::array::from_fn(|byte| (byte * 8) as u8);
        let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(*key_pragma(&key), format!("PRAGMA key = \"x'{hex}'\";"));
    }

    #[test]
    fn key_statement_is_built_at_its_final_length() {
        // A buffer that grew left the key's first digits in the block it moved out of, which
        // `Zeroizing` never wipes: only one built at its final length holds the only copy.
        let pragma = key_pragma(&[0xa5; 32]);
        assert_eq!(pragma.capacity(), pragma.len());
    }

    #[test]
    fn a_failed_key_statement_keeps_the_key_out() {
        let conn = Connection::open_in_memory().unwrap();
        // A statement SQLite can't parse: its error quotes the statement, which holds the key.
        let error = set_key(&conn, "PRAGMA key = \"x'5ec2e7'\" and more;").unwrap_err();
        let reply = error.to_reply().to_string();
        assert!(!reply.contains("5ec2e7"), "{reply}");
        assert_eq!(error.code(), "storage");
    }
}
