//! The desktop's database key: kept in the system's keyring (Windows' Credential Manager, macOS's
//! Keychain, the Secret Service), made on the database's first open, deleted with the database.
//! Where Linux has no Secret Service, it goes to `<path>.key`, which only its user reads, and
//! `status` says `file`.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use duvet_e2e::{Core, Error, KeyStorage, OpenConfig};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub(crate) type Key = Zeroizing<[u8; 32]>;

/// What keeps a database's key: the system keyring's entry, or keyring-core's mock in tests.
pub(crate) trait KeyStore {
    fn get(&self) -> keyring_core::Result<Vec<u8>>;
    fn set(&self, key: &[u8]) -> keyring_core::Result<()>;
    fn delete(&self) -> keyring_core::Result<()>;
}

impl KeyStore for keyring_core::Entry {
    fn get(&self) -> keyring_core::Result<Vec<u8>> {
        self.get_secret()
    }

    fn set(&self, key: &[u8]) -> keyring_core::Result<()> {
        self.set_secret(key)
    }

    fn delete(&self) -> keyring_core::Result<()> {
        self.delete_credential()
    }
}

/// Why there's no keyring entry to keep the key in.
#[derive(Debug)]
pub(crate) enum NoKeyring {
    /// No Secret Service at all: no session bus, or nothing on it providing the service. Only
    /// then does a new database's key go to `<path>.key`.
    #[cfg_attr(not(secret_service), allow(dead_code))]
    Absent,
    /// The keyring couldn't be reached for another reason.
    Failed(keyring_core::Error),
}

/// Opens the database at `path` with the key the system's keyring keeps for it, made on its
/// first open.
pub(crate) fn open(path: &Path, service: &str, account: &str) -> Result<Core, Error> {
    open_with(path, system_entry(service, account))
}

/// Deletes the database at `path` with the files beside it and its key: `<path>.key`, and the
/// system keyring's entry when `keyring` names one (service, account).
pub(crate) fn destroy(path: &Path, keyring: Option<(&str, &str)>) -> Result<(), Error> {
    destroy_with(
        path,
        keyring.map(|(service, account)| system_entry(service, account)),
    )
}

/// The system keyring's entry for the key, or why there is none.
fn system_entry(service: &str, account: &str) -> Result<keyring_core::Entry, NoKeyring> {
    keyring::Entry::new(service, account)
        .map(|entry| entry.inner)
        .map_err(|error| {
            if absent(keyring::Entry::store_status()) {
                NoKeyring::Absent
            } else {
                NoKeyring::Failed(error)
            }
        })
}

/// Whether the keyring couldn't be made because no Secret Service is there at all: no session bus,
/// or nothing on it providing the service. One that's locked or failing is there.
#[cfg(secret_service)]
fn absent(store: &keyring_core::Result<()>) -> bool {
    let Err(keyring_core::Error::PlatformFailure(cause)) = store else {
        return false;
    };
    let mut error: Option<&(dyn std::error::Error + 'static)> = Some(cause.as_ref());
    while let Some(current) = error {
        if no_bus_or_service(current) {
            return true;
        }
        error = current.source();
    }
    false
}

/// One link of the store's error: secret-service's own "no provider or session bus", the bus's
/// socket missing or refusing, or the bus answering that no one provides the service.
#[cfg(secret_service)]
fn no_bus_or_service(error: &(dyn std::error::Error + 'static)) -> bool {
    use std::io::ErrorKind::{ConnectionRefused, NotFound};

    const SERVICE_UNKNOWN: &str = "org.freedesktop.DBus.Error.ServiceUnknown";
    if let Some(error) = error.downcast_ref::<secret_service::Error>() {
        return matches!(error, secret_service::Error::Unavailable);
    }
    if let Some(error) = error.downcast_ref::<zbus::Error>() {
        return match error {
            zbus::Error::MethodError(name, _, _) => name.as_str() == SERVICE_UNKNOWN,
            zbus::Error::FDO(error) => matches!(**error, zbus::fdo::Error::ServiceUnknown(_)),
            _ => false,
        };
    }
    // zbus keeps its I/O errors in an `Arc`.
    let io = error
        .downcast_ref::<std::sync::Arc<std::io::Error>>()
        .map(|error| &**error)
        .or_else(|| error.downcast_ref::<std::io::Error>());
    io.is_some_and(|error| matches!(error.kind(), NotFound | ConnectionRefused))
}

#[cfg(not(secret_service))]
fn absent(_: &keyring_core::Result<()>) -> bool {
    false
}

/// A keyring that's there but failed, which never sends the key to a file. Its text can name the
/// entry, so the message is fixed.
fn keyring_failed(error: &keyring_core::Error) -> Error {
    Error::Storage(
        match error {
            keyring_core::Error::NoStorageAccess(_) => {
                "the system keyring is locked or refused access: unlock it and try again"
            }
            _ => "the system keyring failed",
        }
        .into(),
    )
}

/// Opens the database at `path` with the key `entry` keeps.
///
/// From looking for the database to opening it, everything runs under `<path>.key.lock`, which
/// another open waits for: two first opens can't each store a key of their own, and the one that
/// comes second finds the database and its key, then `locked` while the first keeps it open.
fn open_with(path: &Path, entry: Result<impl KeyStore, NoKeyring>) -> Result<Core, Error> {
    let _choosing = lock_key(path)?;
    let (key, key_storage) = database_key(path, entry)?;
    let mut config = OpenConfig::new(path, key);
    config.key_storage = key_storage;
    Core::open(config)
}

/// Takes `<path>.key.lock`, waiting for any other open of the database that holds it. It isn't
/// the core's `<path>.lock`, which the core only tries on a handle of its own.
fn lock_key(path: &Path) -> Result<File, Error> {
    let failed =
        |error: std::io::Error| Error::Storage(format!("the key's lock: {}", error.kind()));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(beside(path, ".key.lock"))
        .map_err(failed)?;
    file.lock().map_err(failed)?;
    Ok(file)
}

/// Deletes the database at `path` and what's beside it: SQLite's journals, `<path>.key` and the
/// file it's written to first, then its key in `entry`, then `<path>.lock`.
///
/// It takes `<path>.key.lock`, as an open does, then the core's `<path>.lock`: `locked` while a
/// core has the database open, and nothing is deleted then. `<path>.key.lock` stays, empty: an open
/// may be waiting for it, and were it deleted, that open would go on holding the deleted file while
/// the next open locked a new one, and the two would each choose a key.
fn destroy_with(path: &Path, entry: Option<Result<impl KeyStore, NoKeyring>>) -> Result<(), Error> {
    let entry = match entry {
        Some(Ok(entry)) => Some(entry),
        // No Secret Service at all: no entry holds a key.
        Some(Err(NoKeyring::Absent)) | None => None,
        Some(Err(NoKeyring::Failed(error))) => return Err(keyring_failed(&error)),
    };
    let _choosing = lock_key(path)?;
    let _open = duvet_e2e::lock_database(path)?;
    // The database first: what a destroy cut short leaves is a key, which a new database takes.
    for suffix in ["", "-journal", "-wal", "-shm", ".key", ".key.tmp"] {
        remove(&beside(path, suffix), "the database's files")?;
    }
    if let Some(entry) = entry {
        match entry.delete() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => {}
            Err(error) => return Err(keyring_failed(&error)),
        }
    }
    remove(&beside(path, ".lock"), "the database's lock")
}

/// The key of the database at `path`, and where it's kept.
///
/// A key is made only for a database that doesn't exist yet: for one that does, a missing key
/// can't open it, and a new one would only hide the key that might come back. The plaintext
/// `<path>.key` only where there's no Secret Service at all. A `<path>.key` of another length than
/// a key's is replaced while there's no database, and refused once there is one.
fn database_key(
    path: &Path,
    entry: Result<impl KeyStore, NoKeyring>,
) -> Result<(Key, KeyStorage), Error> {
    // A database that can't be looked for isn't new: that's where a new key would hide the right one.
    let fresh = !std::fs::exists(path)
        .map_err(|error| Error::Storage(format!("the database: {}", error.kind())))?;
    #[cfg(secret_service)]
    match file::read(path)? {
        Some(bytes) if bytes.len() == 32 => {
            return key_from(&bytes).map(|key| (key, KeyStorage::File));
        }
        // Not a key, and no database it could be for: a write cut short left it, before key files
        // were renamed into place whole. It goes, and the database gets a key as if it weren't there.
        Some(_) if fresh => file::remove(path)?,
        Some(_) => {
            return Err(Error::Storage(
                "the database's key file isn't 32 bytes".into(),
            ));
        }
        None => {}
    }
    match entry {
        Ok(entry) => key_in(&entry, fresh).map(|key| (key, KeyStorage::Keyring)),
        #[cfg(secret_service)]
        Err(NoKeyring::Absent) if fresh => file::create(path).map(|key| (key, KeyStorage::File)),
        Err(NoKeyring::Absent) => Err(Error::Storage("the system keyring isn't available".into())),
        Err(NoKeyring::Failed(error)) => Err(keyring_failed(&error)),
    }
}

/// The key `entry` holds, or a new random one it stores when the database is `fresh`.
fn key_in(entry: &impl KeyStore, fresh: bool) -> Result<Key, Error> {
    match entry.get() {
        Ok(secret) => key_from(&Zeroizing::new(secret)),
        Err(keyring_core::Error::NoEntry) if fresh => {
            let key = random_key()?;
            entry.set(&*key).map_err(|error| keyring_failed(&error))?;
            Ok(key)
        }
        Err(keyring_core::Error::NoEntry) => Err(Error::BadKey),
        Err(error) => Err(keyring_failed(&error)),
    }
}

fn key_from(bytes: &[u8]) -> Result<Key, Error> {
    if bytes.len() != 32 {
        return Err(Error::Storage("the stored key isn't 32 bytes".into()));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(bytes);
    Ok(key)
}

fn random_key() -> Result<Key, Error> {
    let mut key = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(&mut *key)
        .map_err(|_| Error::Internal("no randomness for the key".into()))?;
    Ok(key)
}

/// `<path><suffix>`: a file the database keeps beside it.
fn beside(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Deletes `file`, which may not be there. `what` names it in the error.
fn remove(file: &Path, what: &str) -> Result<(), Error> {
    match std::fs::remove_file(file) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(Error::Storage(format!("{what}: {}", error.kind())))
        }
        _ => Ok(()),
    }
}

#[cfg(secret_service)]
mod file {
    use std::fs::{File, OpenOptions};
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;

    use duvet_e2e::Error;
    use zeroize::Zeroizing;

    use super::{Key, beside};

    fn failed(error: std::io::Error) -> Error {
        Error::Storage(format!("the key file: {}", error.kind()))
    }

    /// What `<path>.key` holds, when it's there: 33 bytes at most, which tells a key from what
    /// isn't one.
    pub(super) fn read(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, Error> {
        let file = match OpenOptions::new().read(true).open(beside(path, ".key")) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(failed(error)),
        };
        // Read into its final capacity, so no copy is left in a block it outgrew.
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        file.take(33).read_to_end(&mut bytes).map_err(failed)?;
        Ok(Some(bytes))
    }

    /// A new random key in `<path>.key`, readable and writable by its user alone. It's written
    /// whole to `<path>.key.tmp`, then renamed: `<path>.key` holds all of it or isn't there. Only
    /// under `<path>.key.lock`, which keeps any other writer out.
    pub(super) fn create(path: &Path) -> Result<Key, Error> {
        let key = super::random_key()?;
        let (temporary, key_file) = (beside(path, ".key.tmp"), beside(path, ".key"));
        // What a write cut short left.
        super::remove(&temporary, "the key file")?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(failed)?;
        file.write_all(&*key)
            .and_then(|()| file.sync_all())
            .map_err(failed)?;
        std::fs::rename(&temporary, &key_file).map_err(failed)?;
        // The rename itself on the disk, before the database the key opens is made.
        let folder = key_file
            .parent()
            .filter(|folder| !folder.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(folder)
            .and_then(|folder| folder.sync_all())
            .map_err(failed)?;
        Ok(key)
    }

    /// Deletes `<path>.key`.
    pub(super) fn remove(path: &Path) -> Result<(), Error> {
        super::remove(&beside(path, ".key"), "the key file")
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    use keyring_core::{CredentialStore, Entry, mock};

    use super::*;

    fn mock_store() -> Arc<CredentialStore> {
        mock::Store::new().unwrap()
    }

    fn entry_in(store: &Arc<CredentialStore>) -> Entry {
        Entry::new_in_store(store, "duvet-e2e-test", "core").unwrap()
    }

    #[test]
    fn keyring_creates_then_reuses_the_key() {
        let store = mock_store();

        let created = key_in(&entry_in(&store), true).unwrap();
        assert_ne!(*created, [0; 32]);
        assert_eq!(entry_in(&store).get_secret().unwrap(), created.to_vec());

        let reused = key_in(&entry_in(&store), true).unwrap();
        assert_eq!(*reused, *created);
    }

    fn no_entry(store: &Arc<CredentialStore>) -> bool {
        matches!(
            entry_in(store).get_secret(),
            Err(keyring_core::Error::NoEntry)
        )
    }

    #[test]
    fn an_existing_database_gets_no_new_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        std::fs::write(&path, b"a database whose key is gone").unwrap();

        // The keyring has no key for it: no key opens it, and none is stored.
        let store = mock_store();
        let error = database_key(&path, Ok(entry_in(&store))).unwrap_err();
        assert_eq!(error.code(), "bad_key");
        assert!(no_entry(&store));

        // No Secret Service at all, and no key file: no file is made either.
        let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
        assert_eq!(database_key(&path, none).unwrap_err().code(), "storage");
        assert!(!dir.path().join("core.db.key").exists());
    }

    #[cfg(secret_service)]
    #[test]
    fn without_a_secret_service_a_new_database_gets_a_file_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");

        let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
        let (key, storage) = database_key(&path, none).unwrap();
        assert_eq!(storage, KeyStorage::File);
        assert_eq!(
            std::fs::read(dir.path().join("core.db.key")).unwrap(),
            key.to_vec()
        );
    }

    /// `<path>.key` as a write cut short leaves it: 5 of its 32 bytes.
    #[cfg(secret_service)]
    const CUT_KEY: [u8; 5] = [7; 5];

    #[cfg(secret_service)]
    #[test]
    fn a_short_key_file_without_a_database_is_replaced() {
        // No database ever got that key. Without a Secret Service, a whole one takes its place.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        std::fs::write(dir.path().join("core.db.key"), CUT_KEY).unwrap();
        let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
        let (key, storage) = database_key(&path, none).unwrap();
        assert_eq!(storage, KeyStorage::File);
        assert_eq!(
            std::fs::read(dir.path().join("core.db.key")).unwrap(),
            key.to_vec()
        );

        // With one, the key goes to the keyring, and the file goes: every open reads it first.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        std::fs::write(dir.path().join("core.db.key"), CUT_KEY).unwrap();
        let store = mock_store();
        let (key, storage) = database_key(&path, Ok(entry_in(&store))).unwrap();
        assert_eq!(storage, KeyStorage::Keyring);
        assert_eq!(entry_in(&store).get_secret().unwrap(), key.to_vec());
        assert!(!dir.path().join("core.db.key").exists());
    }

    #[cfg(secret_service)]
    #[test]
    fn a_short_key_file_with_a_database_is_storage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        std::fs::write(&path, b"a database").unwrap();
        std::fs::write(dir.path().join("core.db.key"), CUT_KEY).unwrap();

        let store = mock_store();
        for entry in [Ok(entry_in(&store)), Err(NoKeyring::Absent)] {
            let error = database_key(&path, entry).unwrap_err();
            assert_eq!(
                error.to_string(),
                "storage: the database's key file isn't 32 bytes"
            );
        }
        // Nothing takes its place: a new key wouldn't open the database either.
        assert_eq!(
            std::fs::read(dir.path().join("core.db.key")).unwrap(),
            CUT_KEY
        );
        assert!(no_entry(&store));
    }

    /// Run by `the_key_file_lands_whole_or_not_at_all` in a process of its own, which can't write
    /// a file past 5 bytes: it makes the key file of the database `DUVET_E2E_CUT_KEY` names.
    #[cfg(all(secret_service, target_os = "linux"))]
    #[test]
    #[ignore = "a child process of the_key_file_lands_whole_or_not_at_all"]
    fn make_a_key_file_and_be_cut() {
        if let Some(path) = std::env::var_os("DUVET_E2E_CUT_KEY") {
            let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
            database_key(Path::new(&path), none).ok();
        }
    }

    #[cfg(all(secret_service, target_os = "linux"))]
    #[test]
    fn the_key_file_lands_whole_or_not_at_all() {
        use std::os::unix::process::ExitStatusExt;

        // Linux's number for SIGXFSZ, which ends a process that writes past its file size limit.
        const SIGXFSZ: i32 = 25;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        let child = std::process::Command::new("prlimit")
            .arg("--fsize=5")
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "keyring::tests::make_a_key_file_and_be_cut"])
            .args(["--ignored", "--test-threads=1"])
            .env("DUVET_E2E_CUT_KEY", &path)
            .output()
            .unwrap();
        // The kernel ended it halfway through the key: 5 of its bytes are in a file.
        assert_eq!(child.status.signal(), Some(SIGXFSZ), "{child:?}");
        let cut = std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|file| file.as_ref().unwrap().metadata().unwrap().len() == 5)
            .count();
        assert_eq!(cut, 1, "one file holds the 5 bytes written");

        let key_file = dir.path().join("core.db.key");
        assert!(
            !key_file.exists(),
            "a key file landed cut short: {:?}",
            std::fs::read(&key_file)
        );
        // The next open makes it, whole.
        let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
        let (key, _) = database_key(&path, none).unwrap();
        assert_eq!(std::fs::read(&key_file).unwrap(), key.to_vec());
    }

    #[cfg(secret_service)]
    #[test]
    fn only_a_missing_secret_service_counts_as_none() {
        use std::io::{self, ErrorKind};

        let failure = |cause: secret_service::Error| -> keyring_core::Result<()> {
            Err(keyring_core::Error::PlatformFailure(Box::new(cause)))
        };
        let bus = |kind: ErrorKind| {
            failure(secret_service::Error::Zbus(zbus::Error::InputOutput(
                Arc::new(io::Error::from(kind)),
            )))
        };
        for none in [
            failure(secret_service::Error::Unavailable),
            // No socket where the session bus would be, or nothing listening on it.
            bus(ErrorKind::NotFound),
            bus(ErrorKind::ConnectionRefused),
            // A bus, but nothing on it provides the Secret Service.
            failure(secret_service::Error::Zbus(zbus::Error::FDO(Box::new(
                zbus::fdo::Error::ServiceUnknown("no provider".into()),
            )))),
        ] {
            assert!(absent(&none), "{none:?}");
        }

        for there in [
            failure(secret_service::Error::Locked),
            failure(secret_service::Error::Prompt),
            bus(ErrorKind::PermissionDenied),
            Err(keyring_core::Error::NoStorageAccess(Box::new(
                secret_service::Error::Unavailable,
            ))),
            Err(keyring_core::Error::PlatformFailure(
                "another failure".into(),
            )),
            Err(keyring_core::Error::NoDefaultStore),
            Ok(()),
        ] {
            assert!(!absent(&there), "{there:?}");
        }
    }

    #[test]
    fn a_database_that_cant_be_looked_for_gets_no_key() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a-file"), b"").unwrap();
        // Whether it exists can't be known: its folder is a file.
        let path = dir.path().join("a-file").join("core.db");

        let store = mock_store();
        assert_eq!(
            database_key(&path, Ok(entry_in(&store)))
                .unwrap_err()
                .code(),
            "storage"
        );
        assert!(no_entry(&store));
    }

    #[test]
    fn a_locked_or_failing_keyring_writes_no_file() {
        for (refusal, message) in [
            (
                keyring_core::Error::NoStorageAccess("locked".into()),
                "the system keyring is locked or refused access: unlock it and try again",
            ),
            (
                keyring_core::Error::PlatformFailure("a running service failed".into()),
                "the system keyring failed",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("core.db");
            let store = mock_store();
            let entry = entry_in(&store);
            let mock: &mock::Cred = entry.as_any().downcast_ref().unwrap();
            mock.set_error(refusal);

            let error = database_key(&path, Ok(entry)).unwrap_err();
            assert_eq!(error.code(), "storage");
            assert_eq!(error.to_string(), format!("storage: {message}"));
            assert!(!dir.path().join("core.db.key").exists(), "{message}");
            assert!(no_entry(&store));
        }
    }

    #[test]
    fn keyring_makes_no_key_for_a_database_that_exists() {
        let store = mock_store();
        let entry = entry_in(&store);

        let failure = key_in(&entry, false).unwrap_err();
        assert!(matches!(failure, Error::BadKey), "{failure:?}");
        assert!(matches!(
            entry.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
    }

    /// A mock entry whose first read, of all the opens sharing `first`, pauses: another open
    /// meanwhile runs to its end.
    struct FirstReadPauses<'a> {
        entry: Entry,
        first: &'a AtomicBool,
    }

    impl KeyStore for FirstReadPauses<'_> {
        fn get(&self) -> keyring_core::Result<Vec<u8>> {
            let secret = self.entry.get_secret();
            if self.first.swap(false, Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(500));
            }
            secret
        }

        fn set(&self, key: &[u8]) -> keyring_core::Result<()> {
            self.entry.set_secret(key)
        }

        fn delete(&self) -> keyring_core::Result<()> {
            self.entry.delete_credential()
        }
    }

    #[test]
    fn racing_first_opens_agree_on_one_key() {
        let store = mock_store();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        let first = AtomicBool::new(true);
        let open = || {
            open_with(
                &path,
                Ok(FirstReadPauses {
                    entry: entry_in(&store),
                    first: &first,
                }),
            )
        };

        let (a, b) = thread::scope(|scope| {
            let a = scope.spawn(open);
            let b = scope.spawn(open);
            (a.join().unwrap(), b.join().unwrap())
        });
        let (core, loser) = match (a, b) {
            (Ok(core), Err(error)) | (Err(error), Ok(core)) => (core, error),
            (a, b) => panic!("one open wins: {:?} {:?}", a.err(), b.err()),
        };
        assert_eq!(loser.code(), "locked");
        core.close();

        // What the keyring holds opens the database, and so does the next open through it.
        let stored = key_from(&entry_in(&store).get_secret().unwrap()).unwrap();
        Core::open(OpenConfig::new(&path, stored))
            .expect("the stored key opens the database")
            .close();
        open_with(&path, Ok(entry_in(&store))).unwrap().close();
    }

    /// The names of the files in `dir`, in order.
    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|file| file.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn destroy_removes_the_database_and_its_key() {
        // A database whose key the keyring keeps, beside the journal a crash left.
        let store = mock_store();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        open_with(&path, Ok(entry_in(&store))).unwrap().close();
        std::fs::write(dir.path().join("core.db-journal"), b"a crash's journal").unwrap();

        destroy_with(&path, Some(Ok(entry_in(&store)))).unwrap();
        // Only the key's lock stays, empty: another open may be waiting for it.
        assert_eq!(files_in(dir.path()), ["core.db.key.lock"]);
        assert!(no_entry(&store));
        // A second time, there's nothing left to delete.
        destroy_with(&path, Some(Ok(entry_in(&store)))).unwrap();

        // A database whose key its client keeps: no keyring is touched.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        Core::open(OpenConfig::new(&path, [1; 32])).unwrap().close();
        destroy_with(&path, None::<Result<Entry, NoKeyring>>).unwrap();
        assert_eq!(files_in(dir.path()), ["core.db.key.lock"]);

        // A database whose key is in `<path>.key`, where there's no Secret Service.
        #[cfg(secret_service)]
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("core.db");
            let none = || -> Result<Entry, NoKeyring> { Err(NoKeyring::Absent) };
            open_with(&path, none()).unwrap().close();
            assert!(dir.path().join("core.db.key").exists());
            destroy_with(&path, Some(none())).unwrap();
            assert_eq!(files_in(dir.path()), ["core.db.key.lock"]);
        }
    }

    #[test]
    fn destroy_refuses_an_open_database() {
        let store = mock_store();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        let core = open_with(&path, Ok(entry_in(&store))).unwrap();
        let key = entry_in(&store).get_secret().unwrap();

        let error = destroy_with(&path, Some(Ok(entry_in(&store)))).unwrap_err();
        assert_eq!(error.code(), "locked");
        core.close();
        // Nothing went: the database is there, and the key the keyring keeps opens it.
        assert!(path.exists());
        assert_eq!(entry_in(&store).get_secret().unwrap(), key);
        Core::open(OpenConfig::new(&path, key_from(&key).unwrap()))
            .expect("the key opens the database")
            .close();
    }

    #[cfg(secret_service)]
    #[test]
    fn file_key_is_private_and_read_back() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("core.db");
        assert!(file::read(&path).unwrap().is_none());

        let created = file::create(&path).unwrap();
        let metadata = std::fs::metadata(dir.path().join("core.db.key")).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(*file::read(&path).unwrap().unwrap(), created.to_vec());
        // A whole key is never replaced: the next open, of a database still to be made, takes it.
        let none: Result<Entry, NoKeyring> = Err(NoKeyring::Absent);
        let (reused, storage) = database_key(&path, none).unwrap();
        assert_eq!((*reused, storage), (*created, KeyStorage::File));
    }
}
