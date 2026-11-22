//! The desktop's database key: kept in the system's keyring (Windows' Credential Manager, macOS's
//! Keychain, the Secret Service), made on the database's first open. Where Linux has no Secret
//! Service, it goes to `<path>.key`, which only its user reads, and `status` says `file`.

use std::path::Path;

use duvet_e2e::{Error, KeyStorage};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

pub(crate) type Key = Zeroizing<[u8; 32]>;

/// Why a key couldn't be had from the keyring.
#[derive(Debug)]
enum Failure {
    Keyring(keyring_core::Error),
    Core(Error),
}

/// The key of the database at `path`, and where it's kept.
///
/// A key is made only for a database that doesn't exist yet: for one that does, a missing key
/// can't open it, and a new one would only hide the key that might come back.
pub(crate) fn database_key(
    path: &Path,
    service: &str,
    account: &str,
) -> Result<(Key, KeyStorage), Error> {
    let fresh = !path.exists();
    #[cfg(secret_service)]
    if let Some(key) = file::read(path)? {
        return Ok((key, KeyStorage::File));
    }
    let failure = match keyring::Entry::new(service, account) {
        Ok(entry) => match key_in(&entry.inner, fresh) {
            Ok(key) => return Ok((key, KeyStorage::Keyring)),
            Err(failure) => failure,
        },
        Err(error) => Failure::Keyring(error),
    };
    match failure {
        Failure::Core(error) => Err(error),
        #[cfg(secret_service)]
        Failure::Keyring(error) if unreachable(&error) => {
            if fresh {
                file::create(path).map(|key| (key, KeyStorage::File))
            } else {
                Err(Error::Storage("the system keyring isn't available".into()))
            }
        }
        // Its text can name the entry: the message stays fixed.
        Failure::Keyring(_) => Err(Error::Storage("the system keyring failed".into())),
    }
}

/// The key `entry` holds, or a new random one it stores when the database is `fresh`.
fn key_in(entry: &keyring_core::Entry, fresh: bool) -> Result<Key, Failure> {
    match entry.get_secret() {
        Ok(secret) => key_from(&Zeroizing::new(secret)).map_err(Failure::Core),
        Err(keyring_core::Error::NoEntry) if fresh => {
            let key = random_key()?;
            entry.set_secret(&*key).map_err(Failure::Keyring)?;
            Ok(key)
        }
        Err(keyring_core::Error::NoEntry) => Err(Failure::Core(Error::BadKey)),
        Err(error) => Err(Failure::Keyring(error)),
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

fn random_key() -> Result<Key, Failure> {
    let mut key = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(&mut *key)
        .map_err(|_| Failure::Core(Error::Internal("no randomness for the key".into())))?;
    Ok(key)
}

/// The Secret Service isn't there: no session bus, or nothing answering on it.
#[cfg(secret_service)]
fn unreachable(error: &keyring_core::Error) -> bool {
    matches!(
        error,
        keyring_core::Error::NoDefaultStore
            | keyring_core::Error::PlatformFailure(_)
            | keyring_core::Error::NoStorageAccess(_)
    )
}

#[cfg(secret_service)]
mod file {
    use std::fs::OpenOptions;
    use std::io::{ErrorKind, Read, Write};
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use duvet_e2e::Error;
    use zeroize::Zeroizing;

    use super::{Key, key_from};

    fn key_path(path: &Path) -> PathBuf {
        let mut name = path.as_os_str().to_owned();
        name.push(".key");
        PathBuf::from(name)
    }

    /// The key in `<path>.key`, when there is one.
    pub(super) fn read(path: &Path) -> Result<Option<Key>, Error> {
        let mut file = match OpenOptions::new().read(true).open(key_path(path)) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(Error::Storage(format!("the key file: {}", error.kind()))),
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        file.read_to_end(&mut bytes)
            .map_err(|error| Error::Storage(format!("the key file: {}", error.kind())))?;
        key_from(&bytes).map(Some)
    }

    /// A new random key in `<path>.key`, made readable and writable by its user alone.
    pub(super) fn create(path: &Path) -> Result<Key, Error> {
        let key =
            super::random_key().map_err(|_| Error::Internal("no randomness for the key".into()))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(key_path(path))
            .map_err(|error| Error::Storage(format!("the key file: {}", error.kind())))?;
        file.write_all(&*key)
            .and_then(|()| file.sync_all())
            .map_err(|error| Error::Storage(format!("the key file: {}", error.kind())))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use keyring_core::{CredentialStore, Entry, mock};

    use super::*;

    #[test]
    fn keyring_creates_then_reuses_the_key() {
        let store: Arc<CredentialStore> = mock::Store::new().unwrap();
        let entry = || Entry::new_in_store(&store, "duvet-e2e-test", "core").unwrap();

        let created = key_in(&entry(), true).unwrap();
        assert_ne!(*created, [0; 32]);
        assert_eq!(entry().get_secret().unwrap(), created.to_vec());

        let reused = key_in(&entry(), true).unwrap();
        assert_eq!(*reused, *created);
    }

    #[test]
    fn keyring_makes_no_key_for_a_database_that_exists() {
        let store: Arc<CredentialStore> = mock::Store::new().unwrap();
        let entry = Entry::new_in_store(&store, "duvet-e2e-test", "core").unwrap();

        let failure = key_in(&entry, false).unwrap_err();
        assert!(
            matches!(failure, Failure::Core(Error::BadKey)),
            "{failure:?}"
        );
        assert!(matches!(
            entry.get_secret(),
            Err(keyring_core::Error::NoEntry)
        ));
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
        assert_eq!(*file::read(&path).unwrap().unwrap(), *created);
        assert!(file::create(&path).is_err(), "never overwritten");
    }
}
