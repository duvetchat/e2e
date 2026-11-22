//! OpenMLS's provider: RustCrypto for the cryptography and the randomness, and the database for the state.

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use crate::SqlStorage;

/// The provider for one transaction: whatever OpenMLS stores through it goes into that transaction.
pub struct Provider<'a> {
    crypto: &'a RustCrypto,
    storage: SqlStorage<'a>,
}

impl<'a> Provider<'a> {
    pub(crate) fn new(crypto: &'a RustCrypto, storage: SqlStorage<'a>) -> Self {
        Self { crypto, storage }
    }
}

impl<'a> OpenMlsProvider for Provider<'a> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqlStorage<'a>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.crypto
    }
}
