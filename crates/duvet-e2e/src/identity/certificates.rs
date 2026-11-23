//! Each user's devices' certificates, as `observe_user` and rotations bring them, this device's own
//! user's included: only ever ones the identity this device pins or holds for the user signed. With
//! the identities each user had before, they let a leaf made under an earlier identity be taken
//! (`mls::certify_by_pinned`).

use duvet_e2e_rules::DeviceCertificate;
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;

use super::stored_key;
use crate::{Error, Tx};

/// Keeps `identity_key` as one of the identities `user` had before their current one: this
/// device's own user's, as a rotation replaces it (`observe_user` keeps other users').
pub(crate) fn keep_earlier_identity(
    tx: &Tx<'_>,
    user: Uuid,
    identity_key: &[u8; 32],
) -> Result<(), Error> {
    tx.conn().execute(
        "INSERT INTO contact_identities (user_id, identity_key, replaced_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT (user_id, identity_key) DO UPDATE SET replaced_at = excluded.replaced_at",
        params![
            user.as_bytes().as_slice(),
            identity_key.as_slice(),
            tx.now()
        ],
    )?;
    Ok(())
}

/// Keeps `certificates`, which the identity pinned or held for `user` signed, as their devices':
/// in place of every one kept before when `fresh` (another identity's), else of those of the same
/// devices.
pub(crate) fn keep_certificates<'a>(
    tx: &Tx<'_>,
    user: Uuid,
    certificates: impl IntoIterator<Item = &'a [u8]>,
    fresh: bool,
) -> Result<(), Error> {
    if fresh {
        tx.conn().execute(
            "DELETE FROM certificates WHERE user_id = ?1",
            [user.as_bytes().as_slice()],
        )?;
    }
    for signed in certificates {
        let device = DeviceCertificate::read_unverified(signed)
            .map_err(|_| Error::Internal("a certificate to keep is malformed".into()))?
            .device;
        tx.conn().execute(
            "INSERT INTO certificates (user_id, device_id, certificate) VALUES (?1, ?2, ?3) \
             ON CONFLICT (user_id, device_id) DO UPDATE SET certificate = excluded.certificate",
            params![
                user.as_bytes().as_slice(),
                device.as_bytes().as_slice(),
                signed
            ],
        )?;
    }
    Ok(())
}

impl Tx<'_> {
    /// The identities `user` had before the one this device pins or holds for them.
    pub(crate) fn earlier_identities_of(&self, user: Uuid) -> Result<Vec<[u8; 32]>, Error> {
        let mut statement = self
            .conn()
            .prepare("SELECT identity_key FROM contact_identities WHERE user_id = ?1")?;
        let keys =
            statement.query_map([user.as_bytes().as_slice()], |row| row.get::<_, Vec<u8>>(0))?;
        keys.map(|key| stored_key(&key?)).collect()
    }

    /// The certificate kept for `user`'s `device`, signed by the identity this device pins or
    /// holds for the user.
    pub(crate) fn certificate_of(
        &self,
        user: Uuid,
        device: Uuid,
    ) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .conn()
            .query_row(
                "SELECT certificate FROM certificates WHERE user_id = ?1 AND device_id = ?2",
                [user.as_bytes().as_slice(), device.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?)
    }
}
