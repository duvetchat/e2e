//! The commands the core takes: `{"cmd": "<name>", ...fields}`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Error, KeyStorage, PROTOCOL, Tx};

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub(crate) enum Command {
    Status,
}

pub(crate) fn parse(command: &str) -> Result<Command, Error> {
    serde_json::from_str(command).map_err(Error::bad_command)
}

pub(crate) fn dispatch(tx: &mut Tx<'_>, command: Command) -> Result<Value, Error> {
    match command {
        Command::Status => reply(cmd_status(tx)?),
    }
}

fn reply(value: impl Serialize) -> Result<Value, Error> {
    serde_json::to_value(value).map_err(|error| Error::Internal(error.to_string()))
}

#[derive(Serialize)]
struct Status {
    protocol: u32,
    version: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<Uuid>,
    /// Base64.
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_key: Option<String>,
    has_identity: bool,
    key_storage: KeyStorage,
}

fn cmd_status(tx: &mut Tx<'_>) -> Result<Status, Error> {
    let device: Option<(Vec<u8>, Vec<u8>)> = tx
        .conn()
        .query_row("SELECT user_id, device_id FROM device", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()?;
    let identity_key: Option<Vec<u8>> = tx
        .conn()
        .query_row(
            "SELECT value FROM meta WHERE key = 'identity_key'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let uuid =
        |bytes: &[u8]| Uuid::from_slice(bytes).map_err(|error| Error::Internal(error.to_string()));
    Ok(Status {
        protocol: PROTOCOL,
        version: env!("CARGO_PKG_VERSION"),
        user_id: device.as_ref().map(|(user, _)| uuid(user)).transpose()?,
        device_id: device
            .as_ref()
            .map(|(_, device)| uuid(device))
            .transpose()?,
        has_identity: identity_key.is_some(),
        identity_key: identity_key.map(|key| STANDARD.encode(key)),
        key_storage: tx.key_storage(),
    })
}
