//! The commands the core takes: `{"cmd": "<name>", ...fields}`.

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
    #[serde(with = "b64::option", skip_serializing_if = "Option::is_none")]
    identity_key: Option<Vec<u8>>,
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
        identity_key,
        key_storage: tx.key_storage(),
    })
}

/// Binary fields in the JSON protocol: standard base64 with its padding. Use with
/// `#[serde(with = "b64")]` on a `Vec<u8>`, or `b64::option` on an `Option<Vec<u8>>`.
// Batch 1's commands are its first users; the allow goes with them.
#[allow(dead_code)]
pub(crate) mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(
        bytes: impl AsRef<[u8]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(|_| D::Error::custom("not padded base64"))
    }

    pub(crate) mod option {
        use super::*;

        pub(crate) fn serialize<S: Serializer>(
            bytes: &Option<impl AsRef<[u8]>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match bytes {
                Some(bytes) => serializer.serialize_some(&STANDARD.encode(bytes)),
                None => serializer.serialize_none(),
            }
        }

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<Vec<u8>>, D::Error> {
            Option::<String>::deserialize(deserializer)?
                .map(|text| {
                    STANDARD
                        .decode(text)
                        .map_err(|_| D::Error::custom("not padded base64"))
                })
                .transpose()
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::b64;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Fields {
        #[serde(with = "b64")]
        key: Vec<u8>,
        #[serde(default, with = "b64::option", skip_serializing_if = "Option::is_none")]
        note: Option<Vec<u8>>,
    }

    #[test]
    fn binary_fields_are_padded_base64() {
        let fields = Fields {
            key: vec![0xfb, 0xff, 0x01],
            note: Some(b"a".to_vec()),
        };
        let json = serde_json::to_string(&fields).unwrap();
        assert_eq!(json, r#"{"key":"+/8B","note":"YQ=="}"#);
        assert_eq!(serde_json::from_str::<Fields>(&json).unwrap(), fields);
        assert_eq!(
            serde_json::from_str::<Fields>(r#"{"key":""}"#).unwrap(),
            Fields {
                key: vec![],
                note: None
            }
        );

        for bad in [
            r#"{"key":"YQ"}"#,
            r#"{"key":"-_8B"}"#,
            r#"{"key":"+/8B","note":"Y"}"#,
            r#"{"key":3}"#,
        ] {
            assert!(serde_json::from_str::<Fields>(bad).is_err(), "{bad}");
        }
    }
}
