//! The commands the core takes: `{"cmd": "<name>", ...fields}`.

use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{Error, KeyStorage, PROTOCOL, Tx, direct, identity, messages, mls, parts};

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub(crate) enum Command {
    Status,

    // Identity, devices, contacts and key packages.
    CreateDevice {
        user_id: Uuid,
        device_id: Uuid,
    },
    CreateIdentity,
    SignDeviceList {
        remove: Vec<Uuid>,
    },
    ObserveUser {
        user_id: Uuid,
        #[serde(with = "b64")]
        identity_key: Vec<u8>,
        #[serde(with = "b64")]
        device_list: Vec<u8>,
        #[serde(default, with = "b64::list")]
        certificates: Vec<Vec<u8>>,
    },
    SafetyNumber {
        user_id: Uuid,
    },
    VerifyUser {
        user_id: Uuid,
        #[serde(default, with = "b64::option")]
        qr: Option<Vec<u8>>,
    },
    KeyPackages,

    // Attachments' parts.
    AttachmentKey,
    AttachmentEncrypt(parts::AttachmentPart),
    AttachmentDecrypt(parts::AttachmentPart),

    // New devices, by the recovery key or by another device's approval, and the messages devices
    // send each other.
    Recover(identity::Recover),
    ApprovalBegin,
    ApprovalOffer(identity::ApprovalOffer),
    ApprovalReveal(identity::ApprovalReveal),
    ApprovalCheck(identity::ApprovalCheck),
    ApprovalConfirm,
    ApprovalFromQr(identity::ApprovalFromQr),
    ApprovalReceive(identity::ApprovalReceive),
    ReceiveDirect(direct::ReceiveDirect),

    // Conversations' groups.
    CreateGroup(mls::CreateGroup),
    CommitResult(mls::CommitResult),
    AddMembers(mls::AddMembers),
    RemoveMembers(mls::RemoveMembers),
    Leave(mls::ConversationId),
    CommitPending(mls::ConversationId),
    RefreshDue,
    Refresh(mls::ConversationId),
    JoinExternal(mls::JoinExternal),
    ResetGroup(mls::ResetGroup),
    Group(mls::ConversationId),
    Apply(mls::ApplyRequest),

    // Messages.
    Encrypt(messages::Encrypt),
    Sent(messages::Sent),
    Edit(messages::Edit),
    Delete(messages::Delete),
    Messages(messages::ListMessages),
    Search(messages::Search),
    WithoutDevices(messages::WithoutDevices),
}

pub(crate) fn parse(command: &str) -> Result<Command, Error> {
    serde_json::from_str(command).map_err(Error::bad_command)
}

pub(crate) fn dispatch(tx: &mut Tx<'_>, command: Command) -> Result<Value, Error> {
    match command {
        Command::Status => reply(cmd_status(tx)?),

        Command::CreateDevice { user_id, device_id } => {
            reply(identity::create_device(tx, user_id, device_id)?)
        }
        Command::CreateIdentity => reply(identity::create_identity(tx)?),
        Command::SignDeviceList { remove } => reply(identity::sign_device_list(tx, &remove)?),
        Command::ObserveUser {
            user_id,
            identity_key,
            device_list,
            certificates,
        } => reply(identity::observe_user(
            tx,
            user_id,
            &identity_key,
            &device_list,
            &certificates,
        )?),
        Command::SafetyNumber { user_id } => reply(identity::safety_number(tx, user_id)?),
        Command::VerifyUser { user_id, qr } => {
            reply(identity::verify_user(tx, user_id, qr.as_deref())?)
        }
        Command::KeyPackages => reply(identity::key_packages(tx)?),

        Command::AttachmentKey => reply(parts::attachment_key(tx)?),
        Command::AttachmentEncrypt(part) => reply(parts::attachment_encrypt(part)?),
        Command::AttachmentDecrypt(part) => reply(parts::attachment_decrypt(part)?),

        Command::Recover(request) => reply(identity::recover(tx, request)?),
        Command::ApprovalBegin => reply(identity::approval_begin(tx)?),
        Command::ApprovalOffer(request) => reply(identity::approval_offer(tx, request)?),
        Command::ApprovalReveal(request) => reply(identity::approval_reveal(tx, request)?),
        Command::ApprovalCheck(request) => reply(identity::approval_check(tx, request)?),
        Command::ApprovalConfirm => reply(identity::approval_confirm(tx)?),
        Command::ApprovalFromQr(request) => reply(identity::approval_from_qr(tx, request)?),
        Command::ApprovalReceive(request) => reply(identity::approval_receive(tx, request)?),
        Command::ReceiveDirect(request) => reply(direct::receive_direct(tx, request)?),

        Command::CreateGroup(request) => reply(mls::create_group(tx, request)?),
        Command::CommitResult(request) => reply(mls::commit_result(tx, request)?),
        Command::AddMembers(request) => reply(mls::add_members(tx, request)?),
        Command::RemoveMembers(request) => reply(mls::remove_members(tx, request)?),
        Command::Leave(request) => reply(mls::leave(tx, request)?),
        Command::CommitPending(request) => reply(mls::commit_pending(tx, request)?),
        Command::RefreshDue => reply(mls::refresh_due(tx)?),
        Command::Refresh(request) => reply(mls::refresh(tx, request)?),
        Command::JoinExternal(request) => reply(mls::join_external(tx, request)?),
        Command::ResetGroup(request) => reply(mls::reset_group(tx, request)?),
        Command::Group(request) => reply(mls::group(tx, request)?),
        Command::Apply(request) => reply(mls::apply(tx, request)?),

        Command::Encrypt(request) => reply(messages::encrypt(tx, request)?),
        Command::Sent(request) => reply(messages::sent(tx, request)?),
        Command::Edit(request) => reply(messages::edit(tx, request)?),
        Command::Delete(request) => reply(messages::delete(tx, request)?),
        Command::Messages(request) => reply(messages::messages(tx, request)?),
        Command::Search(request) => reply(messages::search(tx, request)?),
        Command::WithoutDevices(request) => reply(messages::without_devices(tx, request)?),
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
/// `#[serde(with = "b64")]` on a `Vec<u8>`, `b64::option` on an `Option<Vec<u8>>`,
/// `b64::list` on a `Vec<Vec<u8>>` a command takes, or `b64::secret` on a key it takes, a
/// `Zeroizing<Vec<u8>>`. [`b64::Bytes`] is one binary value inside a list or map a command takes.
pub(crate) mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    /// A binary value a command takes inside a list or a map.
    #[derive(Debug, Deserialize)]
    #[serde(transparent)]
    pub(crate) struct Bytes(#[serde(deserialize_with = "deserialize")] pub(crate) Vec<u8>);

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

    pub(crate) mod list {
        use super::*;

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<Vec<u8>>, D::Error> {
            Vec::<String>::deserialize(deserializer)?
                .into_iter()
                .map(|text| {
                    STANDARD
                        .decode(text)
                        .map_err(|_| D::Error::custom("not padded base64"))
                })
                .collect()
        }
    }

    /// A secret, decoded into memory that's wiped as it drops. No `String` of its own holds the
    /// base64 on the way, unless the JSON escaped a character in it and serde_json unescaped it.
    pub(crate) mod secret {
        use std::fmt;

        use serde::de::Visitor;
        use zeroize::Zeroizing;

        use super::*;

        pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
            deserializer.deserialize_str(Base64)
        }

        struct Base64;

        impl Visitor<'_> for Base64 {
            type Value = Zeroizing<Vec<u8>>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("padded base64")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Self::Value, E> {
                let mut bytes = Zeroizing::new(vec![0; base64::decoded_len_estimate(text.len())]);
                let len = STANDARD
                    .decode_slice(text, &mut bytes)
                    .map_err(|_| E::custom("not padded base64"))?;
                bytes.truncate(len);
                Ok(bytes)
            }
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
