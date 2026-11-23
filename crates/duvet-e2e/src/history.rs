//! Shared history and catch-ups: one package of a conversation's records, from one device to the
//! devices of another member.
//!
//! - `history_share` packs what this device has of the last day, week, month or all of a
//!   conversation, for a member who joined it later (decision 26).
//! - `catch_up` packs what this device noted for a member who had no device while it sent
//!   (decision 14). The note stays until the client says the package is up
//!   (`catch_up_delivered`), and then only what the package carried goes: a reply lost on the way
//!   costs a package made again, and what didn't fit waits for the next.
//!
//! A package is the records' CBOR, deflated, under a header that says what it is ([`Header`]),
//! signed by the device that made it under `duvet history share v1`: `{v: 1, header, records}`. It
//! goes sealed in parts of 1 MiB, under a key drawn for it alone and bound to its ID (the parts of
//! [`crate::parts`]), 64 MiB at most: when everything doesn't fit, the newest that fits goes, and
//! the reply says so (`truncated`). The key goes to each of the recipient's devices as a direct
//! message of type `history.key` or `catch_up.key`, which `receive_direct` takes once its sender is
//! a device its user's identity certifies and lists. `history_import` then opens the package with
//! it, verifies the package with that same device's key, inflates its records in steps, 256 MiB at
//! most, and imports them as shared by its user: nothing a device has is overwritten, and a message
//! that waits takes the record's content.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e_rules::{DeviceCertificate, HISTORY_SHARE, RuleViolation, sign, verify};
use miniz_oxide::inflate::stream::{InflateState, inflate};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use openmls_traits::OpenMlsProvider;
use openmls_traits::signatures::Signer;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::identity::{from_cbor, invalid, not_found, random, stored_key, stored_uuid, to_cbor};
use crate::messages::{Empty, Record, RecordKind, import, noted_records, records_for};
use crate::mls::{GroupRow, ask_first};
use crate::parts::{PACKAGE_PART, TAG, fits, open_part, seal_part};
use crate::protocol::b64;
use crate::{DirectMessage, Error, OwnDevice, Tx};

/// The largest package, sealed: 64 MiB.
pub const MAX_PACKAGE: usize = 64 * 1024 * 1024;

/// The most a package's records take inflated: 256 MiB.
pub const MAX_RECORDS: usize = 256 * 1024 * 1024;

/// The types of the direct messages that carry a package's key.
pub(crate) const SHARE_KEY: &str = "history.key";
pub(crate) const CATCH_UP_KEY: &str = "catch_up.key";

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// How long the server keeps a package: past it, a catch-up can't be delivered any more.
const PACKAGE_KEPT_MS: i64 = 30 * DAY_MS;

/// zlib's default level.
const COMPRESSION: u8 = 6;

/// How much a package's records' CBOR may take besides the records: its array's header.
const ARRAY_HEADER: usize = 9;

/// Room for a key's direct message's payload, sized ahead so no copy of the key is left behind as
/// its buffer grows.
const KEY_PAYLOAD: usize = 128;

/// How far back a share goes from now: 24 hours, 7 days, 30 days, or all this device has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Range {
    Day,
    Week,
    Month,
    All,
}

impl Range {
    /// When the range starts, at `now`, in Unix milliseconds.
    fn start(self, now: i64) -> i64 {
        let days = match self {
            Range::Day => 1,
            Range::Week => 7,
            Range::Month => 30,
            Range::All => return 0,
        };
        now.saturating_sub(days * DAY_MS).max(0)
    }
}

/// What a package is: a member's share of a conversation's history, or a catch-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareKind {
    Share,
    CatchUp,
}

impl ShareKind {
    /// The type of the direct message that carries the package's key.
    fn key_type(self) -> &'static str {
        match self {
            ShareKind::Share => SHARE_KEY,
            ShareKind::CatchUp => CATCH_UP_KEY,
        }
    }

    fn name(self) -> &'static str {
        match self {
            ShareKind::Share => "share",
            ShareKind::CatchUp => "catch_up",
        }
    }

    fn from_name(name: &str) -> Result<ShareKind, Error> {
        match name {
            "share" => Ok(ShareKind::Share),
            "catch_up" => Ok(ShareKind::CatchUp),
            _ => Err(stored()),
        }
    }
}

/// What a package says of itself, signed with its records: what it is, of which conversation, who
/// shares it (the user and the device that signs it), and for whom.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub kind: ShareKind,
    pub conversation: Uuid,
    pub user: Uuid,
    pub device: Uuid,
    pub to: Uuid,
}

/// What the device signs: `{v: 1, header, records}`, the records deflated.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    v: u32,
    header: Header,
    #[serde(with = "serde_bytes")]
    records: Vec<u8>,
}

/// The same, to write, without a copy of the records.
#[derive(Serialize)]
struct BodyOut<'a> {
    v: u32,
    header: &'a Header,
    #[serde(with = "serde_bytes")]
    records: &'a [u8],
}

/// A package's key, as a direct message carries it: `{v: 1, share, conversation, key}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyPayload {
    v: u32,
    share: Uuid,
    conversation: Uuid,
    #[serde(with = "secret")]
    key: Zeroizing<[u8; 32]>,
}

/// A package sealed for its recipient: its parts, for the server, and its key sealed to each of
/// the recipient's devices, for their inboxes.
#[derive(Debug, Serialize)]
pub struct Sealed {
    pub share_id: Uuid,
    #[serde(serialize_with = "base64_each")]
    pub parts: Vec<Vec<u8>>,
    /// The parts' bytes together: what the package takes on the server.
    pub size: u64,
    pub keys: Vec<SealedKey>,
}

/// A package's key, sealed to one of the recipient's devices.
#[derive(Debug, Serialize)]
pub struct SealedKey {
    pub device_id: Uuid,
    /// The direct message that carries it, for the device's inbox.
    #[serde(with = "b64")]
    pub message: Vec<u8>,
}

/// What `history_share` and `catch_up` answer: the package sealed, and what it holds.
#[derive(Debug, Serialize)]
pub struct Shared {
    #[serde(flatten)]
    pub sealed: Sealed,
    /// The package holds every record this device has from this time on, in Unix milliseconds.
    pub start: i64,
    /// Older records were left out, as they didn't fit.
    pub truncated: bool,
}

/// `history_share`: the conversation's history from the range's start, for one of its members.
#[derive(Debug, Deserialize)]
pub(crate) struct HistoryShare {
    conversation_id: Uuid,
    to_user: Uuid,
    range: Range,
    /// The recipient's devices' certificates, as the server serves them.
    #[serde(with = "b64::list")]
    devices: Vec<Vec<u8>>,
}

/// `catch_up`: what this device noted for a member while they had no device.
#[derive(Debug, Deserialize)]
pub(crate) struct CatchUp {
    conversation_id: Uuid,
    user_id: Uuid,
    /// The member's devices' certificates, as the server serves them.
    #[serde(with = "b64::list")]
    devices: Vec<Vec<u8>>,
}

/// `catch_up_delivered`: the client uploaded a catch-up this device made, and posted its keys.
#[derive(Debug, Deserialize)]
pub(crate) struct CatchUpDelivered {
    conversation_id: Uuid,
    user_id: Uuid,
    share_id: Uuid,
}

/// `history_import`: a package whose key `receive_direct` took, as the server hands its parts over.
#[derive(Debug, Deserialize)]
pub(crate) struct HistoryImport {
    share_id: Uuid,
    #[serde(with = "b64::list")]
    parts: Vec<Vec<u8>>,
}

#[derive(Serialize)]
pub(crate) struct Imported {
    /// How many records changed something.
    imported: usize,
}

/// What `receive_direct` answers for a package's key.
#[derive(Serialize)]
pub(crate) struct KeyReceived {
    share_id: Uuid,
    conversation_id: Uuid,
    /// The user who shares the package.
    user_id: Uuid,
}

pub(crate) fn history_share(tx: &Tx<'_>, request: HistoryShare) -> Result<Shared, Error> {
    share(
        tx,
        request.conversation_id,
        request.to_user,
        request.range,
        &request.devices,
        MAX_PACKAGE,
    )
}

/// `history_share` with the sealed package held to `limit` bytes (the command's is
/// `MAX_PACKAGE`): what this device shows of `conversation` from `range`'s start, the newest that
/// fit, for `to`, a member of it other than this device's user. Its key is sealed to each device
/// of `devices` ([`seal`]).
pub fn share(
    tx: &Tx<'_>,
    conversation: Uuid,
    to: Uuid,
    range: Range,
    devices: &[Vec<u8>],
    limit: usize,
) -> Result<Shared, Error> {
    let own = sharing_with(tx, conversation, to, "to_user")?;
    let recipients = recipients(tx, to, devices)?;
    let start = range.start(tx.now());
    let records = records_for(tx, conversation, start, i64::MAX)?;
    let header = Header {
        kind: ShareKind::Share,
        conversation,
        user: own.user,
        device: own.device,
        to,
    };
    let (shared, _) = pack(tx, &own, &header, &records, start, limit, &recipients)?;
    Ok(shared)
}

pub(crate) fn catch_up(tx: &Tx<'_>, request: CatchUp) -> Result<Shared, Error> {
    catch_up_within(
        tx,
        request.conversation_id,
        request.user_id,
        &request.devices,
        MAX_PACKAGE,
    )
}

/// `catch_up` with the sealed package held to `limit` bytes (the command's is `MAX_PACKAGE`): what
/// this device noted for `user` in `conversation` under the identity it pins for them now, the
/// newest that fit, in one package sealed to their devices. The note stays: the messages the
/// package carried are kept by its ID, and their notes go only once the client says it delivered
/// it (`catch_up_delivered`). Until then the user stays due, and a catch-up whose reply was lost is
/// made again. Nothing noted that a catch-up can carry is `not_found` (`catch_up`).
pub fn catch_up_within(
    tx: &Tx<'_>,
    conversation: Uuid,
    user: Uuid,
    devices: &[Vec<u8>],
    limit: usize,
) -> Result<Shared, Error> {
    let own = sharing_with(tx, conversation, user, "user_id")?;
    // While the client still counts them as without a device, they're due nothing: the key would
    // go to devices that may never come, and the package's delivery would forget its notes.
    let without: bool = tx.conn().query_row(
        "SELECT EXISTS (SELECT 1 FROM deviceless_users WHERE conversation_id = ?1 AND user_id = ?2)",
        params![
            conversation.as_bytes().as_slice(),
            user.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    let records = if without {
        Vec::new()
    } else {
        noted_records(tx, conversation, user)?
    };
    if records.is_empty() {
        return Err(not_found("catch_up"));
    }
    let recipients = recipients(tx, user, devices)?;
    let header = Header {
        kind: ShareKind::CatchUp,
        conversation,
        user: own.user,
        device: own.device,
        to: user,
    };
    let (shared, carried) = pack(tx, &own, &header, &records, 0, limit, &recipients)?;
    // A catch-up the server no longer keeps can't be delivered: its record goes, and its messages'
    // notes stay for another.
    tx.conn().execute(
        "DELETE FROM catch_ups WHERE created_at < ?1",
        [tx.now().saturating_sub(PACKAGE_KEPT_MS)],
    )?;
    let share = shared.sealed.share_id;
    for record in carried
        .iter()
        .filter(|record| record.kind == RecordKind::Message)
    {
        tx.conn().execute(
            "INSERT OR IGNORE INTO catch_ups (share_id, conversation_id, user_id, message, \
             taken, created_at) SELECT ?1, ?2, ?3, m.id, d.taken, ?5 FROM messages m \
             JOIN deviceless d ON d.message = m.id AND d.conversation_id = ?2 AND d.user_id = ?3 \
             WHERE m.conversation_id = ?2 AND m.message_id = ?4",
            params![
                share.as_bytes().as_slice(),
                conversation.as_bytes().as_slice(),
                user.as_bytes().as_slice(),
                record.id.as_bytes().as_slice(),
                tx.now(),
            ],
        )?;
    }
    Ok(shared)
}

/// The client uploaded the catch-up `share_id` that this device made for `user_id` in
/// `conversation_id`, and posted its keys: the notes of the messages it carried go, those of any
/// other message stay for the next catch-up. One this device didn't make for them, or one already
/// delivered, is `not_found` (`share`).
pub(crate) fn catch_up_delivered(tx: &Tx<'_>, request: CatchUpDelivered) -> Result<Empty, Error> {
    let (conversation, user, share) = (
        request.conversation_id.as_bytes().as_slice(),
        request.user_id.as_bytes().as_slice(),
        request.share_id.as_bytes().as_slice(),
    );
    // A note taken again since the package was made (an edit) has more to bring: it stays.
    tx.conn().execute(
        "DELETE FROM deviceless WHERE conversation_id = ?1 AND user_id = ?2 AND EXISTS \
         (SELECT 1 FROM catch_ups c WHERE c.share_id = ?3 AND c.conversation_id = ?1 \
         AND c.user_id = ?2 AND c.message = deviceless.message AND c.taken = deviceless.taken)",
        params![conversation, user, share],
    )?;
    let delivered = tx.conn().execute(
        "DELETE FROM catch_ups WHERE share_id = ?3 AND conversation_id = ?1 AND user_id = ?2",
        params![conversation, user, share],
    )?;
    if delivered == 0 {
        return Err(not_found("share"));
    }
    Ok(Empty {})
}

/// This device, sending a package of `conversation` to `to` (`field`): another user than its
/// own, and a member of the conversation as its group last had it.
fn sharing_with(
    tx: &Tx<'_>,
    conversation: Uuid,
    to: Uuid,
    field: &str,
) -> Result<OwnDevice, Error> {
    let row = GroupRow::read(tx, conversation)?.ok_or_else(|| not_found("group"))?;
    let own = tx.own_device()?;
    if to == own.user {
        return Err(invalid(field, "a package goes to another user"));
    }
    if !row.members.contains(to) {
        return Err(not_found("member"));
    }
    Ok(own)
}

/// The package of the newest `records` that fit, sealed (see [`newest_that_fit`]), with the
/// records it carries.
fn pack<'r>(
    tx: &Tx<'_>,
    own: &OwnDevice,
    header: &Header,
    records: &'r [Record],
    start: i64,
    limit: usize,
    recipients: &[(Uuid, [u8; 32])],
) -> Result<(Shared, &'r [Record]), Error> {
    let (signed, start, first) = newest_that_fit(records, start, limit, |kept| {
        package(&own.signer, header, &deflate(kept)?)
    })?;
    let sealed = seal_for(tx, header.kind, header.conversation, &signed, recipients)?;
    let shared = Shared {
        sealed,
        start,
        truncated: first > 0,
    };
    Ok((shared, &records[first..]))
}

/// The package `build` makes of the newest of `records` (in the order they were sent) that fit:
/// their CBOR within `MAX_RECORDS`, and the package, once sealed, within `limit`. With where its
/// window starts (`start` when they all fit, else just after the newest record left out, so the
/// package holds every record from then on) and the first record it holds: any before were left
/// out.
fn newest_that_fit(
    records: &[Record],
    start: i64,
    limit: usize,
    build: impl Fn(&[Record]) -> Result<Vec<u8>, Error>,
) -> Result<(Vec<u8>, i64, usize), Error> {
    let sizes = records
        .iter()
        .map(|record| to_cbor(record).map(|bytes| bytes.len()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut first = 0;
    let mut kept: usize = sizes.iter().sum();
    while first < records.len() && kept + ARRAY_HEADER > MAX_RECORDS {
        kept -= sizes[first];
        first += 1;
    }
    loop {
        let package = build(&records[first..])?;
        let sealed = sealed_len(package.len());
        if sealed <= limit {
            let start = match first.checked_sub(1) {
                Some(last_out) => i64::try_from(records[last_out].sent)
                    .unwrap_or(i64::MAX)
                    .saturating_add(1),
                None => start,
            };
            return Ok((package, start, first));
        }
        if first == records.len() {
            return Err(Error::TooLarge {
                limit: limit as u64,
            });
        }
        // What the cap takes of these records, by how far over they are, a tenth less: one fewer
        // at least.
        let target = (kept as u128 * limit as u128 * 9 / (sealed as u128 * 10)) as usize;
        loop {
            kept -= sizes[first];
            first += 1;
            if first == records.len() || kept <= target {
                break;
            }
        }
    }
}

/// What `len` bytes take sealed: each part of 1 MiB gains its tag.
fn sealed_len(len: usize) -> usize {
    len + TAG * len.div_ceil(PACKAGE_PART).max(1)
}

/// `records`' CBOR, deflated.
fn deflate(records: &[Record]) -> Result<Vec<u8>, Error> {
    Ok(miniz_oxide::deflate::compress_to_vec(
        &to_cbor(&records)?,
        COMPRESSION,
    ))
}

/// A package: `header` and `records` (their CBOR, deflated), signed by `signer`, the key of the
/// device the header names.
pub fn package(signer: &impl Signer, header: &Header, records: &[u8]) -> Result<Vec<u8>, Error> {
    let body = to_cbor(&BodyOut {
        v: 1,
        header,
        records,
    })?;
    sign(HISTORY_SHARE, body, signer)
        .map_err(|_| Error::Internal("a package couldn't be signed".into()))
}

/// Seals `package`, a package of `conversation`, for `to`: in parts under a new key, which goes to
/// each device `devices` certifies (their certificates, as the server serves them) as a direct
/// message of `kind`'s type, from this device. Each certificate must be one the identity this
/// device pins for `to` signed, of a device on `to`'s latest list: else `wrong_user`,
/// `invalid_signature` (`certificate`) or `device_not_listed`; without that identity,
/// `needs_identities`.
pub fn seal(
    tx: &Tx<'_>,
    kind: ShareKind,
    conversation: Uuid,
    to: Uuid,
    package: &[u8],
    devices: &[Vec<u8>],
) -> Result<Sealed, Error> {
    let recipients = recipients(tx, to, devices)?;
    seal_for(tx, kind, conversation, package, &recipients)
}

/// The devices of `to` that `devices` certify, each once, with their HPKE keys.
fn recipients(tx: &Tx<'_>, to: Uuid, devices: &[Vec<u8>]) -> Result<Vec<(Uuid, [u8; 32])>, Error> {
    if devices.is_empty() {
        return Err(invalid("devices", "a package goes to at least one device"));
    }
    let identity = tx.identity_of(to)?.ok_or_else(|| Error::NeedsIdentities {
        users: vec![to.to_string()],
    })?;
    let list = tx.device_list_of(to)?;
    let mut found = BTreeMap::new();
    for signed in devices {
        let claimed = DeviceCertificate::read_unverified(signed).map_err(|_| signature())?;
        if claimed.user != to {
            return Err(rule("wrong_user"));
        }
        // What this device knows of `to` may be what refuses the certificate: it observes them
        // anew first, once for each state of that knowledge.
        let entry = Sha256::digest(signed);
        let Ok(certificate) = DeviceCertificate::verify(signed, &identity) else {
            ask_first(tx, &entry, BTreeSet::from([to]))?;
            return Err(signature());
        };
        if !list
            .as_ref()
            .is_some_and(|list| list.contains(certificate.device))
        {
            ask_first(tx, &entry, BTreeSet::from([to]))?;
            return Err(rule("device_not_listed"));
        }
        let hpke = stored_key(&certificate.hpke_key)?;
        if *found.entry(certificate.device).or_insert(hpke) != hpke {
            return Err(invalid(
                "devices",
                "a device's certificates give it different keys",
            ));
        }
    }
    Ok(found.into_iter().collect())
}

/// Seals `package` in parts under a new key, which goes to each of `recipients`, sealed to their
/// HPKE keys and signed by this device, with the package's ID and `conversation`.
fn seal_for(
    tx: &Tx<'_>,
    kind: ShareKind,
    conversation: Uuid,
    package: &[u8],
    recipients: &[(Uuid, [u8; 32])],
) -> Result<Sealed, Error> {
    let own = tx.own_device()?;
    let provider = tx.provider();
    // A v7 ID, as the API's, which it orders by: the server knows when a package came anyway.
    let mut counter = [0u8; 10];
    counter.copy_from_slice(&random(provider.rand(), 10)?);
    let millis = u64::try_from(tx.now()).unwrap_or(0);
    let share_id = uuid::Builder::from_unix_timestamp_millis(millis, &counter).into_uuid();
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&random(provider.rand(), 32)?);

    let mut chunks: Vec<&[u8]> = package.chunks(PACKAGE_PART).collect();
    if chunks.is_empty() {
        chunks.push(&[]);
    }
    let last = chunks.len() - 1;
    let parts: Vec<Vec<u8>> = chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| seal_part(&key, share_id, index as u64, index == last, chunk))
        .collect();
    let size = parts.iter().map(|part| part.len() as u64).sum();

    let mut payload = Zeroizing::new(Vec::with_capacity(KEY_PAYLOAD));
    ciborium::into_writer(
        &KeyPayload {
            v: 1,
            share: share_id,
            conversation,
            key,
        },
        &mut *payload,
    )
    .map_err(|_| Error::Internal("a CBOR value couldn't be written".into()))?;
    let keys = recipients
        .iter()
        .map(|&(device, hpke)| {
            let message = DirectMessage::seal(
                provider,
                &own.signer,
                own.device,
                device,
                &hpke,
                kind.key_type(),
                &payload,
            )?;
            Ok(SealedKey {
                device_id: device,
                message,
            })
        })
        .collect::<Result<_, Error>>()?;
    Ok(Sealed {
        share_id,
        parts,
        size,
        keys,
    })
}

/// A package's key, which another device sent this one, as `receive_direct` takes it. Its sender,
/// `from_certificate`, must be a device whose certificate the identity this device pins (or holds)
/// for its user signed, on that user's latest list, and the sender must have signed the message.
/// The key is kept for `history_import`, with the sender's signature key, which must have signed
/// the package. The same key again is taken again; another under the same package is `exists`.
pub(crate) fn receive_key(
    tx: &Tx<'_>,
    kind: ShareKind,
    message: &[u8],
    from_certificate: Option<&[u8]>,
) -> Result<KeyReceived, Error> {
    let own = tx.own_device()?;
    let (_, from) = DirectMessage::header(message)?;
    let signed = from_certificate.ok_or_else(|| {
        invalid(
            "from_certificate",
            "a package's key needs its sender's certificate",
        )
    })?;
    let claimed = DeviceCertificate::read_unverified(signed).map_err(|_| signature())?;
    let identity = tx
        .identity_of(claimed.user)?
        .ok_or_else(|| Error::NeedsIdentities {
            users: vec![claimed.user.to_string()],
        })?;
    // What this device knows of the sender's user may be what refuses the sender (an identity or a
    // list it hasn't observed yet, as after a long absence): it observes them anew first, once for
    // each state of that knowledge, and only then refuses.
    let entry = Sha256::digest(message);
    let Ok(sender) = DeviceCertificate::verify(signed, &identity) else {
        ask_first(tx, &entry, BTreeSet::from([claimed.user]))?;
        return Err(signature());
    };
    if sender.device != from {
        return Err(rule("wrong_device"));
    }
    let listed = tx
        .device_list_of(sender.user)?
        .is_some_and(|list| list.contains(sender.device));
    if !listed {
        ask_first(tx, &entry, BTreeSet::from([sender.user]))?;
        return Err(rule("device_not_listed"));
    }
    let signature_key = stored_key(&sender.signature_key)?;
    let (_, payload) = DirectMessage::open(
        tx.provider(),
        &own.hpke.private,
        own.device,
        from,
        &signature_key,
        message,
    )?;
    let payload = read_key(&payload)?;
    // A key whose package the server no longer keeps opens nothing any more.
    tx.conn().execute(
        "DELETE FROM history_keys WHERE received_at < ?1",
        [tx.now().saturating_sub(PACKAGE_KEPT_MS)],
    )?;
    let kept = StoredKey {
        kind,
        conversation: payload.conversation,
        user: sender.user,
        device: sender.device,
        signature_key,
        key: payload.key,
    };
    let inserted = tx.conn().execute(
        "INSERT INTO history_keys (share_id, kind, conversation_id, user_id, device_id, \
         signature_key, key, received_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
         ON CONFLICT (share_id) DO NOTHING",
        params![
            payload.share.as_bytes().as_slice(),
            kind.name(),
            kept.conversation.as_bytes().as_slice(),
            kept.user.as_bytes().as_slice(),
            kept.device.as_bytes().as_slice(),
            kept.signature_key.as_slice(),
            kept.key.as_slice(),
            tx.now(),
        ],
    )?;
    if inserted == 0 && StoredKey::read(tx, payload.share)?.as_ref() != Some(&kept) {
        return Err(Error::Exists {
            what: "share".into(),
        });
    }
    Ok(KeyReceived {
        share_id: payload.share,
        conversation_id: kept.conversation,
        user_id: kept.user,
    })
}

/// A key's payload, read through a scratch buffer that's wiped after.
fn read_key(payload: &[u8]) -> Result<KeyPayload, Error> {
    let mut scratch = Zeroizing::new([0u8; 256]);
    let mut bytes = payload;
    let read: KeyPayload = ciborium::de::from_reader_with_buffer(&mut bytes, &mut scratch[..])
        .map_err(|_| unreadable())?;
    if read.v != 1 || !bytes.is_empty() {
        return Err(unreadable());
    }
    Ok(read)
}

/// A package's key as this device keeps it.
#[derive(PartialEq, Eq)]
struct StoredKey {
    kind: ShareKind,
    conversation: Uuid,
    user: Uuid,
    device: Uuid,
    signature_key: [u8; 32],
    key: Zeroizing<[u8; 32]>,
}

impl StoredKey {
    fn read(tx: &Tx<'_>, share: Uuid) -> Result<Option<StoredKey>, Error> {
        type Columns = (
            String,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Zeroizing<Vec<u8>>,
        );
        let columns: Option<Columns> = tx
            .conn()
            .query_row(
                "SELECT kind, conversation_id, user_id, device_id, signature_key, key \
                 FROM history_keys WHERE share_id = ?1",
                [share.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        Zeroizing::new(row.get(5)?),
                    ))
                },
            )
            .optional()?;
        let Some((kind, conversation, user, device, signature_key, key)) = columns else {
            return Ok(None);
        };
        let mut sized = Zeroizing::new([0u8; 32]);
        if key.len() != sized.len() {
            return Err(stored());
        }
        sized.copy_from_slice(&key);
        Ok(Some(StoredKey {
            kind: ShareKind::from_name(&kind)?,
            conversation: stored_uuid(&conversation)?,
            user: stored_uuid(&user)?,
            device: stored_uuid(&device)?,
            signature_key: stored_key(&signature_key)?,
            key: sized,
        }))
    }
}

/// A package whose key this device took: opened, its signature verified with the key of the device
/// that sent the key, its header checked against what that key said, and its records imported as
/// shared by its user. The package's user must be a member of the conversation as this device's
/// group has it (`user_not_member`). How many records changed something.
pub(crate) fn history_import(tx: &Tx<'_>, request: HistoryImport) -> Result<Imported, Error> {
    let stored = StoredKey::read(tx, request.share_id)?.ok_or_else(|| not_found("share"))?;
    let row = GroupRow::read(tx, stored.conversation)?.ok_or_else(|| not_found("group"))?;
    if !row.members.contains(stored.user) {
        return Err(rule("user_not_member"));
    }
    let own = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    let package = open_parts(&stored.key, request.share_id, request.parts)?;
    let signed =
        verify(HISTORY_SHARE, &package, &stored.signature_key).map_err(|error| match error {
            RuleViolation::InvalidSignature => Error::InvalidSignature {
                what: "history share".into(),
            },
            _ => unreadable(),
        })?;
    drop(package);
    let body: Body = from_cbor(&signed)
        .filter(|body: &Body| body.v == 1)
        .ok_or_else(unreadable)?;
    drop(signed);
    let expected = Header {
        kind: stored.kind,
        conversation: stored.conversation,
        user: stored.user,
        device: stored.device,
        to: own,
    };
    if body.header != expected {
        return Err(rule("share_mismatch"));
    }
    let imported = import_records(tx, stored.conversation, stored.user, &body.records)?;
    // The key is used up: kept, it would open the server's copy of the package again, a message
    // deleted since included.
    tx.conn().execute(
        "DELETE FROM history_keys WHERE share_id = ?1",
        [request.share_id.as_bytes().as_slice()],
    )?;
    Ok(Imported { imported })
}

/// The package `parts` hold, opened with `key` and bound to `share`: 64 MiB of them at most, each
/// in its place by its size (every part but the last 1 MiB whole). A part that's not, or doesn't
/// open, is `decrypt_failed` (`history`).
fn open_parts(key: &[u8; 32], share: Uuid, parts: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let total: usize = parts.iter().map(Vec::len).sum();
    if total > MAX_PACKAGE {
        return Err(Error::TooLarge {
            limit: MAX_PACKAGE as u64,
        });
    }
    let last = parts.len().checked_sub(1).ok_or_else(unreadable)?;
    let mut package = Vec::with_capacity(total);
    for (index, sealed) in parts.into_iter().enumerate() {
        let (is_last, index) = (index == last, index as u64);
        let len = sealed.len().checked_sub(TAG).ok_or_else(unreadable)?;
        if !fits(PACKAGE_PART, index, is_last, len) {
            return Err(unreadable());
        }
        let plain = open_part(key, share, index, is_last, &sealed).map_err(|_| unreadable())?;
        package.extend_from_slice(&plain);
    }
    Ok(package)
}

/// Imports the records `deflated` holds as shared by `sharer`, one at a time as they inflate: what
/// this holds is one record, never the list. Once more than `MAX_RECORDS` bytes inflated, it's
/// `too_large`, and nothing more is inflated; a stream that isn't DEFLATE, or what it inflates to
/// that isn't one list of records and nothing after, is `decrypt_failed` (`history`). Either undoes
/// what was imported, with the rest of the command. How many records changed something.
fn import_records(
    tx: &Tx<'_>,
    conversation: Uuid,
    sharer: Uuid,
    deflated: &[u8],
) -> Result<usize, Error> {
    let mut inflater = Inflater {
        state: InflateState::new_boxed(DataFormat::Raw),
        input: deflated,
        inflated: 0,
        limit: MAX_RECORDS,
        ended: false,
        over: false,
    };
    let refused = |inflater: &Inflater<'_>| {
        if inflater.over {
            Error::TooLarge {
                limit: MAX_RECORDS as u64,
            }
        } else {
            unreadable()
        }
    };
    let count = array_len(&mut inflater).map_err(|_| refused(&inflater))?;
    let mut imported = 0;
    for _ in 0..count {
        let record: Record =
            ciborium::from_reader(&mut inflater).map_err(|_| refused(&inflater))?;
        imported += import(
            tx,
            conversation,
            std::slice::from_ref(&record),
            Some(sharer),
        )?;
    }
    if !inflater.finished() {
        return Err(unreadable());
    }
    Ok(imported)
}

/// The length of the CBOR array `reader` begins with: a definite one, as this core writes its
/// lists of records.
fn array_len(reader: &mut impl Read) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first)?;
    let (major, info) = (first[0] >> 5, first[0] & 0x1f);
    if major != 4 {
        return Err(io::Error::other("not an array"));
    }
    let width = match info {
        0..=23 => return Ok(u64::from(info)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(io::Error::other("not an array of a stated length")),
    };
    let mut length = [0u8; 8];
    reader.read_exact(&mut length[8 - width..])?;
    Ok(u64::from_be_bytes(length))
}

/// What a raw DEFLATE stream inflates to, as it's read, until more than `limit` bytes inflated.
struct Inflater<'a> {
    state: Box<InflateState>,
    input: &'a [u8],
    inflated: usize,
    limit: usize,
    ended: bool,
    over: bool,
}

impl Inflater<'_> {
    /// Whether the stream ended, with nothing after it, and nothing it inflated was left unread.
    fn finished(&mut self) -> bool {
        matches!(self.read(&mut [0u8]), Ok(0)) && self.ended && self.input.is_empty()
    }
}

impl Read for Inflater<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.ended || buf.is_empty() {
            return Ok(0);
        }
        // One byte past the limit tells it's passed.
        let room = buf.len().min(self.limit - self.inflated + 1);
        let step = inflate(&mut self.state, self.input, &mut buf[..room], MZFlush::None);
        self.input = &self.input[step.bytes_consumed..];
        self.inflated += step.bytes_written;
        if self.inflated > self.limit {
            self.over = true;
            return Err(io::Error::other("over the limit"));
        }
        match step.status {
            Ok(MZStatus::StreamEnd) => self.ended = true,
            Ok(_) => {}
            Err(_) => return Err(io::Error::other("not a DEFLATE stream")),
        }
        Ok(step.bytes_written)
    }
}

/// Each binary value of a list in base64.
fn base64_each<S: Serializer>(values: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_seq(values.iter().map(|value| STANDARD.encode(value)))
}

/// Secret bytes in CBOR, kept where they're wiped as they drop.
mod secret {
    use serde::{Deserializer, Serializer};
    use zeroize::Zeroizing;

    pub(super) fn serialize<S: Serializer>(
        bytes: &Zeroizing<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&bytes[..])
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        serde_bytes::deserialize(deserializer).map(Zeroizing::new)
    }
}

fn rule(name: &str) -> Error {
    Error::RuleViolation { rule: name.into() }
}

fn signature() -> Error {
    Error::InvalidSignature {
        what: "certificate".into(),
    }
}

/// A part that doesn't open, or a package or a key's payload that opens but isn't one.
fn unreadable() -> Error {
    Error::DecryptFailed {
        kind: "history".into(),
    }
}

fn stored() -> Error {
    Error::Internal("a stored package key is malformed".into())
}
