//! The encrypted backup: each conversation's messages and edits, one segment per UTC day, which the
//! user's backup key encrypts: `{v: 1, key_id, user, conversation, day, complete, nonce, ct}`. The
//! key of a segment is HKDF of the backup key with the info "duvet segment v1" || conversation ||
//! day, its associated data the CBOR of its header without `ct`, and what it holds the deflate of
//! its records' CBOR. Files aren't in it: each message's envelope holds its files' keys.
//!
//! Which days to upload: the database marks a day's segment changed whenever a message or an edit of
//! it is written, changed or dropped (`segments` and its triggers), a deletion the day of the message
//! and those of its edits with it. A day is due once it ends in UTC, while it changed since the
//! server last held what this device holds of it, or while this device holds it complete and the
//! server's copy isn't. A day is complete when this device was in the conversation's group from its
//! start to its end (`memberships`, which `apply` and `commit_result` keep, by the time the API took
//! each entry) and holds everything of it: no message it couldn't open, no edit it can't carry.

use std::fmt;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use miniz_oxide::inflate::TINFLStatus;
use openmls_traits::OpenMlsProvider;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{
    BACKUP_KEY, from_cbor, invalid, meta_get, not_found, random, stored_uuid, to_cbor,
};
use crate::messages::{self, Empty, Record, RecordKind};
use crate::protocol::b64;
use crate::{Error, Tx, recovery};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const SEGMENT_INFO: &[u8] = b"duvet segment v1";
const NONCE: usize = 12;
const KEY_ID: usize = 8;
/// miniz_oxide's level for a segment's deflate.
const LEVEL: u8 = 6;

/// The most records' CBOR a segment holds before its deflate, built or imported: 256 MiB.
const MAX_SEGMENT: usize = 256 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub(crate) struct SegmentDay {
    conversation_id: Uuid,
    day: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Uploaded {
    conversation_id: Uuid,
    day: String,
    /// Whether the copy the server holds now is complete.
    complete: bool,
    /// The day's version the uploaded build was of, as `backup_segment` answered it.
    version: i64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SegmentData {
    #[serde(with = "b64")]
    data: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct DueDays {
    segments: Vec<DueDay>,
}

#[derive(Serialize)]
struct DueDay {
    conversation_id: Uuid,
    day: String,
    complete: bool,
}

#[derive(Serialize)]
pub(crate) struct Built {
    #[serde(with = "b64")]
    data: Vec<u8>,
    #[serde(with = "b64")]
    key_id: Vec<u8>,
    complete: bool,
    /// The day's version this build holds, for `backup_uploaded` once it's uploaded.
    version: i64,
}

#[derive(Serialize)]
pub(crate) struct Imported {
    imported: usize,
}

#[derive(Serialize)]
pub(crate) struct Reencrypted {
    #[serde(with = "b64")]
    data: Vec<u8>,
    #[serde(with = "b64")]
    key_id: Vec<u8>,
}

/// The days to upload, by conversation and oldest first: each one that ended (in UTC, by the core's
/// clock) while it changed since the server last held what this device holds of it, or while this
/// device holds it complete and the server's copy isn't. A day with nothing to carry that the server
/// holds nothing of, as far as this device knows, isn't one.
pub(crate) fn backup_due(tx: &Tx<'_>) -> Result<DueDays, Error> {
    let today = Day::of(tx.now());
    let rows = {
        let mut statement = tx.conn().prepare(
            "SELECT conversation_id, day, dirty, uploaded FROM segments \
             WHERE dirty = 1 OR uploaded IS NOT 1 ORDER BY conversation_id, day",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Option<bool>>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut segments = Vec::new();
    for (conversation, text, dirty, uploaded) in rows {
        // Only a day that ended; and none the database couldn't write as a date, which no message's
        // time has.
        let Some(day) = Day::parse(&text).filter(|day| *day < today) else {
            continue;
        };
        let conversation = stored_uuid(&conversation)?;
        let complete = complete(tx, conversation, day)?;
        if !dirty && !(complete && uploaded != Some(true)) {
            continue;
        }
        if uploaded.is_none() && carried(tx, conversation, day)?.is_empty() {
            continue;
        }
        segments.push(DueDay {
            conversation_id: conversation,
            day: text,
            complete,
        });
    }
    Ok(DueDays { segments })
}

/// The segment of `conversation`'s `day`, sealed with the backup key: what this device carries of
/// the day (its messages as they were sent, and their edits), whether it holds the day whole, and the
/// day's version it holds, which `backup_uploaded` takes back once the segment is uploaded. The client
/// imports the server's copy of the day first, when there's one: then the build holds all of it but
/// what this device holds deleted, and a complete copy imported makes this device hold the day whole.
pub(crate) fn backup_segment(tx: &Tx<'_>, request: SegmentDay) -> Result<Built, Error> {
    let day = parse_day(&request.day)?;
    let text = day.to_string();
    let conversation = request.conversation_id;
    let user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    let backup_key = current_key(tx)?.ok_or_else(|| not_found("backup_key"))?;
    let version: i64 = tx
        .conn()
        .query_row(
            "SELECT version FROM segments WHERE conversation_id = ?1 AND day = ?2",
            params![conversation.as_bytes().as_slice(), text],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let complete = complete(tx, conversation, day)?;
    let plain = Zeroizing::new(to_cbor(&carried(tx, conversation, day)?)?);
    if plain.len() > MAX_SEGMENT {
        return Err(Error::TooLarge {
            limit: MAX_SEGMENT as u64,
        });
    }
    let deflated = Zeroizing::new(miniz_oxide::deflate::compress_to_vec(&plain, LEVEL));
    let key_id = recovery::key_id(&backup_key);
    let data = seal(
        tx,
        &backup_key,
        Header {
            v: 1,
            key_id: &key_id,
            user,
            conversation,
            day: &text,
            complete,
            nonce: &[],
        },
        &deflated,
    )?;
    Ok(Built {
        data,
        key_id: key_id.to_vec(),
        complete,
        version,
    })
}

/// The server holds `conversation`'s `day` now, as `backup_segment` built it at `version` and the
/// client uploaded it, complete or not. The day isn't due any more, unless it changed since that
/// build: an older build's upload leaves a newer change due.
pub(crate) fn backup_uploaded(tx: &Tx<'_>, request: Uploaded) -> Result<Empty, Error> {
    let day = parse_day(&request.day)?.to_string();
    tx.conn().execute(
        "INSERT INTO segments (conversation_id, day, dirty, uploaded) VALUES (?1, ?2, 0, ?3) \
         ON CONFLICT (conversation_id, day) DO UPDATE SET uploaded = excluded.uploaded, \
         dirty = dirty AND version != ?4",
        params![
            request.conversation_id.as_bytes().as_slice(),
            day,
            request.complete,
            request.version
        ],
    )?;
    Ok(Empty {})
}

/// Brings in a segment of the user's backup, as the server holds it, under the backup key or one
/// before it: what this device lacks of the day, never overwriting what it has, and a message it
/// holds deleted stays deleted. How many records changed something. The segment counts as the
/// server's copy of the day: the day isn't due when this device holds the same as it, and is when it
/// holds more or other than it.
pub(crate) fn backup_import(tx: &Tx<'_>, request: SegmentData) -> Result<Imported, Error> {
    let opened = open(tx, &request.data)?;
    let conversation = opened.wire.conversation;
    let (start, end) = opened.day.bounds();
    let all = records_in(&opened.deflated, MAX_SEGMENT)?;
    // A record outside the segment's day isn't the day's: it's left out, and the day is due again,
    // to upload without it.
    let records: Vec<Record> = all
        .iter()
        .filter(|record| i64::try_from(record.sent).is_ok_and(|sent| start <= sent && sent < end))
        .cloned()
        .collect();
    let imported = messages::import(tx, conversation, &records, None)?;
    let same =
        records.len() == all.len() && same_records(carried(tx, conversation, opened.day)?, records);
    tx.conn().execute(
        "INSERT INTO segments (conversation_id, day, dirty, uploaded, held) \
         VALUES (?1, ?2, ?3, ?4, ?4) ON CONFLICT (conversation_id, day) DO UPDATE SET \
         dirty = excluded.dirty, uploaded = excluded.uploaded, held = held OR excluded.held",
        params![
            conversation.as_bytes().as_slice(),
            opened.day.to_string(),
            !same,
            opened.wire.complete
        ],
    )?;
    Ok(Imported { imported })
}

/// A segment of the user's backup sealed anew with the current backup key, the same day and records
/// in it: after a rotation, a device that kept the keys before it moves the backup to the new key,
/// segment by segment, each segment saying which key it's under meanwhile.
pub(crate) fn backup_reencrypt(tx: &Tx<'_>, request: SegmentData) -> Result<Reencrypted, Error> {
    let opened = open(tx, &request.data)?;
    let backup_key = current_key(tx)?.ok_or_else(|| not_found("backup_key"))?;
    let key_id = recovery::key_id(&backup_key);
    let wire = &opened.wire;
    let data = seal(
        tx,
        &backup_key,
        Header {
            v: 1,
            key_id: &key_id,
            user: wire.user,
            conversation: wire.conversation,
            day: &wire.day,
            complete: wire.complete,
            nonce: &[],
        },
        &opened.deflated,
    )?;
    Ok(Reencrypted {
        data,
        key_id: key_id.to_vec(),
    })
}

/// What an entry of `conversation`'s queue shows of this device's place in its group, by whether it
/// held the group before the entry and holds it after, and when the API took the entry: it entered
/// then (a welcome brought it in), it was still in then, or it left then (a commit took it out). An
/// entry without that time shows no more than what it did, and one that brings the device in, that
/// it entered by the core's clock.
pub(crate) fn followed(
    tx: &Tx<'_>,
    conversation: Uuid,
    held: bool,
    holds: bool,
    sent_at: Option<i64>,
) -> Result<(), Error> {
    let id = conversation.as_bytes().as_slice();
    match (held, holds, sent_at) {
        (false, true, _) => entered(tx, conversation, sent_at.unwrap_or_else(|| tx.now())),
        (true, true, Some(at)) => {
            tx.conn().execute(
                "UPDATE memberships SET seen_until = max(seen_until, ?2) \
                 WHERE conversation_id = ?1 AND open = 1",
                params![id, at],
            )?;
            Ok(())
        }
        (true, false, _) => {
            tx.conn().execute(
                "UPDATE memberships SET seen_until = max(seen_until, coalesce(?2, seen_until)), \
                 open = 0 WHERE conversation_id = ?1 AND open = 1",
                params![id, sent_at],
            )?;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// This device entered `conversation`'s group at `at`: a stay of its own begins then, and one it
/// still had there ends where it was last seen in.
pub(crate) fn entered(tx: &Tx<'_>, conversation: Uuid, at: i64) -> Result<(), Error> {
    let id = conversation.as_bytes().as_slice();
    tx.conn().execute(
        "UPDATE memberships SET open = 0 WHERE conversation_id = ?1 AND open = 1",
        [id],
    )?;
    tx.conn().execute(
        "INSERT INTO memberships (conversation_id, entered_at, seen_until) VALUES (?1, ?2, ?2)",
        params![id, at],
    )?;
    Ok(())
}

/// Whether this device holds `conversation`'s `day` whole: in the group from the day's start to its
/// end, as far as it applied the queue, or with a complete copy of the day imported; and with no
/// message of the day it couldn't open, nor an edit of the day it can't carry (one of a message it
/// doesn't show).
fn complete(tx: &Tx<'_>, conversation: Uuid, day: Day) -> Result<bool, Error> {
    let (start, end) = day.bounds();
    Ok(tx.conn().query_row(
        "SELECT (EXISTS (SELECT 1 FROM memberships WHERE conversation_id = ?1 \
             AND entered_at <= ?2 AND seen_until >= ?3) \
             OR EXISTS (SELECT 1 FROM segments WHERE conversation_id = ?1 AND day = ?4 \
             AND held = 1)) \
         AND NOT EXISTS (SELECT 1 FROM messages WHERE conversation_id = ?1 \
             AND status = 'waiting' AND sent_at >= ?2 AND sent_at < ?3) \
         AND NOT EXISTS (SELECT 1 FROM edits e WHERE e.conversation_id = ?1 \
             AND e.seq IS NOT NULL AND e.sent_at >= ?2 AND e.sent_at < ?3 \
             AND NOT EXISTS (SELECT 1 FROM messages m WHERE m.message_id = e.message_id \
                 AND m.conversation_id = e.conversation_id AND m.status = 'ok' \
                 AND m.deleted = 0))",
        params![
            conversation.as_bytes().as_slice(),
            start,
            end,
            day.to_string()
        ],
        |row| row.get(0),
    )?)
}

/// What a segment of `conversation`'s `day` carries.
fn carried(tx: &Tx<'_>, conversation: Uuid, day: Day) -> Result<Vec<Record>, Error> {
    let (start, end) = day.bounds();
    messages::records_for(tx, conversation, start, end)
}

/// Whether two sets of records are the same, in whatever order.
fn same_records(mut held: Vec<Record>, mut other: Vec<Record>) -> bool {
    type Order<'a> = (
        u64,
        u64,
        bool,
        Uuid,
        Uuid,
        Uuid,
        &'a [u8],
        Option<Uuid>,
        Option<Uuid>,
    );
    fn order(record: &Record) -> Order<'_> {
        (
            record.sent,
            record.seq,
            record.kind == RecordKind::Edit,
            record.id,
            record.user,
            record.device,
            &record.envelope,
            record.shared_by,
            record.reply_to,
        )
    }
    held.sort_by(|a, b| order(a).cmp(&order(b)));
    other.sort_by(|a, b| order(a).cmp(&order(b)));
    held == other
}

/// A segment: `{v: 1, key_id, user, conversation, day, complete, nonce, ct}`.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    v: u32,
    #[serde(with = "serde_bytes")]
    key_id: Vec<u8>,
    user: Uuid,
    conversation: Uuid,
    day: String,
    complete: bool,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

/// A segment's header: its fields but `ct`, whose CBOR is its associated data.
#[derive(Serialize)]
struct Header<'a> {
    v: u32,
    #[serde(with = "serde_bytes")]
    key_id: &'a [u8],
    user: Uuid,
    conversation: Uuid,
    day: &'a str,
    complete: bool,
    #[serde(with = "serde_bytes")]
    nonce: &'a [u8],
}

/// The segment of `header`, holding `deflated` (the deflate of its records' CBOR), sealed with
/// `backup_key` under a new nonce, which takes the header's place.
fn seal(
    tx: &Tx<'_>,
    backup_key: &[u8; 32],
    header: Header<'_>,
    deflated: &[u8],
) -> Result<Vec<u8>, Error> {
    let nonce = random(tx.provider().rand(), NONCE)?;
    let header = Header {
        nonce: nonce.as_slice(),
        ..header
    };
    let ct = cipher(backup_key, header.conversation, header.day)?
        .encrypt(
            Nonce::from_slice(header.nonce),
            Payload {
                msg: deflated,
                aad: &to_cbor(&header)?,
            },
        )
        .map_err(|_| Error::Internal("AES-256-GCM couldn't encrypt".into()))?;
    to_cbor(&Wire {
        v: header.v,
        key_id: header.key_id.to_vec(),
        user: header.user,
        conversation: header.conversation,
        day: header.day.to_owned(),
        complete: header.complete,
        nonce: header.nonce.to_vec(),
        ct,
    })
}

/// A segment this device opened: its header, its day, and what it holds.
struct Opened {
    wire: Wire,
    day: Day,
    deflated: Zeroizing<Vec<u8>>,
}

/// Opens a segment of this device's user's backup, with the backup key its `key_id` names, the
/// current one or one before it. What isn't a segment this core reads is `bad_command` (`data`); one
/// under a key this device doesn't hold, `not_found` (`backup_key`); one that doesn't open (altered,
/// another user's), `decrypt_failed` (`segment`).
fn open(tx: &Tx<'_>, data: &[u8]) -> Result<Opened, Error> {
    let not_a_segment = || invalid("data", "the data isn't a segment this core reads");
    let wire: Wire = from_cbor(data).ok_or_else(not_a_segment)?;
    if wire.v != 1 || wire.key_id.len() != KEY_ID || wire.nonce.len() != NONCE {
        return Err(not_a_segment());
    }
    let day = Day::parse(&wire.day).ok_or_else(not_a_segment)?;
    let user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
    if wire.user != user {
        return Err(unopened());
    }
    let backup_key = held_key(tx, &wire.key_id)?.ok_or_else(|| not_found("backup_key"))?;
    let header = Header {
        v: wire.v,
        key_id: &wire.key_id,
        user: wire.user,
        conversation: wire.conversation,
        day: &wire.day,
        complete: wire.complete,
        nonce: &wire.nonce,
    };
    let deflated = cipher(&backup_key, wire.conversation, &wire.day)?
        .decrypt(
            Nonce::from_slice(&wire.nonce),
            Payload {
                msg: &wire.ct,
                aad: &to_cbor(&header)?,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| unopened())?;
    Ok(Opened {
        wire,
        day,
        deflated,
    })
}

/// The records `deflated` holds, inflated to `limit` bytes at most: past it, `too_large`.
fn records_in(deflated: &[u8], limit: usize) -> Result<Vec<Record>, Error> {
    let plain = match miniz_oxide::inflate::decompress_to_vec_with_limit(deflated, limit) {
        Ok(plain) => Zeroizing::new(plain),
        Err(mut error) => {
            error.output.zeroize();
            return Err(match error.status {
                TINFLStatus::HasMoreOutput => Error::TooLarge {
                    limit: limit as u64,
                },
                _ => unopened(),
            });
        }
    };
    from_cbor(&plain).ok_or_else(unopened)
}

/// A segment's AES-256-GCM key: HKDF-SHA256 of the backup key, with the info "duvet segment v1" ||
/// conversation || day.
fn cipher(backup_key: &[u8; 32], conversation: Uuid, day: &str) -> Result<Aes256Gcm, Error> {
    let info = [
        SEGMENT_INFO,
        conversation.as_bytes().as_slice(),
        day.as_bytes(),
    ]
    .concat();
    let mut key = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, backup_key)
        .expand(&info, &mut *key)
        .map_err(|_| Error::Internal("a segment's key couldn't be derived".into()))?;
    Aes256Gcm::new_from_slice(&*key)
        .map_err(|_| Error::Internal("AES-256-GCM refused its key".into()))
}

/// The backup key this device holds that `key_id` names: the current one, or one before it.
fn held_key(tx: &Tx<'_>, key_id: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    if let Some(current) = current_key(tx)?
        && recovery::key_id(&current).as_slice() == key_id
    {
        return Ok(Some(current));
    }
    Ok(tx
        .previous_backup_keys()?
        .into_iter()
        .find(|key| recovery::key_id(key).as_slice() == key_id))
}

/// This device's backup key, once it holds the user's identity.
fn current_key(tx: &Tx<'_>) -> Result<Option<Zeroizing<[u8; 32]>>, Error> {
    let Some(stored) = meta_get(tx, BACKUP_KEY)?.map(Zeroizing::new) else {
        return Ok(None);
    };
    let mut key = Zeroizing::new([0u8; 32]);
    if stored.len() != key.len() {
        return Err(Error::Internal("the stored backup key is malformed".into()));
    }
    key.copy_from_slice(&stored);
    Ok(Some(key))
}

fn parse_day(text: &str) -> Result<Day, Error> {
    Day::parse(text).ok_or_else(|| invalid("day", "a day is a UTC date written YYYY-MM-DD"))
}

/// A segment that doesn't open, or holds what a segment doesn't.
fn unopened() -> Error {
    Error::DecryptFailed {
        kind: "segment".into(),
    }
}

/// A UTC day, by its number from 1970-01-01.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Day(i64);

impl Day {
    /// The day `ms`, a Unix time in milliseconds, falls in.
    fn of(ms: i64) -> Day {
        Day(ms.div_euclid(DAY_MS))
    }

    /// Its first millisecond, and the next day's.
    fn bounds(self) -> (i64, i64) {
        let start = self.0.saturating_mul(DAY_MS);
        (start, start.saturating_add(DAY_MS))
    }

    /// The day `YYYY-MM-DD` names, from 0000-01-01 to 9999-12-31: its spelling alone.
    fn parse(text: &str) -> Option<Day> {
        let bytes = text.as_bytes();
        if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
            return None;
        }
        let number = |digits: &[u8]| {
            digits.iter().try_fold(0i64, |number, &digit| {
                digit
                    .is_ascii_digit()
                    .then(|| number * 10 + i64::from(digit - b'0'))
            })
        };
        let (year, month, day) = (
            number(&bytes[..4])?,
            number(&bytes[5..7])?,
            number(&bytes[8..])?,
        );
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        Some(Day(days_from_civil(year, month, day)))
    }
}

impl fmt::Display for Day {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (year, month, day) = civil_from_days(self.0);
        write!(f, "{year:04}-{month:02}-{day:02}")
    }
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// The proleptic Gregorian date of a day number (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let of_era = z.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// The day number of a proleptic Gregorian date (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + of_year;
    era * 146_097 + of_era - 719_468
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    #[test]
    fn days_are_sqlites_utc_dates() {
        // The triggers name a day with SQLite's strftime, the commands with `Day`: they agree, to
        // the millisecond at each day's edges, around leap days and years' ends.
        let conn = Connection::open_in_memory().unwrap();
        let mut instants = vec![0, 1, -1, 1_795_391_999_999, 1_795_392_000_000];
        for (year, month, day) in [
            (1, 1, 1),
            (1900, 2, 28),
            (1900, 3, 1),
            (1969, 12, 31),
            (2000, 2, 29),
            (2000, 3, 1),
            (2024, 2, 29),
            (2026, 11, 23),
            (2026, 12, 31),
            (2027, 1, 1),
            (9999, 12, 31),
        ] {
            let start = days_from_civil(year, month, day) * DAY_MS;
            instants.extend([start - 1, start, start + DAY_MS / 2, start + DAY_MS - 1]);
        }
        for ms in instants {
            let sqlite: String = conn
                .query_row(
                    "SELECT strftime('%Y-%m-%d', ?1 / 1000.0, 'unixepoch')",
                    [ms],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(Day::of(ms).to_string(), sqlite, "{ms}");
            assert_eq!(Day::parse(&sqlite), Some(Day::of(ms)), "{ms}");
            let (start, end) = Day::of(ms).bounds();
            assert!(start <= ms && ms < end && end - start == DAY_MS, "{ms}");
        }
    }

    #[test]
    fn days_read_only_their_own_spelling() {
        for text in [
            "2026-11-23",
            "2024-02-29",
            "2000-02-29",
            "0000-01-01",
            "9999-12-31",
        ] {
            assert_eq!(Day::parse(text).unwrap().to_string(), text);
        }
        for text in [
            "2026-11-31",
            "2025-02-29",
            "1900-02-29",
            "2026-00-10",
            "2026-13-10",
            "2026-11-00",
            "2026-11-2a",
            "+026-11-23",
            "2026/11/23",
            "2026-11-233",
            "2026-1-123",
            "２０２６-11-23",
            "",
        ] {
            assert_eq!(Day::parse(text), None, "{text}");
        }
    }

    #[test]
    fn inflating_stops_at_the_limit() {
        let record = Record {
            kind: RecordKind::Message,
            id: Uuid::from_u128(1),
            seq: 1,
            user: Uuid::from_u128(2),
            device: Uuid::from_u128(3),
            sent: 4,
            envelope: vec![0; 4096],
            shared_by: None,
            reply_to: None,
        };
        let plain = to_cbor(&vec![record.clone()]).unwrap();
        let deflated = miniz_oxide::deflate::compress_to_vec(&plain, LEVEL);
        assert!(deflated.len() < 1024);
        assert!(matches!(
            records_in(&deflated, 1024),
            Err(Error::TooLarge { limit: 1024 })
        ));
        assert_eq!(records_in(&deflated, plain.len()).unwrap(), [record]);
        // What inflates but isn't records, or doesn't inflate, doesn't open.
        let other = miniz_oxide::deflate::compress_to_vec(b"not records", LEVEL);
        assert!(matches!(
            records_in(&other, MAX_SEGMENT),
            Err(Error::DecryptFailed { .. })
        ));
        assert!(matches!(
            records_in(&[0xff; 16], MAX_SEGMENT),
            Err(Error::DecryptFailed { .. })
        ));
    }

    #[test]
    fn records_compare_in_any_order() {
        let record = |seq: u64| Record {
            kind: RecordKind::Message,
            id: Uuid::from_u128(u128::from(seq)),
            seq,
            user: Uuid::from_u128(9),
            device: Uuid::from_u128(9),
            sent: 100,
            envelope: vec![1],
            shared_by: None,
            reply_to: None,
        };
        assert!(same_records(
            vec![record(1), record(2)],
            vec![record(2), record(1)]
        ));
        assert!(!same_records(vec![record(1)], vec![record(1), record(2)]));
        let mut shared = record(1);
        shared.shared_by = Some(Uuid::from_u128(7));
        assert!(!same_records(vec![record(1)], vec![shared]));
    }
}
