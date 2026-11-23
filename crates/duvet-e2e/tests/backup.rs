//! The encrypted backup through `Core::handle`, against a fake of the API: each conversation's UTC
//! days as segments the user's backup key encrypts. A device lists the days due (`backup_due`),
//! builds a day's segment (`backup_segment`) and hears the server holds it (`backup_uploaded`);
//! another device of the user imports it (`backup_import`). A day is complete when the device was in
//! the group from its start to its end and read everything of it; a deletion makes its days due
//! again; and after a rotation the old segments move to the new key (`backup_reencrypt`). The
//! segments are opened here as the contract lays them out, apart from the core's own code.

mod support;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use duvet_e2e::messages::{self, Record, RecordKind};
use duvet_e2e::{Clock, FakeClock, SystemClock, recovery};
use duvet_e2e_rules::Kind;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use support::*;
use uuid::Uuid;

const MINUTE: i64 = 60 * 1000;
const HOUR: i64 = 60 * MINUTE;

/// A segment as the contract lays it out: `{v: 1, key_id, user, conversation, day, complete,
/// nonce, ct}`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
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

/// A segment's header, its associated data: its fields but `ct`, in the same order.
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

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

impl Segment {
    fn read(data: &[u8]) -> Segment {
        ciborium::from_reader(data).expect("a segment")
    }

    fn header(&self) -> Vec<u8> {
        cbor(&Header {
            v: self.v,
            key_id: &self.key_id,
            user: self.user,
            conversation: self.conversation,
            day: &self.day,
            complete: self.complete,
            nonce: &self.nonce,
        })
    }

    /// The AES-256-GCM key of this conversation's day: HKDF of `backup_key`, with the info
    /// "duvet segment v1" || conversation || day.
    fn cipher(&self, backup_key: &[u8; 32]) -> Aes256Gcm {
        let info = [
            b"duvet segment v1".as_slice(),
            self.conversation.as_bytes(),
            self.day.as_bytes(),
        ]
        .concat();
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(None, backup_key)
            .expand(&info, &mut key)
            .unwrap();
        Aes256Gcm::new_from_slice(&key).unwrap()
    }

    /// What it holds, opened with `backup_key`: the deflate of the records' CBOR.
    fn open(&self, backup_key: &[u8; 32]) -> Vec<Record> {
        let deflated = self
            .cipher(backup_key)
            .decrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ct,
                    aad: &self.header(),
                },
            )
            .expect("the segment opens with the key");
        let plain = miniz_oxide::inflate::decompress_to_vec(&deflated).unwrap();
        ciborium::from_reader(plain.as_slice()).unwrap()
    }

    /// The segment sealed anew with `backup_key`, holding `records`, its header as it is.
    fn sealed(self, backup_key: &[u8; 32], records: &[Record]) -> Vec<u8> {
        let plain = cbor(&records.to_vec());
        self.sealed_plain(backup_key, &plain)
    }

    /// The segment sealed anew with `backup_key`, holding the deflate of `plain`, whatever it is.
    fn sealed_plain(mut self, backup_key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
        let deflated = miniz_oxide::deflate::compress_to_vec(plain, 6);
        self.ct = self
            .cipher(backup_key)
            .encrypt(
                Nonce::from_slice(&self.nonce),
                Payload {
                    msg: &deflated,
                    aad: &self.header(),
                },
            )
            .unwrap();
        cbor(&self)
    }
}

/// The UTC date of `ms`, counted day by day from 1970: the test's own reckoning, apart from the
/// core's.
fn utc_day(ms: i64) -> String {
    let leap = |year: i64| (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mut days = ms.div_euclid(DAY_MS);
    let mut year = 1970;
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let february = if leap(year) { 29 } else { 28 };
    let months = [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    while days >= months[month] {
        days -= months[month];
        month += 1;
    }
    format!("{year:04}-{:02}-{:02}", month + 1, days + 1)
}

/// The start of the UTC day after tomorrow by the system's clock: the tests' day. The core's clock
/// never goes behind the system's, which OpenMLS reads for its key packages' lifetimes.
fn test_day() -> i64 {
    (SystemClock.now_ms().div_euclid(DAY_MS) + 2) * DAY_MS
}

/// A DM of A and B, which A1 made at noon the day before `day`: A1 with A's identity (its
/// `create_identity` reply, the recovery key in it), and B1.
struct Dm {
    server: FakeServer,
    conversation: Uuid,
    a: Uuid,
    b: Uuid,
    a1: TestDevice,
    b1: TestDevice,
    identity: Value,
    day: i64,
}

fn dm() -> Dm {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut b1] {
        server.introduce(device);
    }
    let day = test_day();
    server.clock.set(day - 12 * HOUR);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    let command = server.create_group(conversation);
    server
        .commit(&mut a1, conversation, command)
        .expect("the server takes epoch 0");
    server.deliver_all(&mut [&mut a1, &mut b1]);
    Dm {
        server,
        conversation,
        a,
        b,
        a1,
        b1,
        identity,
        day,
    }
}

impl Dm {
    fn at(&mut self, ms: i64) {
        self.server.clock.set(ms);
    }

    /// Every device of the chat applies its queue.
    fn deliver(&mut self) {
        self.server.deliver_all(&mut [&mut self.a1, &mut self.b1]);
    }
}

/// The backup key an identity's reply hands the server, as its recovery key opens it.
fn backup_key_of(user: Uuid, reply: &Value) -> [u8; 32] {
    let recovery_key = recovery::parse(reply["recovery_key"].as_str().unwrap()).unwrap();
    *recovery::unwrap_backup_key(&recovery_key, user, &bytes(&reply["wrapped_backup_key"])).unwrap()
}

/// `device` sends `envelope`, answering `reply_to`, and hears the API's answer: the message's ID.
fn send(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    envelope: Value,
    reply_to: Option<Uuid>,
) -> Uuid {
    let nonce = new_id().to_string();
    let encrypted = ok(
        &mut device.core,
        json!({
            "cmd": "encrypt",
            "conversation_id": conversation,
            "nonce": nonce,
            "envelope": envelope,
        }),
    );
    let ciphertext = bytes(&encrypted["ciphertext"]);
    let (message_id, seq) = server.post_message(device, conversation, &nonce, ciphertext, &[]);
    let mut answer = json!({
        "cmd": "sent",
        "conversation_id": conversation,
        "nonce": nonce,
        "message_id": message_id,
        "seq": seq,
    });
    if let Some(reply_to) = reply_to {
        let queue = &mut server.chats.get_mut(&conversation).unwrap().queue;
        let entry = &mut queue[usize::try_from(seq).unwrap() - 1];
        entry.meta.insert("reply_to".into(), json!(reply_to));
        answer["reply_to"] = json!(reply_to);
    }
    ok(&mut device.core, answer);
    message_id
}

fn say(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid, text: &str) -> Uuid {
    send(server, device, conversation, json!({"text": text}), None)
}

fn edit(
    server: &mut FakeServer,
    device: &mut TestDevice,
    conversation: Uuid,
    message_id: Uuid,
    text: &str,
) {
    let edited = ok(
        &mut device.core,
        json!({"cmd": "edit", "conversation_id": conversation, "message_id": message_id, "text": text}),
    );
    let ciphertext = bytes(&edited["ciphertext"]);
    server.post_change(device, conversation, "edit", message_id, ciphertext);
}

fn delete(server: &mut FakeServer, device: &mut TestDevice, conversation: Uuid, message_id: Uuid) {
    let deleted = ok(
        &mut device.core,
        json!({"cmd": "delete", "conversation_id": conversation, "message_id": message_id}),
    );
    let ciphertext = bytes(&deleted["ciphertext"]);
    server.post_change(device, conversation, "delete", message_id, ciphertext);
}

/// The server hands `device` a copy it can't read of the last entry of `conversation`'s queue, a
/// message: the device keeps it as waiting.
fn hand_unreadable(server: &FakeServer, device: &mut TestDevice, conversation: Uuid) {
    let mut copy = server.entries(conversation).last().unwrap().clone();
    let mut data = bytes(&copy["data"]);
    *data.last_mut().unwrap() ^= 1;
    copy["data"] = json!(b64(&data));
    let taken = ok(
        &mut device.core,
        json!({"cmd": "apply", "conversation_id": conversation, "entries": [copy]}),
    );
    assert_eq!(taken["results"][0]["result"], "undecryptable");
}

/// A file as a message carries it: the file itself isn't in the backup, only what the envelope
/// says of it, its key among it.
fn file() -> Value {
    json!({
        "id": new_id(),
        "key": b64(&[7; 32]),
        "sha256": b64(&[8; 32]),
        "name": "foto.jpg",
        "type": "image/jpeg",
        "size": 48_213,
    })
}

/// The days `backup_due` lists: each one's conversation, day and whether it's complete.
fn due(device: &mut TestDevice) -> Vec<(Uuid, String, bool)> {
    ok(&mut device.core, json!({"cmd": "backup_due"}))["segments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|due| {
            (
                due["conversation_id"].as_str().unwrap().parse().unwrap(),
                due["day"].as_str().unwrap().to_owned(),
                due["complete"].as_bool().unwrap(),
            )
        })
        .collect()
}

fn segment_command(conversation: Uuid, day: &str) -> Value {
    json!({"cmd": "backup_segment", "conversation_id": conversation, "day": day})
}

/// `backup_segment`'s reply for the day.
fn segment(device: &mut TestDevice, conversation: Uuid, day: &str) -> Value {
    ok(&mut device.core, segment_command(conversation, day))
}

/// The server holds the day, complete or not.
fn uploaded(device: &mut TestDevice, conversation: Uuid, day: &str, built: &Value) {
    let reply = ok(
        &mut device.core,
        json!({
            "cmd": "backup_uploaded",
            "conversation_id": conversation,
            "day": day,
            "complete": built["complete"],
            "version": built["version"],
        }),
    );
    assert_eq!(reply, json!({}));
}

/// `device` builds the day's segment, the client uploads it, and the core hears the server holds
/// it: `backup_segment`'s reply.
fn back_up(device: &mut TestDevice, conversation: Uuid, day: &str) -> Value {
    let built = segment(device, conversation, day);
    uploaded(device, conversation, day, &built);
    built
}

fn import_command(data: &Value) -> Value {
    json!({"cmd": "backup_import", "data": data})
}

/// How many records of the segment `data` changed something on `device`.
fn imported(device: &mut TestDevice, data: &Value) -> u64 {
    ok(&mut device.core, import_command(data))["imported"]
        .as_u64()
        .unwrap()
}

/// `(code, detail)` of an error: its `what`, `kind`, `rule` or `field`.
fn refusal(error: &Value) -> (String, String) {
    let detail = ["what", "kind", "rule", "field"]
        .into_iter()
        .find_map(|name| error.get(name))
        .map_or_else(String::new, |detail| detail.as_str().unwrap().to_string());
    (error["code"].as_str().unwrap().to_string(), detail)
}

fn expect(code: &str, detail: &str) -> (String, String) {
    (code.to_string(), detail.to_string())
}

/// The messages of `conversation` as `device` shows them, newest first, without the nonce only the
/// sender's own copy keeps.
fn shown(device: &mut TestDevice, conversation: Uuid) -> Vec<Value> {
    let page = ok(
        &mut device.core,
        json!({"cmd": "messages", "conversation_id": conversation, "limit": 100}),
    );
    page["messages"]
        .as_array()
        .unwrap()
        .iter()
        .cloned()
        .map(|mut message| {
            message.as_object_mut().unwrap().remove("nonce");
            message
        })
        .collect()
}

/// The IDs of the messages `device` shows, newest first.
fn shown_ids(device: &mut TestDevice, conversation: Uuid) -> Vec<Uuid> {
    shown(device, conversation)
        .iter()
        .map(|message| message["message_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// A new device of `user`, recovered with the recovery key of `identity` (an identity's reply): it
/// holds that identity's backup key, and no group.
fn recovered(server: &mut FakeServer, user: Uuid, identity: &Value) -> TestDevice {
    recovered_with(server, user, identity, None)
}

/// `recover` for `user`, with the blobs of `identity` (an identity's reply), the user's list as the
/// server serves it, and the earlier backup keys the server keeps beside them, when given.
fn recovering(
    server: &FakeServer,
    user: Uuid,
    identity: &Value,
    previous: Option<&Value>,
) -> Value {
    let mut command = json!({
        "cmd": "recover",
        "recovery_key": identity["recovery_key"],
        "wrapped_backup_key": identity["wrapped_backup_key"],
        "encrypted_identity": identity["encrypted_identity"],
        "device_list": server.observed(user)["device_list"],
    });
    if let Some(previous) = previous {
        command["wrapped_previous_backup_keys"] = previous.clone();
    }
    command
}

/// As `recovered`, with the earlier backup keys too, when given.
fn recovered_with(
    server: &mut FakeServer,
    user: Uuid,
    identity: &Value,
    previous: Option<&Value>,
) -> TestDevice {
    let mut device = server.bare_device(user);
    let recovered = ok(
        &mut device.core,
        recovering(server, user, identity, previous),
    );
    server.take_device(user, &recovered["certificate"], &recovered["device_list"]);
    device
}

/// The earlier backup keys as `rotate_keys` hands them to the server: `{v: 1, nonce, ct}`,
/// AES-256-GCM under the new backup key, with "duvet previous backup keys v1" || user as associated
/// data; `ct` holds the CBOR list of the keys, `{key, until}`, oldest first.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousKeys {
    v: u32,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ct: Vec<u8>,
}

fn previous_keys_aad(user: Uuid) -> Vec<u8> {
    [b"duvet previous backup keys v1".as_slice(), user.as_bytes()].concat()
}

/// The keys an earlier backup keys' blob holds, opened with `backup_key` for `user`.
fn open_previous_keys(backup_key: &[u8; 32], user: Uuid, blob: &[u8]) -> Vec<EarlierKey> {
    let sealed: PreviousKeys = ciborium::from_reader(blob).expect("the blob's CBOR");
    assert_eq!((sealed.v, sealed.nonce.len()), (1, 12));
    let plain = Aes256Gcm::new_from_slice(backup_key)
        .unwrap()
        .decrypt(
            Nonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ct,
                aad: &previous_keys_aad(user),
            },
        )
        .expect("the blob opens with the backup key, for its user");
    ciborium::from_reader(plain.as_slice()).expect("the earlier keys")
}

/// An earlier backup key as the blob holds it: the key, and the UTC day it was replaced on.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EarlierKey {
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    until: String,
}

/// An earlier backup keys' blob holding `keys`, sealed with `backup_key` for `user`.
fn seal_previous_keys(backup_key: &[u8; 32], user: Uuid, keys: &[EarlierKey]) -> Vec<u8> {
    let nonce = vec![3; 12];
    let ct = Aes256Gcm::new_from_slice(backup_key)
        .unwrap()
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &cbor(&keys),
                aad: &previous_keys_aad(user),
            },
        )
        .unwrap();
    cbor(&PreviousKeys { v: 1, nonce, ct })
}

/// The backup keys from before the current one `device` keeps, oldest first.
fn earlier_keys(device: &mut TestDevice) -> Vec<[u8; 32]> {
    device
        .core
        .transaction(|tx| tx.previous_backup_keys())
        .unwrap()
        .iter()
        .map(|key| **key)
        .collect()
}

#[test]
fn segment_round_trip() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);

    // On the day, A1 writes, B1 answers with a file, and A1 edits its message.
    dm.at(day + HOUR);
    let hello = say(&mut dm.server, &mut dm.a1, conversation, "hola");
    dm.at(day + 2 * HOUR);
    let photo = send(
        &mut dm.server,
        &mut dm.b1,
        conversation,
        json!({"text": "mira", "attachments": [file()]}),
        Some(hello),
    );
    dm.at(day + 3 * HOUR);
    edit(
        &mut dm.server,
        &mut dm.a1,
        conversation,
        hello,
        "hola, editado",
    );
    dm.deliver();
    // The next day B1 writes again: A1 applied its queue past the day's end.
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "mañana");
    dm.deliver();

    // The day is due, complete: A1 was in the group from its start to its end, and read it all.
    // The day still going isn't due.
    let the_day = utc_day(day);
    assert_eq!(due(&mut dm.a1), [(conversation, the_day.clone(), true)]);
    let built = segment(&mut dm.a1, conversation, &the_day);
    assert_eq!(built["complete"], true);
    let backup_key = backup_key_of(dm.a, &dm.identity);
    assert_eq!(bytes(&built["key_id"]), recovery::key_id(&backup_key));

    // The segment as the contract lays it out, opened with A's backup key: its header, and the
    // day's messages and edit as A1 carries them, in the order they were sent. The file isn't in
    // it: its key is, in its message's envelope.
    let segment = Segment::read(&bytes(&built["data"]));
    assert_eq!(segment.v, 1);
    assert_eq!(segment.key_id, recovery::key_id(&backup_key));
    assert_eq!(
        (segment.user, segment.conversation, segment.day.as_str()),
        (dm.a, conversation, the_day.as_str())
    );
    assert!(segment.complete);
    assert_eq!(segment.nonce.len(), 12);
    let records = segment.open(&backup_key);
    let order: Vec<(RecordKind, Uuid)> = records
        .iter()
        .map(|record| (record.kind, record.id))
        .collect();
    assert_eq!(
        order,
        [
            (RecordKind::Message, hello),
            (RecordKind::Message, photo),
            (RecordKind::Edit, hello),
        ]
    );
    assert_eq!(records[1].user, dm.b);
    assert_eq!(records[1].reply_to, Some(hello));
    let carried = dm
        .a1
        .core
        .transaction(|tx| messages::records_for(tx, conversation, day, day + DAY_MS))
        .unwrap();
    assert_eq!(records, carried);

    // Another device of A's, recovered with the recovery key, imports it: it shows the day as A1
    // does, the edit applied, the reply and the file kept.
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    assert_eq!(imported(&mut a2, &built["data"]), 3);
    let the_day_on_a1: Vec<Value> = shown(&mut dm.a1, conversation)
        .into_iter()
        .filter(|message| message["sent_at"].as_i64().unwrap() < day + DAY_MS)
        .collect();
    assert_eq!(the_day_on_a1.len(), 2);
    assert_eq!(the_day_on_a1[1]["text"], "hola, editado");
    assert_eq!(shown(&mut a2, conversation), the_day_on_a1);
    // Again, it changes nothing; and A2 holds the day as the server does, so nothing is due.
    assert_eq!(imported(&mut a2, &built["data"]), 0);
    assert_eq!(due(&mut a2), []);

    // Once the server holds it, A1 has nothing due either.
    uploaded(&mut dm.a1, conversation, &the_day, &built);
    assert_eq!(due(&mut dm.a1), []);
}

#[test]
fn segment_rejects_tampering_and_other_keys() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    say(&mut dm.server, &mut dm.a1, conversation, "solo para A");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let the_day = utc_day(day);
    let built = segment(&mut dm.a1, conversation, &the_day);
    let theirs = segment(&mut dm.b1, conversation, &the_day);
    let segment = Segment::read(&bytes(&built["data"]));
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let records = segment.open(&backup_key);
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    // Each is refused alike by an import and by a move to the current key.
    let mut refused = |blob: Vec<u8>| -> (String, String) {
        let data = json!(b64(&blob));
        let by_import = refusal(&error(&mut a2.core, import_command(&data)));
        let by_reencrypt = refusal(&error(
            &mut a2.core,
            json!({"cmd": "backup_reencrypt", "data": data}),
        ));
        assert_eq!(by_reencrypt, by_import);
        by_import
    };

    // A byte of its ciphertext changed.
    let mut changed = segment.clone();
    *changed.ct.last_mut().unwrap() ^= 1;
    assert_eq!(refused(cbor(&changed)), expect("decrypt_failed", "segment"));
    // Its header changed: another conversation or day (another key, other associated data), its
    // completeness, or its user.
    let mut others = vec![segment.clone(), segment.clone(), segment.clone()];
    others[0].conversation = new_id();
    others[1].day = utc_day(day + DAY_MS);
    others[2].complete = !segment.complete;
    let mut stranger = segment.clone();
    stranger.user = dm.b;
    others.push(stranger);
    for other in others {
        assert_eq!(
            refused(cbor(&other)),
            expect("decrypt_failed", "segment"),
            "{other:?}"
        );
    }
    // Another backup key: one that no key A2 holds is named by...
    let another_key = [0x42u8; 32];
    let mut foreign = segment.clone();
    foreign.key_id = recovery::key_id(&another_key).to_vec();
    assert_eq!(
        refused(foreign.sealed(&another_key, &records)),
        expect("not_found", "backup_key")
    );
    // ...or one that claims A's key's ID, which doesn't open it.
    let forged = segment.clone().sealed(&another_key, &records);
    assert_eq!(refused(forged), expect("decrypt_failed", "segment"));
    // B's own backup of the same day, under B's key.
    assert_eq!(
        refused(bytes(&theirs["data"])),
        expect("decrypt_failed", "segment")
    );
    // What isn't a segment, or one of a version this core doesn't read.
    assert_eq!(
        refused(b"not a segment".to_vec()),
        expect("bad_command", "data")
    );
    let mut later = segment.clone();
    later.v = 2;
    assert_eq!(refused(cbor(&later)), expect("bad_command", "data"));

    // None of it imported anything; the segment itself imports.
    assert_eq!(shown(&mut a2, conversation), Vec::<Value>::new());
    assert_eq!(imported(&mut a2, &built["data"]), 1);
}

#[test]
fn segment_day_is_utc() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // Two messages of the same evening in UTC-5: at 18:59 there, the day before `day` in UTC as
    // well, and at 23:30 there, which in UTC is 04:30 of `day`.
    let evening = day - MINUTE;
    let late_evening = day + 4 * HOUR + 30 * MINUTE;
    assert_eq!(
        utc_day(evening - 5 * HOUR),
        utc_day(late_evening - 5 * HOUR)
    );
    dm.at(evening);
    let earlier = say(&mut dm.server, &mut dm.a1, conversation, "18:59 en UTC-5");
    dm.at(late_evening);
    let later = say(&mut dm.server, &mut dm.a1, conversation, "23:30 en UTC-5");
    dm.deliver();

    // While `day` lasts in UTC, only the day before is due: a day is due once it ends. A1 made the
    // DM at noon that day, so it isn't complete.
    let (before, the_day) = (utc_day(day - DAY_MS), utc_day(day));
    assert_eq!(due(&mut dm.a1), [(conversation, before.clone(), false)]);

    // Once `day` ends in UTC (and the next day's first message came), it's due as well, complete.
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "el día siguiente");
    dm.deliver();
    assert_eq!(
        due(&mut dm.a1),
        [
            (conversation, before.clone(), false),
            (conversation, the_day.clone(), true)
        ]
    );

    // The message of 23:30 in UTC-5 is in `day`'s segment; the one of 18:59, in the day before's.
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let mut holds = |day: &str| -> Vec<Uuid> {
        let built = segment(&mut dm.a1, conversation, day);
        Segment::read(&bytes(&built["data"]))
            .open(&backup_key)
            .iter()
            .map(|record| record.id)
            .collect()
    };
    assert_eq!(holds(&the_day), [later]);
    assert_eq!(holds(&before), [earlier]);

    // A day is a UTC date written YYYY-MM-DD, and nothing else.
    for day in [
        "2026-13-01",
        "2026-02-30",
        "2025-02-29",
        "26-11-23",
        "2026-11-23T00:00:00Z",
        "2026-1-23",
        " 2026-11-23",
        "",
    ] {
        let refused = error(&mut dm.a1.core, segment_command(conversation, day));
        assert_eq!(refusal(&refused), expect("bad_command", "day"), "{day:?}");
    }
    segment(&mut dm.a1, conversation, "2024-02-29");
}

#[test]
fn delete_marks_its_days_again() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // A1 writes on `day` and edits it the next day, beside a message of B1's that day.
    dm.at(day + HOUR);
    let gone = say(&mut dm.server, &mut dm.a1, conversation, "lo borraré");
    dm.at(day + DAY_MS + HOUR);
    edit(
        &mut dm.server,
        &mut dm.a1,
        conversation,
        gone,
        "lo borraré, editado",
    );
    dm.at(day + DAY_MS + 2 * HOUR);
    let stays = say(&mut dm.server, &mut dm.b1, conversation, "esto queda");
    dm.deliver();

    // The day after, A1 backs both days up, and has nothing due. B1 lists and builds them too, but
    // its uploads are still under way when the deletion comes.
    dm.at(day + 2 * DAY_MS + HOUR);
    let days = [utc_day(day), utc_day(day + DAY_MS)];
    for device in [&mut dm.a1, &mut dm.b1] {
        let listed: Vec<String> = due(device).into_iter().map(|(_, day, _)| day).collect();
        assert_eq!(listed, days);
    }
    let before_deletion: Vec<Value> = days
        .iter()
        .map(|day| back_up(&mut dm.a1, conversation, day))
        .collect();
    assert_eq!(due(&mut dm.a1), []);
    let in_flight: Vec<Value> = days
        .iter()
        .map(|day| segment(&mut dm.b1, conversation, day))
        .collect();

    // A1 deletes its message. On A1, and on B1 once the queue brings the deletion, the message's
    // day and its edit's are due again: on B1 even once the server holds the segments it built
    // before, which still have them.
    dm.at(day + 2 * DAY_MS + 2 * HOUR);
    delete(&mut dm.server, &mut dm.a1, conversation, gone);
    dm.deliver();
    for (day, built) in days.iter().zip(&in_flight) {
        uploaded(&mut dm.b1, conversation, day, built);
    }
    for device in [&mut dm.a1, &mut dm.b1] {
        let listed: Vec<String> = due(device).into_iter().map(|(_, day, _)| day).collect();
        assert_eq!(listed, days);
    }

    // Their segments hold neither the message nor its edit.
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let mut holds = |day: &str| -> Vec<(RecordKind, Uuid)> {
        let built = segment(&mut dm.a1, conversation, day);
        Segment::read(&bytes(&built["data"]))
            .open(&backup_key)
            .iter()
            .map(|record| (record.kind, record.id))
            .collect()
    };
    assert_eq!(holds(&days[0]), []);
    assert_eq!(holds(&days[1]), [(RecordKind::Message, stays)]);
    for device in [&mut dm.a1, &mut dm.b1] {
        for day in &days {
            back_up(device, conversation, day);
        }
        assert_eq!(due(device), []);
    }

    // The server hands back the copy from before the deletion: it brings nothing back, and leaves
    // its day due, as the server's copy isn't what A1 holds.
    assert_eq!(imported(&mut dm.a1, &before_deletion[0]["data"]), 0);
    assert!(!shown_ids(&mut dm.a1, conversation).contains(&gone));
    let listed: Vec<String> = due(&mut dm.a1).into_iter().map(|(_, day, _)| day).collect();
    assert_eq!(listed, [days[0].clone()]);
}

#[test]
fn a_copy_from_before_a_deletion_doesnt_bring_the_message_back() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // On the day A1 writes and edits its message, and B1 answers; A1 backs the day up the next
    // day, then deletes its message and is lost before it uploads the day again.
    dm.at(day + HOUR);
    let gone = say(&mut dm.server, &mut dm.a1, conversation, "lo borraré");
    dm.at(day + 2 * HOUR);
    edit(&mut dm.server, &mut dm.a1, conversation, gone, "editado");
    dm.at(day + 3 * HOUR);
    let stays = say(&mut dm.server, &mut dm.b1, conversation, "esto queda");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "mañana");
    dm.deliver();
    let the_day = utc_day(day);
    let before = back_up(&mut dm.a1, conversation, &the_day);
    delete(&mut dm.server, &mut dm.a1, conversation, gone);

    // A device recovered after the deletion imports that copy with the IDs the API saw deleted in
    // the conversation: neither the message nor its edit comes back, and the day is due, to upload
    // without them.
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    let taken = ok(
        &mut a2.core,
        json!({"cmd": "backup_import", "data": before["data"], "deleted": [gone]}),
    );
    assert_eq!(taken, json!({"imported": 1}));
    assert_eq!(shown_ids(&mut a2, conversation), [stays]);
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), true)]);
    let rebuilt = segment(&mut a2, conversation, &the_day);
    let held: Vec<Uuid> = Segment::read(&bytes(&rebuilt["data"]))
        .open(&backup_key_of(dm.a, &dm.identity))
        .iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(held, [stays]);
}

#[test]
fn a_stay_out_of_the_group_breaks_its_days() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // The day before `day`, a second device of A's, recovered, joins the group by external commit.
    dm.at(day - 11 * HOUR);
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    dm.server.publish(&mut a2);
    for device in [&mut dm.a1, &mut dm.b1, &mut a2] {
        dm.server.introduce(device);
    }
    let join = |server: &mut FakeServer, a2: &mut TestDevice| {
        let command = json!({
            "cmd": "join_external",
            "conversation_id": conversation,
            "generation": 0,
            "group_info": server.group_info(conversation),
        });
        server
            .commit(a2, conversation, command)
            .expect("the server takes the external commit");
    };
    join(&mut dm.server, &mut a2);
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);

    // B1 writes through `day` and the day after. At 10:00 on `day` the API takes A2 out (its
    // removal, which A1 commits); at 10:00 the next day A2 comes back by external commit.
    let write = |dm: &mut Dm, a2: &mut TestDevice, at: i64, text: &str| {
        dm.at(at);
        say(&mut dm.server, &mut dm.b1, conversation, text);
        dm.server.deliver_all(&mut [&mut dm.a1, &mut dm.b1, a2]);
    };
    write(&mut dm, &mut a2, day + HOUR, "antes");
    dm.at(day + 10 * HOUR);
    dm.server.remove_device(conversation, a2.id);
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    let commit = json!({"cmd": "commit_pending", "conversation_id": conversation});
    dm.server
        .commit(&mut dm.a1, conversation, commit)
        .expect("the server takes the removal");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    assert_eq!(a2.no_group(conversation)["what"], "membership");
    write(&mut dm, &mut a2, day + 11 * HOUR, "fuera");
    write(&mut dm, &mut a2, day + DAY_MS + HOUR, "aún fuera");
    dm.at(day + DAY_MS + 10 * HOUR);
    join(&mut dm.server, &mut a2);
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    write(&mut dm, &mut a2, day + DAY_MS + 11 * HOUR, "de vuelta");
    write(&mut dm, &mut a2, day + 2 * DAY_MS + HOUR, "al otro día");
    write(&mut dm, &mut a2, day + 3 * DAY_MS + HOUR, "y al siguiente");

    // A1, in the group all along, holds the three days whole. A2 holds neither the day it left nor
    // the one it came back, only the one after, which it was in from start to end.
    let days = [
        utc_day(day),
        utc_day(day + DAY_MS),
        utc_day(day + 2 * DAY_MS),
    ];
    let whole = |completes: [bool; 3]| -> Vec<(Uuid, String, bool)> {
        days.iter()
            .zip(completes)
            .map(|(day, complete)| (conversation, day.clone(), complete))
            .collect()
    };
    assert_eq!(due(&mut dm.a1), whole([true, true, true]));
    assert_eq!(due(&mut a2), whole([false, false, true]));
}

#[test]
fn incomplete_day_can_be_replaced() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);

    // On `day`, B1 writes, and the server hands A1 a copy it can't read: A1 keeps it as waiting.
    dm.at(day + HOUR);
    let unread = say(&mut dm.server, &mut dm.b1, conversation, "no llega bien");
    hand_unreadable(&dm.server, &mut dm.a1, conversation);

    // At noon, a second device of A's, recovered, joins the group by external commit.
    dm.at(day + 12 * HOUR);
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    dm.server.publish(&mut a2);
    for device in [&mut dm.a1, &mut dm.b1, &mut a2] {
        dm.server.introduce(device);
    }
    let join = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": dm.server.group_info(conversation),
    });
    dm.server
        .commit(&mut a2, conversation, join)
        .expect("the server takes the external commit");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    dm.at(day + 13 * HOUR);
    let read = say(&mut dm.server, &mut dm.b1, conversation, "este sí");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);

    // After midnight, before anything of the next day came: the day is due on both of A's devices,
    // incomplete. A1 couldn't read a message of it, A2 came in at noon, and neither has seen the
    // day end.
    dm.at(day + DAY_MS + 30 * MINUTE);
    let the_day = utc_day(day);
    assert_eq!(due(&mut dm.a1), [(conversation, the_day.clone(), false)]);
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), false)]);

    // A1 uploads its copy, incomplete. A2 imports the server's copy first, which holds all A2 holds
    // of the day: it has nothing to upload. Neither has the day due any more.
    let first = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(first["complete"], false);
    assert_eq!(imported(&mut a2, &first["data"]), 0);
    assert_eq!(due(&mut dm.a1), []);
    assert_eq!(due(&mut a2), []);

    // The message A1 couldn't read comes another way (an import of what B1 has of the day): the
    // day changed, and is due again, still incomplete.
    let records = dm
        .b1
        .core
        .transaction(|tx| messages::records_for(tx, conversation, day, day + DAY_MS))
        .unwrap();
    let filled = dm
        .a1
        .core
        .transaction(|tx| messages::import(tx, conversation, &records, Some(dm.b)))
        .unwrap();
    assert_eq!(filled, 1);
    assert_eq!(due(&mut dm.a1), [(conversation, the_day.clone(), false)]);
    let second = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(second["complete"], false);
    assert_eq!(due(&mut dm.a1), []);

    // Then the next day's first message comes: A1 has its queue past the day's end. The day is
    // complete, and due once more, to replace the server's incomplete copy. A2's, begun at noon,
    // never is.
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "buenos días");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    assert_eq!(due(&mut dm.a1), [(conversation, the_day.clone(), true)]);
    assert_eq!(due(&mut a2), []);
    let third = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(third["complete"], true);
    assert_eq!(due(&mut dm.a1), []);

    // A device restoring the backup takes the incomplete copy, then the complete one that
    // replaced it: the second brings what the first lacked. It then holds the day as the server
    // does.
    let mut a3 = recovered(&mut dm.server, dm.a, &dm.identity);
    assert_eq!(imported(&mut a3, &first["data"]), 1);
    assert_eq!(shown_ids(&mut a3, conversation), [read]);
    assert_eq!(imported(&mut a3, &third["data"]), 1);
    assert_eq!(shown_ids(&mut a3, conversation), [read, unread]);
    assert_eq!(due(&mut a3), []);
}

#[test]
fn what_a_device_cant_carry_keeps_its_day_incomplete() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // On `day`, A1 writes twice; B1 gets a copy of the first it can't read, and keeps it as waiting.
    dm.at(day + HOUR);
    let unread = say(&mut dm.server, &mut dm.a1, conversation, "B1 no lo lee");
    hand_unreadable(&dm.server, &mut dm.b1, conversation);
    dm.at(day + 2 * HOUR);
    say(
        &mut dm.server,
        &mut dm.a1,
        conversation,
        "este B1 sí lo lee",
    );
    // The next day A1 edits the first: B1 reads the edit, which waits for its message.
    dm.at(day + DAY_MS + HOUR);
    edit(&mut dm.server, &mut dm.a1, conversation, unread, "editado");
    dm.at(day + DAY_MS + 2 * HOUR);
    say(&mut dm.server, &mut dm.a1, conversation, "otro día");
    dm.deliver();

    // Once both days ended and the next one's first message came, A1 holds both whole. B1 holds
    // neither, though it applied its queue past their ends: it couldn't read a message of the
    // first, and can't carry the second's edit, of a message it doesn't show.
    dm.at(day + 2 * DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.a1, conversation, "pasado mañana");
    dm.deliver();
    let (first, second) = (utc_day(day), utc_day(day + DAY_MS));
    assert_eq!(
        due(&mut dm.a1),
        [
            (conversation, first.clone(), true),
            (conversation, second.clone(), true)
        ]
    );
    assert_eq!(
        due(&mut dm.b1),
        [
            (conversation, first.clone(), false),
            (conversation, second.clone(), false)
        ]
    );

    // Once B1 has the message (an import of what A1 has of its day), the edit applies to it, and
    // both days are complete.
    let records = dm
        .a1
        .core
        .transaction(|tx| messages::records_for(tx, conversation, day, day + DAY_MS))
        .unwrap();
    let filled = dm
        .b1
        .core
        .transaction(|tx| messages::import(tx, conversation, &records, Some(dm.a)))
        .unwrap();
    assert_eq!(filled, 1);
    assert_eq!(
        due(&mut dm.b1),
        [(conversation, first, true), (conversation, second, true)]
    );
}

#[test]
fn a_day_with_nothing_to_carry_is_due_once_it_has_something() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // On `day` A1 writes once, and B1 gets a copy it can't read; the next day A1 edits it, and
    // B1's edit waits for its message. B1 has nothing of either day to carry.
    dm.at(day + HOUR);
    let unread = say(&mut dm.server, &mut dm.a1, conversation, "B1 no lo lee");
    hand_unreadable(&dm.server, &mut dm.b1, conversation);
    dm.at(day + DAY_MS + HOUR);
    edit(&mut dm.server, &mut dm.a1, conversation, unread, "editado");
    dm.at(day + 2 * DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.a1, conversation, "pasado mañana");
    dm.deliver();
    assert_eq!(due(&mut dm.b1), []);

    // Once B1 has the message, both days are due: the message's, and its edit's.
    let records = dm
        .a1
        .core
        .transaction(|tx| messages::records_for(tx, conversation, day, day + DAY_MS))
        .unwrap();
    dm.b1
        .core
        .transaction(|tx| messages::import(tx, conversation, &records, Some(dm.a)))
        .unwrap();
    assert_eq!(
        due(&mut dm.b1),
        [
            (conversation, utc_day(day), true),
            (conversation, utc_day(day + DAY_MS), true)
        ]
    );
}

#[test]
fn reencrypt_moves_old_segments_to_the_new_key() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    let hello = say(&mut dm.server, &mut dm.a1, conversation, "antes del cambio");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let the_day = utc_day(day);
    let old = segment(&mut dm.a1, conversation, &the_day);
    let old_key = backup_key_of(dm.a, &dm.identity);
    assert_eq!(bytes(&old["key_id"]), recovery::key_id(&old_key));
    let old_segment = Segment::read(&bytes(&old["data"]));

    // A changes its keys: a new backup key, the old one kept by A1, wrapped by the new.
    let rotated = ok(&mut dm.a1.core, json!({"cmd": "rotate_keys", "remove": []}));
    dm.server.take_identity(dm.a, &rotated);
    let new_key = backup_key_of(dm.a, &rotated);
    assert_ne!(new_key, old_key);

    // A1 moves the old segment to the new key: the same day and records, under the new key's ID.
    let moved = ok(
        &mut dm.a1.core,
        json!({"cmd": "backup_reencrypt", "data": old["data"]}),
    );
    assert_eq!(bytes(&moved["key_id"]), recovery::key_id(&new_key));
    let moved_segment = Segment::read(&bytes(&moved["data"]));
    assert_eq!(moved_segment.key_id, recovery::key_id(&new_key));
    assert_eq!(
        (
            moved_segment.user,
            moved_segment.conversation,
            &moved_segment.day,
            moved_segment.complete
        ),
        (dm.a, conversation, &the_day, old_segment.complete)
    );
    assert_ne!(moved_segment.nonce, old_segment.nonce);
    assert_eq!(moved_segment.open(&new_key), old_segment.open(&old_key));
    // What it builds from now on is under the new key too.
    let rebuilt = segment(&mut dm.a1, conversation, &the_day);
    assert_eq!(bytes(&rebuilt["key_id"]), recovery::key_id(&new_key));

    // A device recovered with the new recovery key holds the new backup key alone: it imports the
    // moved segment, and can't open the old one.
    let mut a2 = recovered(&mut dm.server, dm.a, &rotated);
    let refused = error(&mut a2.core, import_command(&old["data"]));
    assert_eq!(refusal(&refused), expect("not_found", "backup_key"));
    assert_eq!(imported(&mut a2, &moved["data"]), 1);
    assert_eq!(shown_ids(&mut a2, conversation), [hello]);
    // A1, which keeps the old key, still opens the old segment.
    assert_eq!(imported(&mut dm.a1, &old["data"]), 0);
}

#[test]
fn reencrypt_moves_only_what_an_import_takes() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    say(&mut dm.server, &mut dm.a1, conversation, "hola");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let built = segment(&mut dm.a1, conversation, &utc_day(day));
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let read = Segment::read(&bytes(&built["data"]));
    let records = read.clone().open(&backup_key);
    let reencrypt = |data: &Value| json!({"cmd": "backup_reencrypt", "data": data});

    // A segment that holds something other than records moves no more than it imports.
    let not_records = json!(b64(&read.clone().sealed_plain(&backup_key, b"no records")));
    for command in [import_command(&not_records), reencrypt(&not_records)] {
        let refused = error(&mut dm.a1.core, command);
        assert_eq!(refusal(&refused), expect("decrypt_failed", "segment"));
    }

    // A record of another day moves without it, as an import leaves it out.
    let mut stray = records[0].clone();
    stray.id = new_id();
    stray.sent += DAY_MS as u64;
    let mixed = json!(b64(&read.sealed(&backup_key, &[records[0].clone(), stray])));
    let moved = ok(&mut dm.a1.core, reencrypt(&mixed));
    assert_eq!(
        Segment::read(&bytes(&moved["data"])).open(&backup_key),
        records
    );
}

#[test]
fn an_import_leaves_out_records_of_other_days() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    let hello = say(&mut dm.server, &mut dm.a1, conversation, "hola");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let the_day = utc_day(day);
    let built = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(due(&mut dm.a1), []);
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let read = Segment::read(&bytes(&built["data"]));
    let records = read.clone().open(&backup_key);

    // The server's copy of the day holds a record of the next day besides the day's own: an import
    // leaves it out, and the day is due again, to upload without it.
    let mut stray = records[0].clone();
    stray.id = new_id();
    stray.sent += DAY_MS as u64;
    let mixed = json!(b64(&read.sealed(&backup_key, &[records[0].clone(), stray])));
    assert_eq!(imported(&mut dm.a1, &mixed), 0);
    assert_eq!(shown_ids(&mut dm.a1, conversation), [hello]);
    assert_eq!(due(&mut dm.a1), [(conversation, the_day, false)]);
}

#[test]
fn a_day_listed_again_during_an_upload_stays_due() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    let gone = say(&mut dm.server, &mut dm.a1, conversation, "se borrará");
    say(&mut dm.server, &mut dm.a1, conversation, "se queda");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let the_day = utc_day(day);

    // A1 lists the day and builds it; its upload is under way when A1 deletes a message of the day,
    // and the client lists the days again meanwhile.
    assert_eq!(due(&mut dm.a1).len(), 1);
    let built = segment(&mut dm.a1, conversation, &the_day);
    delete(&mut dm.server, &mut dm.a1, conversation, gone);
    assert_eq!(due(&mut dm.a1).len(), 1);

    // The upload of the build from before the deletion ends: the day stays due, to upload without
    // the message.
    uploaded(&mut dm.a1, conversation, &the_day, &built);
    let listed: Vec<String> = due(&mut dm.a1).into_iter().map(|(_, day, _)| day).collect();
    assert_eq!(listed, [the_day.clone()]);
    let latest = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(due(&mut dm.a1), []);
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let carried = Segment::read(&bytes(&latest["data"])).open(&backup_key);
    assert!(carried.iter().all(|record| record.id != gone));
}

#[test]
fn a_deletion_replaces_the_servers_complete_copy() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // At noon A's second device, recovered, joins the group; then it writes, and so does B1.
    dm.at(day + 12 * HOUR);
    let mut a2 = recovered(&mut dm.server, dm.a, &dm.identity);
    for device in [&mut dm.a1, &mut dm.b1, &mut a2] {
        dm.server.introduce(device);
    }
    let join = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": dm.server.group_info(conversation),
    });
    dm.server
        .commit(&mut a2, conversation, join)
        .expect("the server takes the external commit");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    dm.at(day + 13 * HOUR);
    let gone = say(&mut dm.server, &mut a2, conversation, "lo borraré");
    let stays = say(&mut dm.server, &mut dm.b1, conversation, "esto queda");
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "al día siguiente");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);

    // A1, in the group the whole day, uploads it complete; then A1 is lost.
    let the_day = utc_day(day);
    let complete_copy = back_up(&mut dm.a1, conversation, &the_day);
    assert_eq!(complete_copy["complete"], true);

    // A2 deletes its message. The day is due on A2, which holds it incomplete (it came in at noon).
    dm.at(day + DAY_MS + 2 * HOUR);
    delete(&mut dm.server, &mut a2, conversation, gone);
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), false)]);

    // As the client does before it builds a day the server holds, A2 imports the server's copy: it
    // then holds the day whole, but for the deleted message, which the copy still has. The day stays
    // due, complete; its upload replaces the server's copy with one as complete and without the
    // message.
    assert_eq!(imported(&mut a2, &complete_copy["data"]), 0);
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), true)]);
    let replacement = back_up(&mut a2, conversation, &the_day);
    assert_eq!(replacement["complete"], true);
    let backup_key = backup_key_of(dm.a, &dm.identity);
    let ids: Vec<Uuid> = Segment::read(&bytes(&replacement["data"]))
        .open(&backup_key)
        .iter()
        .map(|record| record.id)
        .collect();
    assert_eq!(ids, [stays]);
    assert_eq!(due(&mut a2), []);
}

#[test]
fn a_slow_clock_doesnt_complete_the_join_day() {
    let mut dm = dm();
    let (conversation, day) = (dm.conversation, dm.day);
    // B1 writes at 01:00. At 10:00 a second device of A's joins by external commit; its clock runs
    // 13 hours behind the API's, so as it joins it reads the day before.
    dm.at(day + HOUR);
    say(
        &mut dm.server,
        &mut dm.b1,
        conversation,
        "antes de que entre",
    );
    dm.deliver();
    dm.at(day + 10 * HOUR);
    let slow = FakeClock::at(day + 10 * HOUR - 13 * HOUR);
    let mut a2 = dm.server.bare_device_on(dm.a, slow.clone());
    let recovered = ok(
        &mut a2.core,
        recovering(&dm.server, dm.a, &dm.identity, None),
    );
    dm.server
        .take_device(dm.a, &recovered["certificate"], &recovered["device_list"]);
    for device in [&mut dm.a1, &mut dm.b1, &mut a2] {
        dm.server.introduce(device);
    }
    let join = json!({
        "cmd": "join_external",
        "conversation_id": conversation,
        "generation": 0,
        "group_info": dm.server.group_info(conversation),
    });
    dm.server
        .commit(&mut a2, conversation, join)
        .expect("the server takes the external commit");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);
    dm.at(day + 11 * HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "después");
    dm.at(day + DAY_MS + HOUR);
    say(&mut dm.server, &mut dm.b1, conversation, "al día siguiente");
    dm.server
        .deliver_all(&mut [&mut dm.a1, &mut dm.b1, &mut a2]);

    // Once its own clock has passed that day too, A2 lists the day incomplete: it never had what
    // came before it joined, whatever its clock said then.
    slow.set(day + DAY_MS + HOUR);
    assert_eq!(due(&mut a2), [(conversation, utc_day(day), false)]);
}

/// A day of A's under A's first backup key, then A's change of keys: the old day's segment, the
/// backup key before the change and the rotation's reply.
fn old_segment_then_rotation(dm: &mut Dm) -> (Uuid, Value, [u8; 32], Value) {
    let (conversation, day) = (dm.conversation, dm.day);
    dm.at(day + HOUR);
    let hello = say(&mut dm.server, &mut dm.a1, conversation, "antes del cambio");
    dm.deliver();
    dm.at(day + DAY_MS + HOUR);
    let old = segment(&mut dm.a1, conversation, &utc_day(day));
    let old_key = backup_key_of(dm.a, &dm.identity);
    let rotated = ok(&mut dm.a1.core, json!({"cmd": "rotate_keys", "remove": []}));
    dm.server.take_identity(dm.a, &rotated);
    (hello, old, old_key, rotated)
}

#[test]
fn recovery_with_the_earlier_keys_opens_old_segments() {
    let mut dm = dm();
    let conversation = dm.conversation;
    let (hello, old, old_key, rotated) = old_segment_then_rotation(&mut dm);
    let new_key = backup_key_of(dm.a, &rotated);
    let sealed = rotated["wrapped_previous_backup_keys"].clone();

    // A device recovered with the new recovery key and the earlier keys the server keeps imports
    // the segment written under the old key, and moves it to the new one.
    let mut a2 = recovered_with(&mut dm.server, dm.a, &rotated, Some(&sealed));
    assert_eq!(imported(&mut a2, &old["data"]), 1);
    assert_eq!(shown_ids(&mut a2, conversation), [hello]);
    let moved = ok(
        &mut a2.core,
        json!({"cmd": "backup_reencrypt", "data": old["data"]}),
    );
    assert_eq!(bytes(&moved["key_id"]), recovery::key_id(&new_key));
    assert_eq!(
        Segment::read(&bytes(&moved["data"])).open(&new_key),
        Segment::read(&bytes(&old["data"])).open(&old_key)
    );
    assert_eq!(earlier_keys(&mut a2), [old_key]);

    // The blob holds the keys before the new one, the one it replaced among them, sealed with the
    // new backup key for A: what the rotating device keeps.
    assert_eq!(
        open_previous_keys(&new_key, dm.a, &bytes(&sealed)),
        [EarlierKey {
            key: old_key.to_vec(),
            until: utc_day(dm.day + DAY_MS),
        }]
    );
    assert_eq!(earlier_keys(&mut dm.a1), [old_key]);

    // Without the blob, as before, the old segment doesn't open there.
    let mut a3 = recovered(&mut dm.server, dm.a, &rotated);
    let refused = error(&mut a3.core, import_command(&old["data"]));
    assert_eq!(refusal(&refused), expect("not_found", "backup_key"));
    assert_eq!(earlier_keys(&mut a3), Vec::<[u8; 32]>::new());
}

#[test]
fn an_earlier_key_opens_only_the_days_before_its_change() {
    let mut dm = dm();
    let day = dm.day;
    let (_, old, old_key, rotated) = old_segment_then_rotation(&mut dm);
    let sealed = rotated["wrapped_previous_backup_keys"].clone();
    let mut a2 = recovered_with(&mut dm.server, dm.a, &rotated, Some(&sealed));
    // The old key's segment of the day before the change still opens.
    assert_eq!(imported(&mut dm.a1, &old["data"]), 0);
    assert_eq!(imported(&mut a2, &old["data"]), 1);

    // Whoever kept the old key (the lost device) seals segments of the change's day, and of the
    // day after, under it: no device takes them, nor moves them to the new key.
    let records = Segment::read(&bytes(&old["data"])).open(&old_key);
    for later in [day + DAY_MS, day + 2 * DAY_MS] {
        let mut forged = Segment::read(&bytes(&old["data"]));
        forged.day = utc_day(later);
        let moved: Vec<Record> = records
            .iter()
            .cloned()
            .map(|mut record| {
                record.sent += (later - day) as u64;
                record
            })
            .collect();
        let data = json!(b64(&forged.sealed(&old_key, &moved)));
        for device in [&mut dm.a1, &mut a2] {
            let refused = error(&mut device.core, import_command(&data));
            assert_eq!(refusal(&refused), expect("decrypt_failed", "segment"));
            let refused = error(
                &mut device.core,
                json!({"cmd": "backup_reencrypt", "data": data}),
            );
            assert_eq!(refusal(&refused), expect("decrypt_failed", "segment"));
        }
    }

    // The blob keeps the day the old key was replaced on.
    let new_key = backup_key_of(dm.a, &rotated);
    assert_eq!(
        open_previous_keys(&new_key, dm.a, &bytes(&sealed)),
        [EarlierKey {
            key: old_key.to_vec(),
            until: utc_day(day + DAY_MS),
        }]
    );
}

#[test]
fn a_device_late_to_a_rotation_builds_again_what_it_sealed_under_the_old_key() {
    // A DM of A and B, with A on A1 and A2, which holds A's backup key too.
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut a2 = server.device(a);
    let mut b1 = server.device(b);
    for device in [&mut a1, &mut a2, &mut b1] {
        server.publish(device);
    }
    for device in [&mut a1, &mut a2, &mut b1] {
        server.introduce(device);
    }
    let old_key = backup_key_of(a, &identity);
    a2.core
        .transaction(|tx| {
            tx.conn().execute(
                "INSERT INTO meta (key, value) VALUES ('backup_key', ?1)",
                [old_key.as_slice()],
            )?;
            Ok(())
        })
        .unwrap();
    let day = test_day();
    server.clock.set(day - 12 * HOUR);
    let conversation = new_id();
    server.conversation(conversation, Kind::Dm, None, &[a, b], false);
    let command = server.create_group(conversation);
    server.commit(&mut a1, conversation, command).unwrap();
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);

    // On the day, A1 writes, then changes the keys with A2 staying.
    server.clock.set(day + HOUR);
    let hello = say(&mut server, &mut a1, conversation, "antes del cambio");
    server.deliver_all(&mut [&mut a1, &mut a2, &mut b1]);
    server.clock.set(day + 2 * HOUR);
    let mut rotating = json!({"cmd": "rotate_keys", "remove": []});
    rotating["certificates"] = server.observed(a)["certificates"].clone();
    let rotated = ok(&mut a1.core, rotating);
    server.take_identity(a, &rotated);
    let new_key = backup_key_of(a, &rotated);

    // The next day A2 backs the day up before it takes its transfer: under the old key, for the
    // day it was replaced on, which no device opens.
    server.clock.set(day + DAY_MS + HOUR);
    let the_day = utc_day(day);
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), false)]);
    let stale = back_up(&mut a2, conversation, &the_day);
    assert_eq!(bytes(&stale["key_id"]), recovery::key_id(&old_key));

    // Once it takes the transfer, the day is due again, and built under the new key.
    let inbox = server.inbox(a2.id);
    ok(
        &mut a2.core,
        json!({
            "cmd": "receive_direct",
            "message": b64(&inbox[0]),
            "identity_key": rotated["identity_key"],
        }),
    );
    assert_eq!(due(&mut a2), [(conversation, the_day.clone(), false)]);
    let rebuilt = back_up(&mut a2, conversation, &the_day);
    assert_eq!(bytes(&rebuilt["key_id"]), recovery::key_id(&new_key));
    assert_eq!(due(&mut a2), []);

    // A device recovered with the new recovery key and the earlier keys refuses the first copy and
    // takes the second.
    let sealed = rotated["wrapped_previous_backup_keys"].clone();
    let mut a3 = recovered_with(&mut server, a, &rotated, Some(&sealed));
    let refused = error(&mut a3.core, import_command(&stale["data"]));
    assert_eq!(refusal(&refused), expect("decrypt_failed", "segment"));
    assert_eq!(imported(&mut a3, &rebuilt["data"]), 1);
    assert_eq!(shown_ids(&mut a3, conversation), [hello]);
}

/// A new device of A, which A1 approves by its QR: the device, and `approval_from_qr`'s reply.
fn approving(dm: &mut Dm) -> (TestDevice, Value) {
    let mut device = dm.server.bare_device(dm.a);
    let begun = ok(&mut device.core, json!({"cmd": "approval_begin"}));
    let approved = ok(
        &mut dm.a1.core,
        json!({"cmd": "approval_from_qr", "qr": begun["qr"]}),
    );
    dm.server
        .take_device(dm.a, &approved["certificate"], &approved["device_list"]);
    (device, approved)
}

/// `approval_receive` of the transfer `approved` holds, with the earlier backup keys the server
/// keeps.
fn approval_taking(approved: &Value, previous: &Value) -> Value {
    json!({
        "cmd": "approval_receive",
        "transfer": approved["transfer"],
        "wrapped_previous_backup_keys": previous,
    })
}

#[test]
fn a_device_approved_after_a_rotation_opens_old_segments() {
    let mut dm = dm();
    let conversation = dm.conversation;
    let (hello, old, old_key, rotated) = old_segment_then_rotation(&mut dm);
    let sealed = rotated["wrapped_previous_backup_keys"].clone();

    // A1 approves A2 after the change: A2 takes the transfer with the earlier keys the server
    // keeps, and opens the segment written under the old key.
    let (mut a2, approved) = approving(&mut dm);
    ok(&mut a2.core, approval_taking(&approved, &sealed));
    assert_eq!(earlier_keys(&mut a2), [old_key]);
    assert_eq!(imported(&mut a2, &old["data"]), 1);
    assert_eq!(shown_ids(&mut a2, conversation), [hello]);

    // Earlier keys that don't open fail the approval whole: the device takes it again with the
    // right ones.
    let (mut a3, approved) = approving(&mut dm);
    let mut tampered = bytes(&sealed);
    *tampered.last_mut().unwrap() ^= 1;
    let refused = error(
        &mut a3.core,
        approval_taking(&approved, &json!(b64(&tampered))),
    );
    assert_eq!(
        refusal(&refused),
        expect("decrypt_failed", "previous_backup_keys")
    );
    let status = ok(&mut a3.core, json!({"cmd": "status"}));
    assert_eq!(status["has_identity"], false);
    ok(&mut a3.core, approval_taking(&approved, &sealed));
    assert_eq!(imported(&mut a3, &old["data"]), 1);
}

#[test]
fn recovery_refuses_earlier_keys_that_dont_open() {
    let mut dm = dm();
    let (_, old, old_key, rotated) = old_segment_then_rotation(&mut dm);
    let new_key = backup_key_of(dm.a, &rotated);
    let sealed = bytes(&rotated["wrapped_previous_backup_keys"]);
    // B's account changes its keys too: its blob is sealed with B's backup key, for B.
    let theirs = ok(&mut dm.b1.core, json!({"cmd": "rotate_keys", "remove": []}));
    let mut tampered = sealed.clone();
    *tampered.last_mut().unwrap() ^= 1;

    // B's blob, one sealed with A's new backup key but for B, one with a byte changed, and what
    // isn't one: each fails the recovery whole, and the device is left as it was.
    let mut a2 = dm.server.bare_device(dm.a);
    for (blob, expected) in [
        (
            theirs["wrapped_previous_backup_keys"].clone(),
            expect("decrypt_failed", "previous_backup_keys"),
        ),
        (
            json!(b64(&seal_previous_keys(
                &new_key,
                dm.b,
                &[EarlierKey {
                    key: old_key.to_vec(),
                    until: utc_day(dm.day + DAY_MS),
                }],
            ))),
            expect("decrypt_failed", "previous_backup_keys"),
        ),
        (
            json!(b64(&tampered)),
            expect("decrypt_failed", "previous_backup_keys"),
        ),
        (
            json!(b64(b"not the earlier keys")),
            expect("bad_command", "wrapped_previous_backup_keys"),
        ),
    ] {
        let refused = error(
            &mut a2.core,
            recovering(&dm.server, dm.a, &rotated, Some(&blob)),
        );
        assert_eq!(refusal(&refused), expected, "{blob}");
        let status = ok(&mut a2.core, json!({"cmd": "status"}));
        assert_eq!(status["has_identity"], false, "{blob}");
        let refused = error(&mut a2.core, import_command(&old["data"]));
        assert_eq!(
            refusal(&refused),
            expect("not_found", "backup_key"),
            "{blob}"
        );
    }

    // The same device then recovers with A's own blob, and opens the old segment.
    let recovered = ok(
        &mut a2.core,
        recovering(&dm.server, dm.a, &rotated, Some(&json!(b64(&sealed)))),
    );
    dm.server
        .take_device(dm.a, &recovered["certificate"], &recovered["device_list"]);
    assert_eq!(earlier_keys(&mut a2), [old_key]);
    assert_eq!(imported(&mut a2, &old["data"]), 1);
}
