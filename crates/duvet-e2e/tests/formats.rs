//! The formats around a conversation's messages: the envelope each one carries, the encrypted
//! parts of attachments and history packages, and the messages one device sends another.

use std::sync::atomic::{AtomicU64, Ordering};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ciborium::Value as Cbor;
use duvet_e2e::{
    Attachment, Core, DirectMessage, Envelope, Error, MAX_DIRECT, MAX_ENVELOPE, MAX_THUMBNAIL,
    OpenConfig, ThumbnailRef, parts,
};
use duvet_e2e_rules::{DIRECT_MESSAGE, SUITE, sign};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::random::OpenMlsRand;
use openmls_traits::types::{
    HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType, SignatureScheme,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

fn new_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0000_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

fn bytes(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("base64 text"))
        .expect("padded base64")
}

/// A core over a database of its own, removed after it.
struct Session {
    core: Core,
    _dir: TempDir,
}

impl Session {
    fn new() -> Session {
        let dir = tempfile::tempdir().unwrap();
        let core = Core::open(OpenConfig::new(dir.path().join("core.db"), [1; 32])).unwrap();
        Session { core, _dir: dir }
    }

    fn run(&mut self, command: &Value) -> Value {
        serde_json::from_str(&self.core.handle(&command.to_string())).expect("a JSON reply")
    }

    fn ok(&mut self, command: Value) -> Value {
        let reply = self.run(&command);
        reply
            .get("ok")
            .cloned()
            .unwrap_or_else(|| panic!("{command} failed: {reply}"))
    }

    fn error(&mut self, command: Value) -> Value {
        let reply = self.run(&command);
        reply
            .get("error")
            .cloned()
            .unwrap_or_else(|| panic!("{command} didn't fail: {reply}"))
    }

    fn attachment_key(&mut self) -> String {
        let key = self.ok(json!({"cmd": "attachment_key"}))["key"].clone();
        assert_eq!(bytes(&key).len(), 32);
        key.as_str().unwrap().to_owned()
    }
}

fn error_of(error: &Error) -> Value {
    error.to_reply()["error"].clone()
}

// The envelope.

fn attachment(seed: u8) -> Attachment {
    Attachment {
        id: new_id(),
        key: Zeroizing::new([seed; 32]),
        sha256: [!seed; 32],
        name: format!("photo {seed}.png"),
        content_type: "image/png".into(),
        size: 123_456,
        width: Some(1920),
        height: Some(1080),
        duration_ms: None,
        waveform: None,
        thumbnail: Some(vec![seed; 512]),
        thumbnail_ref: None,
    }
}

fn text(text: &str) -> Cbor {
    Cbor::Text(text.into())
}

fn uint(number: u64) -> Cbor {
    Cbor::Integer(number.into())
}

fn id(id: Uuid) -> Cbor {
    Cbor::Bytes(id.as_bytes().to_vec())
}

fn map(entries: Vec<(&str, Cbor)>) -> Cbor {
    Cbor::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

fn to_cbor(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

fn from_cbor(bytes: &[u8]) -> Cbor {
    ciborium::from_reader(bytes).expect("CBOR")
}

/// A CBOR map's entry under `key`.
fn entry<'a>(map: &'a Cbor, key: &str) -> &'a Cbor {
    map.as_map()
        .expect("a map")
        .iter()
        .find(|(k, _)| k.as_text() == Some(key))
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("no {key}"))
}

/// A CBOR map's keys, in order, all of them text.
fn keys(map: &Cbor) -> Vec<&str> {
    let mut keys: Vec<&str> = map
        .as_map()
        .expect("a map")
        .iter()
        .map(|(k, _)| k.as_text().expect("a text key"))
        .collect();
    keys.sort_unstable();
    keys
}

fn unsigned(value: &Cbor) -> u64 {
    u64::try_from(value.as_integer().expect("an integer")).expect("unsigned")
}

/// A sound attachment in CBOR, with only its required fields.
fn attachment_entries() -> Vec<(&'static str, Cbor)> {
    vec![
        ("id", id(new_id())),
        ("key", Cbor::Bytes(vec![1; 32])),
        ("sha256", Cbor::Bytes(vec![2; 32])),
        ("name", text("notes.txt")),
        ("type", text("text/plain")),
        ("size", uint(5)),
    ]
}

/// `entries` with `key` set to `value`, or without it when `value` is `None`.
fn with(
    mut entries: Vec<(&'static str, Cbor)>,
    key: &'static str,
    value: Option<Cbor>,
) -> Vec<(&'static str, Cbor)> {
    entries.retain(|(k, _)| *k != key);
    entries.extend(value.map(|value| (key, value)));
    entries
}

fn assert_unreadable(bytes: &[u8], case: &str) {
    let error = error_of(&Envelope::decode(bytes).expect_err(case));
    assert_eq!(error["code"], "decrypt_failed", "{case}: {error}");
    assert_eq!(error["kind"], "envelope", "{case}");
}

#[test]
fn envelope_round_trip() {
    let voice_note = Attachment {
        content_type: "audio/ogg".into(),
        width: None,
        height: None,
        duration_ms: Some(4_200),
        waveform: Some((0..=255).collect()),
        thumbnail: None,
        ..attachment(2)
    };
    let video = Attachment {
        content_type: "video/mp4".into(),
        duration_ms: Some(61_000),
        thumbnail: None,
        thumbnail_ref: Some(ThumbnailRef {
            id: new_id(),
            key: Zeroizing::new([9; 32]),
            sha256: [8; 32],
            size: 20_000,
        }),
        ..attachment(3)
    };
    let largest_inline = Attachment {
        thumbnail: Some(vec![7; MAX_THUMBNAIL]),
        ..attachment(4)
    };
    let envelopes = [
        Envelope::Message {
            text: Some("Hola, ¿cómo va? 👋\nSecond line".into()),
            attachments: vec![],
        },
        Envelope::Message {
            text: None,
            attachments: vec![attachment(1)],
        },
        Envelope::Message {
            text: Some("three files".into()),
            attachments: vec![voice_note, video, largest_inline],
        },
        Envelope::Edit {
            message_id: new_id(),
            text: "fixed a typo".into(),
        },
        // An edit can leave no text, as when it clears a file's caption.
        Envelope::Edit {
            message_id: new_id(),
            text: String::new(),
        },
        Envelope::Delete {
            message_id: new_id(),
        },
    ];
    for envelope in envelopes {
        let encoded = envelope.encode().unwrap();
        let decoded = Envelope::decode(&encoded).unwrap();
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }
}

#[test]
fn envelope_needs_exactly_one_form() {
    let v1 = || ("v", uint(1));
    let files = || Cbor::Array(vec![map(attachment_entries())]);
    let message_id = id(new_id());

    let forms = [
        vec![v1(), ("text", text("hi"))],
        vec![v1(), ("attachments", files())],
        vec![v1(), ("text", text("hi")), ("attachments", files())],
        vec![v1(), ("edit", message_id.clone()), ("text", text("hi"))],
        vec![v1(), ("delete", message_id.clone())],
    ];
    for form in forms {
        Envelope::decode(&to_cbor(&map(form))).unwrap();
    }

    let none = [
        vec![v1()],
        vec![v1(), ("attachments", Cbor::Array(vec![]))],
        vec![v1(), ("text", text(""))],
        vec![v1(), ("edit", message_id.clone())],
    ];
    for (case, entries) in none.into_iter().enumerate() {
        assert_unreadable(&to_cbor(&map(entries)), &format!("no form {case}"));
    }

    let two = [
        vec![
            v1(),
            ("edit", message_id.clone()),
            ("delete", message_id.clone()),
        ],
        vec![
            v1(),
            ("edit", message_id.clone()),
            ("text", text("hi")),
            ("attachments", files()),
        ],
        vec![v1(), ("delete", message_id.clone()), ("text", text("hi"))],
        vec![
            v1(),
            ("delete", message_id.clone()),
            ("attachments", files()),
        ],
        vec![
            v1(),
            ("edit", message_id.clone()),
            ("delete", message_id.clone()),
            ("text", text("hi")),
        ],
    ];
    for (case, entries) in two.into_iter().enumerate() {
        assert_unreadable(&to_cbor(&map(entries)), &format!("two forms {case}"));
    }

    // The core never writes one either.
    let empty = Envelope::Message {
        text: None,
        attachments: vec![],
    };
    let blank = Envelope::Message {
        text: Some(String::new()),
        attachments: vec![],
    };
    for envelope in [empty, blank] {
        let error = error_of(&envelope.encode().unwrap_err());
        assert_eq!(error["code"], "bad_command", "{error}");
        assert_eq!(error["field"], "envelope");
    }
}

#[test]
fn envelope_is_v1_and_nothing_else() {
    let message = |file: Vec<(&'static str, Cbor)>| {
        to_cbor(&map(vec![
            ("v", uint(1)),
            ("attachments", Cbor::Array(vec![map(file)])),
        ]))
    };
    Envelope::decode(&message(attachment_entries())).unwrap();

    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "v 2",
            to_cbor(&map(vec![("v", uint(2)), ("text", text("hi"))])),
        ),
        ("no v", to_cbor(&map(vec![("text", text("hi"))]))),
        (
            "a field v1 doesn't have",
            to_cbor(&map(vec![
                ("v", uint(1)),
                ("text", text("hi")),
                ("reaction", text("👍")),
            ])),
        ),
        (
            "an empty list of files beside text",
            to_cbor(&map(vec![
                ("v", uint(1)),
                ("text", text("hi")),
                ("attachments", Cbor::Array(vec![])),
            ])),
        ),
        (
            "text as bytes",
            to_cbor(&map(vec![
                ("v", uint(1)),
                ("text", Cbor::Bytes(b"hi".to_vec())),
            ])),
        ),
        (
            "an edit's ID of 15 bytes",
            to_cbor(&map(vec![
                ("v", uint(1)),
                ("edit", Cbor::Bytes(vec![1; 15])),
                ("text", text("hi")),
            ])),
        ),
        (
            "a key of 31 bytes",
            message(with(
                attachment_entries(),
                "key",
                Some(Cbor::Bytes(vec![1; 31])),
            )),
        ),
        (
            "a SHA-256 of 33 bytes",
            message(with(
                attachment_entries(),
                "sha256",
                Some(Cbor::Bytes(vec![1; 33])),
            )),
        ),
        ("no key", message(with(attachment_entries(), "key", None))),
        ("no name", message(with(attachment_entries(), "name", None))),
        (
            "a negative size",
            message(with(
                attachment_entries(),
                "size",
                Some(Cbor::Integer((-1).into())),
            )),
        ),
        (
            "an attachment field v1 doesn't have",
            message(with(
                attachment_entries(),
                "spoiler",
                Some(Cbor::Bool(true)),
            )),
        ),
        (
            "a thumbnail over 8 KiB",
            message(with(
                attachment_entries(),
                "thumbnail",
                Some(Cbor::Bytes(vec![0; MAX_THUMBNAIL + 1])),
            )),
        ),
        (
            "a thumbnail inside and another apart",
            message(with(
                with(
                    attachment_entries(),
                    "thumbnail",
                    Some(Cbor::Bytes(vec![0; 10])),
                ),
                "thumbnail_ref",
                Some(map(vec![
                    ("id", id(new_id())),
                    ("key", Cbor::Bytes(vec![1; 32])),
                    ("sha256", Cbor::Bytes(vec![2; 32])),
                    ("size", uint(10)),
                ])),
            )),
        ),
        (
            "a thumbnail apart with a key of 16 bytes",
            message(with(
                attachment_entries(),
                "thumbnail_ref",
                Some(map(vec![
                    ("id", id(new_id())),
                    ("key", Cbor::Bytes(vec![1; 16])),
                    ("sha256", Cbor::Bytes(vec![2; 32])),
                    ("size", uint(10)),
                ])),
            )),
        ),
        ("not a map", to_cbor(&Cbor::Array(vec![uint(1)]))),
        ("not CBOR", vec![0xff, 0x00, 0x13]),
        ("nothing", vec![]),
        (
            "bytes after the envelope",
            [message(attachment_entries()), vec![0]].concat(),
        ),
    ];
    for (case, bytes) in cases {
        assert_unreadable(&bytes, case);
    }

    // An envelope rides in a message's ciphertext, 32 KiB at most: a bigger one is refused
    // before it's read, and never written.
    let big = to_cbor(&map(vec![
        ("v", uint(1)),
        ("text", text(&"a".repeat(MAX_ENVELOPE))),
    ]));
    let error = error_of(&Envelope::decode(&big).unwrap_err());
    assert_eq!(error["code"], "too_large", "{error}");
    assert_eq!(error["limit"], MAX_ENVELOPE);
    let big = Envelope::Message {
        text: Some("a".repeat(MAX_ENVELOPE)),
        attachments: vec![],
    };
    let error = error_of(&big.encode().unwrap_err());
    assert_eq!(error["code"], "too_large", "{error}");
    assert_eq!(error["limit"], MAX_ENVELOPE);

    // Nor does the core write a thumbnail over 8 KiB, or one inside and another apart.
    let oversized = Attachment {
        thumbnail: Some(vec![0; MAX_THUMBNAIL + 1]),
        ..attachment(5)
    };
    let both = Attachment {
        thumbnail_ref: Some(ThumbnailRef {
            id: new_id(),
            key: Zeroizing::new([1; 32]),
            sha256: [2; 32],
            size: 10,
        }),
        ..attachment(6)
    };
    for file in [oversized, both] {
        let envelope = Envelope::Message {
            text: None,
            attachments: vec![file],
        };
        let error = error_of(&envelope.encode().unwrap_err());
        assert_eq!(error["code"], "bad_command", "{error}");
    }
}

#[test]
fn envelope_follows_the_contract() {
    let file = attachment(3);
    let message = Envelope::Message {
        text: Some("hi".into()),
        attachments: vec![file.clone()],
    };
    let value = from_cbor(&message.encode().unwrap());
    assert_eq!(keys(&value), ["attachments", "text", "v"]);
    assert_eq!(unsigned(entry(&value, "v")), 1);
    assert_eq!(entry(&value, "text").as_text(), Some("hi"));

    let encoded = &entry(&value, "attachments").as_array().unwrap()[0];
    assert_eq!(
        keys(encoded),
        [
            "height",
            "id",
            "key",
            "name",
            "sha256",
            "size",
            "thumbnail",
            "type",
            "width"
        ]
    );
    assert_eq!(entry(encoded, "id").as_bytes().unwrap(), file.id.as_bytes());
    assert_eq!(
        entry(encoded, "key").as_bytes().unwrap(),
        file.key.as_slice()
    );
    assert_eq!(entry(encoded, "sha256").as_bytes().unwrap(), &file.sha256);
    assert_eq!(entry(encoded, "name").as_text(), Some("photo 3.png"));
    assert_eq!(entry(encoded, "type").as_text(), Some("image/png"));
    assert_eq!(unsigned(entry(encoded, "size")), 123_456);
    assert_eq!(unsigned(entry(encoded, "width")), 1920);
    assert_eq!(unsigned(entry(encoded, "height")), 1080);
    assert_eq!(
        entry(encoded, "thumbnail").as_bytes().unwrap(),
        &vec![3; 512]
    );

    let with_ref = Attachment {
        thumbnail: None,
        duration_ms: Some(5),
        waveform: Some(vec![1, 2]),
        thumbnail_ref: Some(ThumbnailRef {
            id: new_id(),
            key: Zeroizing::new([9; 32]),
            sha256: [8; 32],
            size: 77,
        }),
        ..attachment(4)
    };
    let value = from_cbor(
        &Envelope::Message {
            text: None,
            attachments: vec![with_ref.clone()],
        }
        .encode()
        .unwrap(),
    );
    assert_eq!(keys(&value), ["attachments", "v"]);
    let encoded = &entry(&value, "attachments").as_array().unwrap()[0];
    assert_eq!(unsigned(entry(encoded, "duration_ms")), 5);
    assert_eq!(entry(encoded, "waveform").as_bytes().unwrap(), &vec![1, 2]);
    let thumbnail = entry(encoded, "thumbnail_ref");
    let thumbnail_ref = with_ref.thumbnail_ref.unwrap();
    assert_eq!(keys(thumbnail), ["id", "key", "sha256", "size"]);
    assert_eq!(
        entry(thumbnail, "id").as_bytes().unwrap(),
        thumbnail_ref.id.as_bytes()
    );
    assert_eq!(entry(thumbnail, "key").as_bytes().unwrap(), &vec![9; 32]);
    assert_eq!(entry(thumbnail, "sha256").as_bytes().unwrap(), &vec![8; 32]);
    assert_eq!(unsigned(entry(thumbnail, "size")), 77);

    let message_id = new_id();
    let edit = from_cbor(
        &Envelope::Edit {
            message_id,
            text: "new".into(),
        }
        .encode()
        .unwrap(),
    );
    assert_eq!(keys(&edit), ["edit", "text", "v"]);
    assert_eq!(
        entry(&edit, "edit").as_bytes().unwrap(),
        message_id.as_bytes()
    );
    assert_eq!(entry(&edit, "text").as_text(), Some("new"));

    let delete = from_cbor(&Envelope::Delete { message_id }.encode().unwrap());
    assert_eq!(keys(&delete), ["delete", "v"]);
    assert_eq!(unsigned(entry(&delete, "v")), 1);
    assert_eq!(
        entry(&delete, "delete").as_bytes().unwrap(),
        message_id.as_bytes()
    );
}

// Attachments' parts.

fn part(cmd: &str, key: &str, id: Uuid, index: usize, last: bool, data: &[u8]) -> Value {
    json!({
        "cmd": cmd,
        "key": key,
        "attachment_id": id,
        "index": index,
        "last": last,
        "data": b64(data),
    })
}

/// A file as the contract cuts it: whole parts of 64 KiB, then the rest in the last; an empty
/// file is one empty part.
fn cut(file: &[u8]) -> Vec<&[u8]> {
    if file.is_empty() {
        vec![file]
    } else {
        file.chunks(parts::ATTACHMENT_PART).collect()
    }
}

fn encrypt_file(session: &mut Session, key: &str, id: Uuid, file: &[u8]) -> Vec<Vec<u8>> {
    let pieces = cut(file);
    let last = pieces.len() - 1;
    pieces
        .into_iter()
        .enumerate()
        .map(|(index, piece)| {
            let command = part("attachment_encrypt", key, id, index, index == last, piece);
            bytes(&session.ok(command)["data"])
        })
        .collect()
}

/// The parts a client downloaded, opened in order as it opens them: the last one it has as the
/// file's last.
fn decrypt_file(
    session: &mut Session,
    key: &str,
    id: Uuid,
    sealed: &[Vec<u8>],
) -> Result<Vec<u8>, Value> {
    let mut file = Vec::new();
    for (index, data) in sealed.iter().enumerate() {
        let last = index + 1 == sealed.len();
        let reply = session.run(&part("attachment_decrypt", key, id, index, last, data));
        match reply.get("ok") {
            Some(ok) => file.extend(bytes(&ok["data"])),
            None => return Err(reply["error"].clone()),
        }
    }
    Ok(file)
}

fn assert_refused(result: Result<Vec<u8>, Value>, case: &str) {
    let Err(error) = result else {
        panic!("{case}: opened");
    };
    assert_eq!(error["code"], "decrypt_failed", "{case}: {error}");
    assert_eq!(error["kind"], "attachment", "{case}");
}

#[test]
fn parts_round_trip_and_detect_tampering() {
    let mut session = Session::new();
    let key = session.attachment_key();
    let other_key = session.attachment_key();
    assert_ne!(key, other_key);

    for size in [0usize, 1, 65_536, 200_000] {
        let file: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
        let id = new_id();
        let sealed = encrypt_file(&mut session, &key, id, &file);
        let count = size.div_ceil(parts::ATTACHMENT_PART).max(1);
        assert_eq!(sealed.len(), count, "{size} bytes");
        assert_eq!(
            sealed.iter().map(Vec::len).sum::<usize>(),
            size + count * parts::TAG,
            "{size} bytes"
        );
        assert_eq!(decrypt_file(&mut session, &key, id, &sealed).unwrap(), file);

        for (index, piece) in sealed.iter().enumerate() {
            for at in [0, piece.len() / 2, piece.len() - 1] {
                let mut changed = sealed.clone();
                changed[index][at] ^= 0x01;
                assert_refused(
                    decrypt_file(&mut session, &key, id, &changed),
                    &format!("{size} bytes, part {index}, byte {at} changed"),
                );
            }
        }
        assert_refused(
            decrypt_file(&mut session, &key, new_id(), &sealed),
            &format!("{size} bytes under another file's ID"),
        );
        assert_refused(
            decrypt_file(&mut session, &other_key, id, &sealed),
            &format!("{size} bytes under another key"),
        );

        if sealed.len() > 1 {
            let mut swapped = sealed.clone();
            swapped.swap(0, 1);
            assert_refused(
                decrypt_file(&mut session, &key, id, &swapped),
                &format!("{size} bytes, two parts swapped"),
            );
            // Cut at a part's end: the part before isn't marked as the last.
            assert_refused(
                decrypt_file(&mut session, &key, id, &sealed[..sealed.len() - 1]),
                &format!("{size} bytes without the last part"),
            );
        }
        // The last part, opened as one that isn't the last.
        let last = sealed.len() - 1;
        let reply = session.run(&part(
            "attachment_decrypt",
            &key,
            id,
            last,
            false,
            &sealed[last],
        ));
        assert_eq!(
            reply["error"]["code"], "decrypt_failed",
            "{size} bytes: {reply}"
        );
    }
}

#[test]
fn empty_file_is_one_final_part() {
    let mut session = Session::new();
    let key = session.attachment_key();
    let id = new_id();

    let sealed = bytes(&session.ok(part("attachment_encrypt", &key, id, 0, true, b""))["data"]);
    assert_eq!(sealed.len(), parts::TAG);
    let opened = session.ok(part("attachment_decrypt", &key, id, 0, true, &sealed));
    assert_eq!(bytes(&opened["data"]), b"");

    // It's that file's one part, and nothing else.
    for (index, last) in [(0, false), (1, true)] {
        let error = session.error(part("attachment_decrypt", &key, id, index, last, &sealed));
        assert_eq!(error["code"], "decrypt_failed", "{error}");
        assert_eq!(error["kind"], "attachment");
    }

    // Only an empty file has an empty part: no other part is sealed empty.
    for (index, last) in [(0, false), (1, true), (3, false)] {
        let error = session.error(part("attachment_encrypt", &key, id, index, last, b""));
        assert_eq!(error["code"], "bad_command", "{error}");
        assert_eq!(error["field"], "data");
    }

    // The command seals what the library seals.
    let raw: [u8; 32] = bytes(&json!(key)).try_into().unwrap();
    assert_eq!(parts::seal_part(&raw, id, 0, true, b""), sealed);
    assert_eq!(parts::open_part(&raw, id, 0, true, &sealed).unwrap(), b"");
}

#[test]
fn parts_follow_the_contract() {
    assert_eq!(parts::ATTACHMENT_PART, 65_536);
    assert_eq!(parts::PACKAGE_PART, 1_048_576);
    assert_eq!(parts::TAG, 16);

    let key = [0x42; 32];
    let id = new_id();
    for (index, last) in [
        (0, false),
        (0, true),
        (1, false),
        (7, true),
        (u64::MAX, true),
    ] {
        let sealed = parts::seal_part(&key, id, index, last, b"a part");
        // AES-256-GCM, the nonce 00 00 00 || index (u64, big-endian) || 01 on the last part and
        // 00 on the others, and the ID's 16 bytes as associated data.
        let mut nonce = [0u8; 12];
        nonce[3..11].copy_from_slice(&index.to_be_bytes());
        nonce[11] = u8::from(last);
        let opened = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed,
                    aad: id.as_bytes(),
                },
            )
            .unwrap();
        assert_eq!(opened, b"a part");
        assert_eq!(
            parts::open_part(&key, id, index, last, &sealed).unwrap(),
            b"a part"
        );
    }

    // A package's parts take 1 MiB each, through the same functions.
    let package: Vec<u8> = (0..parts::PACKAGE_PART).map(|i| (i % 253) as u8).collect();
    let sealed = parts::seal_part(&key, id, 0, false, &package);
    assert_eq!(sealed.len(), parts::PACKAGE_PART + parts::TAG);
    assert_eq!(
        parts::open_part(&key, id, 0, false, &sealed).unwrap(),
        package
    );
    let error = error_of(&parts::open_part(&key, id, 0, true, &sealed).unwrap_err());
    assert_eq!(error["code"], "decrypt_failed");

    // A part the command seals is the library's, byte for byte.
    let mut session = Session::new();
    let piece = vec![0x17; parts::ATTACHMENT_PART];
    let sealed = session.ok(part("attachment_encrypt", &b64(&key), id, 2, false, &piece));
    assert_eq!(
        bytes(&sealed["data"]),
        parts::seal_part(&key, id, 2, false, &piece)
    );
}

#[test]
fn attachment_commands_check_their_fields() {
    let mut session = Session::new();
    let key = session.attachment_key();
    let id = new_id();

    // A key of another length, said without quoting it.
    for wrong in [vec![0x5a; 31], vec![0x5a; 33], vec![]] {
        for cmd in ["attachment_encrypt", "attachment_decrypt"] {
            let error = session.error(part(cmd, &b64(&wrong), id, 0, true, b"x"));
            assert_eq!(error["code"], "bad_command", "{error}");
            assert_eq!(error["field"], "key");
            if !wrong.is_empty() {
                assert!(!error.to_string().contains(&b64(&wrong)), "{error}");
            }
        }
    }
    let error = session.error(part("attachment_encrypt", "not base64!", id, 0, true, b"x"));
    assert_eq!(error["code"], "bad_command", "{error}");
    assert!(!error.to_string().contains("not base64!"), "{error}");

    // A part holds 64 KiB of the file at most, and every part but the last holds that much.
    let error = session.error(part(
        "attachment_encrypt",
        &key,
        id,
        0,
        true,
        &vec![0; parts::ATTACHMENT_PART + 1],
    ));
    assert_eq!(error["code"], "too_large", "{error}");
    assert_eq!(error["limit"], parts::ATTACHMENT_PART);
    let error = session.error(part(
        "attachment_encrypt",
        &key,
        id,
        0,
        false,
        &vec![0; parts::ATTACHMENT_PART - 1],
    ));
    assert_eq!(error["code"], "bad_command", "{error}");
    assert_eq!(error["field"], "data");

    // Sealed, a part is 16 bytes more, and the same rules hold.
    let error = session.error(part(
        "attachment_decrypt",
        &key,
        id,
        0,
        true,
        &vec![0; parts::ATTACHMENT_PART + parts::TAG + 1],
    ));
    assert_eq!(error["code"], "too_large", "{error}");
    assert_eq!(error["limit"], parts::ATTACHMENT_PART + parts::TAG);
    let whole = vec![0; parts::ATTACHMENT_PART];
    let sealed = bytes(&session.ok(part("attachment_encrypt", &key, id, 0, false, &whole))["data"]);
    for wrong in [&sealed[..sealed.len() - 1], &sealed[..parts::TAG - 1], &[]] {
        let error = session.error(part("attachment_decrypt", &key, id, 0, false, wrong));
        assert_eq!(error["code"], "decrypt_failed", "{error}");
        assert_eq!(error["kind"], "attachment");
    }
    // A part the core never seals in its place is refused, though its key opens it: one before
    // the last that isn't whole, or an empty one after the first.
    let raw: [u8; 32] = bytes(&json!(key)).try_into().unwrap();
    for (index, last, plain) in [(0, false, vec![1; 100]), (2, true, vec![])] {
        let sealed = parts::seal_part(&raw, id, index as u64, last, &plain);
        assert_eq!(
            parts::open_part(&raw, id, index as u64, last, &sealed).unwrap(),
            plain
        );
        let error = session.error(part("attachment_decrypt", &key, id, index, last, &sealed));
        assert_eq!(error["code"], "decrypt_failed", "{error}");
        assert_eq!(error["kind"], "attachment");
    }

    let error = session.error(
        json!({"cmd": "attachment_encrypt", "key": key, "index": 0, "last": true, "data": ""}),
    );
    assert_eq!(error["code"], "bad_command", "{error}");
    assert_eq!(error["field"], "attachment_id");
}

// Messages between devices.

/// A device's keys, made as `create_device` makes them, in memory.
struct Device {
    id: Uuid,
    signer: SignatureKeyPair,
    signature_key: [u8; 32],
    hpke_secret: Vec<u8>,
    hpke_key: [u8; 32],
}

impl Device {
    fn new(provider: &OpenMlsRustCrypto) -> Device {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let ikm = provider.rand().random_vec(32).unwrap();
        let hpke = provider
            .crypto()
            .derive_hpke_keypair(SUITE.hpke_config(), &ikm)
            .unwrap();
        Device {
            id: new_id(),
            signature_key: signer.public().try_into().unwrap(),
            signer,
            hpke_secret: hpke.private.to_vec(),
            hpke_key: hpke.public.try_into().unwrap(),
        }
    }

    /// `payload` of `kind`, from this device to `to`.
    fn seal(
        &self,
        provider: &OpenMlsRustCrypto,
        to: &Device,
        kind: &str,
        payload: &[u8],
    ) -> Vec<u8> {
        DirectMessage::seal(
            provider,
            &self.signer,
            self.id,
            to.id,
            &to.hpke_key,
            kind,
            payload,
        )
        .unwrap()
    }

    /// `message` opened by this device, as one from `from`.
    fn open(
        &self,
        provider: &OpenMlsRustCrypto,
        from: &Device,
        message: &[u8],
    ) -> Result<(String, Zeroizing<Vec<u8>>), Error> {
        DirectMessage::open(
            provider,
            &self.hpke_secret,
            self.id,
            from.id,
            &from.signature_key,
            message,
        )
    }
}

/// A direct message with `field` of its body set to `value`, signed again by `signer`.
fn resigned(message: &[u8], field: &str, value: Cbor, signer: &SignatureKeyPair) -> Vec<u8> {
    let mut body = from_cbor(entry(&from_cbor(message), "body").as_bytes().unwrap());
    let slot = body
        .as_map_mut()
        .unwrap()
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(field))
        .map(|(_, v)| v)
        .unwrap();
    *slot = value;
    sign(DIRECT_MESSAGE, to_cbor(&body), signer).unwrap()
}

fn assert_refused_with(
    result: Result<(String, Zeroizing<Vec<u8>>), Error>,
    code: &str,
    case: &str,
) {
    let error = error_of(&result.err().unwrap_or_else(|| panic!("{case}: opened")));
    assert_eq!(error["code"], code, "{case}: {error}");
    match code {
        "decrypt_failed" => assert_eq!(error["kind"], "direct", "{case}"),
        "invalid_signature" => assert_eq!(error["what"], "direct message", "{case}"),
        _ => {}
    }
}

#[test]
fn direct_message_round_trip() {
    // Two devices as the core makes them, each with its database.
    let (mut alice, mut bob) = (Session::new(), Session::new());
    let (alice_device, bob_device) = (new_id(), new_id());
    let alice_keys =
        alice.ok(json!({"cmd": "create_device", "user_id": new_id(), "device_id": alice_device}));
    let bob_keys =
        bob.ok(json!({"cmd": "create_device", "user_id": new_id(), "device_id": bob_device}));
    let alice_signature_key: [u8; 32] = bytes(&alice_keys["signature_key"]).try_into().unwrap();
    let bob_hpke_key: [u8; 32] = bytes(&bob_keys["hpke_key"]).try_into().unwrap();

    let payload = b"a history package's key".to_vec();
    let message = alice
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            DirectMessage::seal(
                tx.provider(),
                &own.signer,
                own.device,
                bob_device,
                &bob_hpke_key,
                "history.key",
                &payload,
            )
        })
        .unwrap();
    let (kind, opened) = bob
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            DirectMessage::open(
                tx.provider(),
                &own.hpke.private,
                own.device,
                alice_device,
                &alice_signature_key,
                &message,
            )
        })
        .unwrap();
    assert_eq!(kind, "history.key");
    assert_eq!(*opened, payload);

    let provider = OpenMlsRustCrypto::default();
    let (a, b) = (Device::new(&provider), Device::new(&provider));

    // Each message has its own HPKE key: the same payload twice reads as two messages.
    assert_ne!(
        a.seal(&provider, &b, "k", b"same"),
        a.seal(&provider, &b, "k", b"same")
    );

    // From nothing up to the largest payload that fits in 64 KiB.
    let overhead = a.seal(&provider, &b, "k", &[0; 1000]).len() - 1000;
    for payload in [vec![], vec![0x42; MAX_DIRECT - overhead]] {
        let message = a.seal(&provider, &b, "k", &payload);
        assert!(message.len() <= MAX_DIRECT);
        let (kind, opened) = b.open(&provider, &a, &message).unwrap();
        assert_eq!(
            (kind.as_str(), opened.as_slice()),
            ("k", payload.as_slice())
        );
    }
    assert_eq!(
        a.seal(&provider, &b, "k", &vec![0; MAX_DIRECT - overhead])
            .len(),
        MAX_DIRECT
    );
}

#[test]
fn direct_message_rejects_wrong_sender() {
    let provider = OpenMlsRustCrypto::default();
    let (alice, bob, carol, dave) = (
        Device::new(&provider),
        Device::new(&provider),
        Device::new(&provider),
        Device::new(&provider),
    );
    let good = alice.seal(&provider, &bob, "history.key", b"payload");
    bob.open(&provider, &alice, &good).unwrap();

    // Signed by another device than the one it names.
    let forged = DirectMessage::seal(
        &provider,
        &carol.signer,
        alice.id,
        bob.id,
        &bob.hpke_key,
        "history.key",
        b"payload",
    )
    .unwrap();
    assert_refused_with(
        bob.open(&provider, &alice, &forged),
        "invalid_signature",
        "signed by carol as alice",
    );
    // Opened as carol's, whose key signed it, it still names alice.
    assert_refused_with(
        bob.open(&provider, &carol, &forged),
        "invalid_signature",
        "carol naming alice",
    );
    // A message from alice, opened as one from carol.
    assert_refused_with(
        bob.open(&provider, &carol, &good),
        "invalid_signature",
        "alice's as carol's",
    );

    // Encrypted to another device.
    let to_carol = alice.seal(&provider, &carol, "history.key", b"payload");
    assert_refused_with(
        bob.open(&provider, &alice, &to_carol),
        "decrypt_failed",
        "to carol",
    );
    let named_bob_sealed_to_carol = DirectMessage::seal(
        &provider,
        &alice.signer,
        alice.id,
        bob.id,
        &carol.hpke_key,
        "history.key",
        b"payload",
    )
    .unwrap();
    assert_refused_with(
        bob.open(&provider, &alice, &named_bob_sealed_to_carol),
        "decrypt_failed",
        "named bob, sealed to carol's key",
    );

    // A changed body breaks the signature.
    let signed = from_cbor(&good);
    let mut body = entry(&signed, "body").as_bytes().unwrap().clone();
    let middle = body.len() / 2;
    body[middle] ^= 0x01;
    let changed = to_cbor(&map(vec![
        ("body", Cbor::Bytes(body)),
        ("sig", entry(&signed, "sig").clone()),
    ]));
    assert_refused_with(
        bob.open(&provider, &alice, &changed),
        "invalid_signature",
        "a byte of the body",
    );

    // `from`, `to` and `type` changed and signed again: HPKE's associated data still holds them.
    let retyped = resigned(&good, "type", text("approval.transfer"), &alice.signer);
    assert_refused_with(
        bob.open(&provider, &alice, &retyped),
        "decrypt_failed",
        "type changed",
    );
    let refrom = resigned(&good, "from", id(dave.id), &dave.signer);
    assert_refused_with(
        bob.open(&provider, &dave, &refrom),
        "decrypt_failed",
        "from changed",
    );
    let sealed_for_another = DirectMessage::seal(
        &provider,
        &alice.signer,
        alice.id,
        new_id(),
        &bob.hpke_key,
        "history.key",
        b"payload",
    )
    .unwrap();
    let reto = resigned(&sealed_for_another, "to", id(bob.id), &alice.signer);
    assert_refused_with(
        bob.open(&provider, &alice, &reto),
        "decrypt_failed",
        "to changed",
    );
    // Sealed to bob but naming another device: bob doesn't read another device's message.
    let renamed = resigned(&good, "to", id(new_id()), &alice.signer);
    assert_refused_with(
        bob.open(&provider, &alice, &renamed),
        "decrypt_failed",
        "to another device",
    );

    // Not a direct message at all.
    assert_refused_with(
        bob.open(&provider, &alice, &[0xff, 0x01]),
        "decrypt_failed",
        "not CBOR",
    );
    let version_2 = resigned(&good, "v", uint(2), &alice.signer);
    assert_refused_with(
        bob.open(&provider, &alice, &version_2),
        "decrypt_failed",
        "v 2",
    );

    // Over 64 KiB: never sealed, and refused before it's read.
    let overhead = alice.seal(&provider, &bob, "k", &[0; 1000]).len() - 1000;
    let error = DirectMessage::seal(
        &provider,
        &alice.signer,
        alice.id,
        bob.id,
        &bob.hpke_key,
        "k",
        &vec![0; MAX_DIRECT - overhead + 1],
    )
    .unwrap_err();
    assert_eq!(error_of(&error)["code"], "too_large");
    assert_eq!(error_of(&error)["limit"], MAX_DIRECT);
    let mut largest = alice.seal(&provider, &bob, "k", &vec![0; MAX_DIRECT - overhead]);
    largest.push(0);
    let error = error_of(&bob.open(&provider, &alice, &largest).unwrap_err());
    assert_eq!(error["code"], "too_large", "{error}");
    assert_eq!(error["limit"], MAX_DIRECT);
}

#[test]
fn direct_message_follows_the_contract() {
    let provider = OpenMlsRustCrypto::default();
    let (alice, bob) = (Device::new(&provider), Device::new(&provider));
    let message = alice.seal(&provider, &bob, "approval.transfer", b"transfer");

    // {body, sig}, the Ed25519 signature over "duvet direct message v1" || 0x00 || body.
    let signed = from_cbor(&message);
    assert_eq!(keys(&signed), ["body", "sig"]);
    let body = entry(&signed, "body").as_bytes().unwrap().clone();
    let sig =
        ed25519_dalek::Signature::from_slice(entry(&signed, "sig").as_bytes().unwrap()).unwrap();
    let covered = [b"duvet direct message v1".as_slice(), &[0], &body].concat();
    ed25519_dalek::VerifyingKey::from_bytes(&alice.signature_key)
        .unwrap()
        .verify_strict(&covered, &sig)
        .unwrap();

    // The body: {v: 1, from, to, type, enc, ct}, the devices as their 16 bytes.
    let body = from_cbor(&body);
    assert_eq!(keys(&body), ["ct", "enc", "from", "to", "type", "v"]);
    assert_eq!(unsigned(entry(&body, "v")), 1);
    assert_eq!(
        entry(&body, "from").as_bytes().unwrap(),
        alice.id.as_bytes()
    );
    assert_eq!(entry(&body, "to").as_bytes().unwrap(), bob.id.as_bytes());
    assert_eq!(entry(&body, "type").as_text(), Some("approval.transfer"));

    // HPKE's base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, the info
    // "duvet direct message v1", and from || to || type as associated data.
    let ciphertext = HpkeCiphertext {
        kem_output: entry(&body, "enc").as_bytes().unwrap().clone().into(),
        ciphertext: entry(&body, "ct").as_bytes().unwrap().clone().into(),
    };
    let associated = [
        alice.id.as_bytes().as_slice(),
        bob.id.as_bytes(),
        b"approval.transfer",
    ]
    .concat();
    let config = HpkeConfig(
        HpkeKemType::DhKem25519,
        HpkeKdfType::HkdfSha256,
        HpkeAeadType::AesGcm128,
    );
    let opened = provider
        .crypto()
        .hpke_open(
            config,
            &ciphertext,
            &bob.hpke_secret,
            b"duvet direct message v1",
            &associated,
        )
        .unwrap();
    assert_eq!(opened, b"transfer");
}
