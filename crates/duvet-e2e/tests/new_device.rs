//! New devices through `Core::handle`, against a fake of the API: one recovered with the recovery
//! key, one approved by another device of its user by the QR or by the notice and its code, and a
//! recovered one joining its groups by external commit.

mod support;

use std::collections::BTreeSet;

use duvet_e2e::{Clock, DirectMessage, Error, mls, recovery};
use duvet_e2e_rules::{DeviceCertificate, DeviceList, Kind};
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    MlsMessageIn, OpenMlsProvider, OpenMlsRand, ProcessedMessageContent, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use rusqlite::OptionalExtension;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::*;
use uuid::Uuid;

const TEN_MINUTES_MS: i64 = 10 * 60 * 1000;

/// The QR the new device shows: itself as it asks to be certified, and the attempt's key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qr {
    v: u32,
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hpke_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
}

/// What the new device sends first, through the server: itself and the commitment's hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Commitment {
    v: u32,
    user: Uuid,
    device: Uuid,
    #[serde(with = "serde_bytes")]
    signature_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hpke_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
}

/// The approver's answer: the commitment it answers, its certificate and its nonce.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    v: u32,
    #[serde(with = "serde_bytes")]
    hash: Vec<u8>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

/// The key and the nonce the commitment hid.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reveal {
    v: u32,
    #[serde(with = "serde_bytes")]
    key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
}

/// What a transfer carries, encrypted to the attempt's key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transfer {
    v: u32,
    #[serde(with = "serde_bytes")]
    identity: Vec<u8>,
    #[serde(with = "serde_bytes")]
    backup_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    certificate: Vec<u8>,
    #[serde(with = "serde_bytes")]
    device_list: Vec<u8>,
    #[serde(with = "serde_bytes")]
    approver: Vec<u8>,
}

/// A signed object, before its signature is checked.
#[derive(Deserialize)]
struct Signed {
    #[serde(with = "serde_bytes")]
    body: Vec<u8>,
}

/// A direct message's body, as its sender signed it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    v: u32,
    from: Uuid,
    to: Uuid,
    #[serde(rename = "type")]
    kind: String,
    #[serde(with = "serde_bytes")]
    #[allow(dead_code)]
    enc: Vec<u8>,
    #[serde(with = "serde_bytes")]
    #[allow(dead_code)]
    ct: Vec<u8>,
}

fn cbor(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// A blob of the core's, read as the contract has it: exactly one CBOR value of that shape.
fn read<T: DeserializeOwned>(blob: &Value) -> T {
    read_bytes(&bytes(blob))
}

fn read_bytes<T: DeserializeOwned>(mut blob: &[u8]) -> T {
    let value = ciborium::from_reader(&mut blob).expect("the contract's CBOR");
    assert!(blob.is_empty(), "nothing after the value");
    value
}

fn key32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

fn random32() -> [u8; 32] {
    OpenMlsRustCrypto::default().rand().random_array().unwrap()
}

/// SHA-256("duvet approval commit v1" || key || nonce), computed apart from the core.
fn commitment_hash(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    Sha256::new()
        .chain_update(b"duvet approval commit v1")
        .chain_update(key)
        .chain_update(nonce)
        .finalize()
        .to_vec()
}

/// The code, computed apart from the core: SHA-256("duvet approval code v1" || key || nonce ||
/// the approver's certificate || the new device's user, device, signature key and HPKE key ||
/// the approver's nonce), its first 8 bytes as a big-endian number modulo 10^6, in 6 digits.
fn code_of(reveal: &Reveal, offer: &Offer, asked: &Commitment) -> String {
    let digest = Sha256::new()
        .chain_update(b"duvet approval code v1")
        .chain_update(&reveal.key)
        .chain_update(&reveal.nonce)
        .chain_update(&offer.certificate)
        .chain_update(asked.user.as_bytes())
        .chain_update(asked.device.as_bytes())
        .chain_update(&asked.signature_key)
        .chain_update(&asked.hpke_key)
        .chain_update(&offer.nonce)
        .finalize();
    let first: [u8; 8] = digest[..8].try_into().unwrap();
    format!("{:06}", u64::from_be_bytes(first) % 1_000_000)
}

fn begin(device: &mut TestDevice) -> Value {
    ok(&mut device.core, json!({"cmd": "approval_begin"}))
}

fn offer(commitment: &Value) -> Value {
    json!({"cmd": "approval_offer", "commitment": commitment})
}

fn reveal(offer: &Value) -> Value {
    json!({"cmd": "approval_reveal", "offer": offer})
}

fn check(reveal: &Value) -> Value {
    json!({"cmd": "approval_check", "reveal": reveal})
}

/// The person confirms on the approver, with the code they compared.
fn confirm(code: &str) -> Value {
    json!({"cmd": "approval_confirm", "code": code})
}

/// The person types on the new device the code the approver shows.
fn accept(code: &str) -> Value {
    json!({"cmd": "approval_accept", "code": code})
}

/// 6 digits that differ from `code`'s in every place.
fn other_code(code: &str) -> String {
    code.bytes()
        .map(|digit| char::from(b'0' + (digit - b'0' + 1) % 10))
        .collect()
}

fn from_qr(qr: &Value) -> Value {
    json!({"cmd": "approval_from_qr", "qr": qr})
}

fn approval_receive(transfer: &Value) -> Value {
    json!({"cmd": "approval_receive", "transfer": transfer})
}

fn receive_direct(message: &[u8]) -> Value {
    json!({"cmd": "receive_direct", "message": b64(message)})
}

fn recovering(recovery_key: &str, identity: &Value, device_list: &Value) -> Value {
    json!({
        "cmd": "recover",
        "recovery_key": recovery_key,
        "wrapped_backup_key": identity["wrapped_backup_key"],
        "encrypted_identity": identity["encrypted_identity"],
        "device_list": device_list,
    })
}

fn status(device: &mut TestDevice) -> Value {
    ok(&mut device.core, json!({"cmd": "status"}))
}

/// A row of the device's `meta`.
fn meta(device: &mut TestDevice, name: &str) -> Option<Vec<u8>> {
    device
        .core
        .transaction(|tx| {
            Ok(tx
                .conn()
                .query_row("SELECT value FROM meta WHERE key = ?1", [name], |row| {
                    row.get(0)
                })
                .optional()?)
        })
        .unwrap()
}

/// Everything a device keeps of an identity: its `meta` rows by name, its certificate, and how many
/// approvals are under way.
type IdentityRows = (Vec<(String, Vec<u8>)>, Option<Vec<u8>>, i64);

fn identity_rows(device: &mut TestDevice) -> IdentityRows {
    device
        .core
        .transaction(|tx| {
            let mut rows = Vec::new();
            for row in tx
                .conn()
                .prepare("SELECT key, value FROM meta ORDER BY key")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            {
                rows.push(row?);
            }
            let certificate = tx
                .conn()
                .query_row("SELECT certificate FROM device", [], |row| row.get(0))?;
            let approvals = tx
                .conn()
                .query_row("SELECT count(*) FROM approvals", [], |row| row.get(0))?;
            Ok((rows, certificate, approvals))
        })
        .unwrap()
}

/// The device's own signature and HPKE keys, as `create_device` made them.
fn own_keys(device: &mut TestDevice) -> (Vec<u8>, Vec<u8>) {
    device
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            Ok((own.signer.public().to_vec(), own.hpke.public.clone()))
        })
        .unwrap()
}

/// The signature key a certificate certifies.
fn signature_key_of(certificate: &Value) -> [u8; 32] {
    key32(
        &DeviceCertificate::read_unverified(&bytes(certificate))
            .unwrap()
            .signature_key,
    )
}

/// `(code, detail)` of an error: its `what`, `kind`, `rule` or `field`, or its fixed message for a
/// code without any (`exists`).
fn refusal(error: &Value) -> (String, String) {
    let detail = ["what", "kind", "rule", "field", "message"]
        .into_iter()
        .find_map(|name| error.get(name))
        .map_or_else(String::new, |detail| detail.as_str().unwrap().to_string());
    (error["code"].as_str().unwrap().to_string(), detail)
}

fn expect(code: &str, detail: &str) -> (String, String) {
    (code.to_string(), detail.to_string())
}

/// A recovery key that differs from `key` by one letter and fails its check.
fn mistyped(key: &str) -> String {
    const BASE58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for at in 0..key.len() {
        for letter in BASE58.chars() {
            let mut typed: Vec<char> = key.chars().collect();
            if typed[at] == letter {
                continue;
            }
            typed[at] = letter;
            let typed: String = typed.into_iter().collect();
            if recovery::parse(&typed).is_err() {
                return typed;
            }
        }
    }
    unreachable!("some letter fails the check")
}

#[test]
fn recover_with_key_signs_the_new_device() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let mut a2 = server.bare_device(a);
    let list = server.observed(a)["device_list"].clone();
    let before = identity_rows(&mut a2);

    // Another recovery key: the backup key doesn't unwrap with it.
    let other = recovery::generate(&RustCrypto::default()).unwrap();
    let refused = error(&mut a2.core, recovering(&other, &identity, &list));
    assert_eq!(refusal(&refused), expect("decrypt_failed", "backup_key"));
    // A letter mistyped: the key's check fails before anything is opened.
    let typo = mistyped(identity["recovery_key"].as_str().unwrap());
    let refused = error(&mut a2.core, recovering(&typo, &identity, &list));
    assert_eq!(refusal(&refused), expect("bad_command", "recovery_key"));
    assert!(!refused.to_string().contains(&typo), "{refused}");
    // The right key, with a list another identity signed.
    let stranger = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let forged = DeviceList::new(a, key32(stranger.public()), 9, vec![a1.id])
        .sign(&stranger)
        .unwrap();
    let refused = error(
        &mut a2.core,
        recovering(
            identity["recovery_key"].as_str().unwrap(),
            &identity,
            &json!(b64(&forged)),
        ),
    );
    assert_eq!(
        refusal(&refused),
        expect("invalid_signature", "device_list")
    );
    // The right key, with what isn't a list, or a list the identity signs for another user.
    let key = identity["recovery_key"].as_str().unwrap();
    let backup_key = recovery::unwrap_backup_key(
        &recovery::parse(key).unwrap(),
        a,
        &bytes(&identity["wrapped_backup_key"]),
    )
    .unwrap();
    let seed = recovery::decrypt_identity(&backup_key, a, &bytes(&identity["encrypted_identity"]))
        .unwrap();
    let signer = SignatureKeyPair::from_raw(
        SignatureScheme::ED25519,
        seed.to_vec(),
        bytes(&identity["identity_key"]),
    );
    let elsewhere = DeviceList::new(
        new_id(),
        key32(&bytes(&identity["identity_key"])),
        9,
        vec![a1.id],
    )
    .sign(&signer)
    .unwrap();
    for (device_list, expected) in [
        (
            json!(b64(b"not a list")),
            expect("bad_command", "device_list"),
        ),
        (
            json!(b64(&elsewhere)),
            expect("rule_violation", "wrong_user"),
        ),
    ] {
        let refused = error(&mut a2.core, recovering(key, &identity, &device_list));
        assert_eq!(refusal(&refused), expected);
    }
    // None of it changed anything.
    assert_eq!(identity_rows(&mut a2), before);
    assert_eq!(status(&mut a2)["has_identity"], false);

    // With its key, the new device takes the identity, and signs its own certificate and the next
    // list, with both devices.
    let recovered = ok(
        &mut a2.core,
        recovering(identity["recovery_key"].as_str().unwrap(), &identity, &list),
    );
    let identity_key = key32(&bytes(&identity["identity_key"]));
    let new_list = DeviceList::verify(&bytes(&recovered["device_list"]), &identity_key).unwrap();
    assert_eq!(new_list.user, a);
    assert_eq!(new_list.version, 2);
    let mut both = vec![a1.id, a2.id];
    both.sort();
    assert_eq!(new_list.devices, both);
    let certificate =
        DeviceCertificate::verify(&bytes(&recovered["certificate"]), &identity_key).unwrap();
    let (signature_key, hpke_key) = own_keys(&mut a2);
    assert_eq!((certificate.user, certificate.device), (a, a2.id));
    assert_eq!(certificate.signature_key, signature_key);
    assert_eq!(certificate.hpke_key, hpke_key);
    assert_eq!(certificate.created, server.clock.now_ms() as u64);

    // It holds what the first device holds: the identity and the backup key.
    let state = status(&mut a2);
    assert_eq!(state["has_identity"], true);
    assert_eq!(state["identity_key"], identity["identity_key"]);
    for row in ["identity_key", "identity_secret", "backup_key"] {
        assert_eq!(meta(&mut a2, row), meta(&mut a1, row), "{row}");
    }
    assert_eq!(
        meta(&mut a2, "device_list"),
        Some(bytes(&recovered["device_list"]))
    );

    // The server takes the new list and certificate; the new device makes key packages with its
    // certificate, and the first device takes the new list.
    server.take_device(a, &recovered["certificate"], &recovered["device_list"]);
    server.publish(&mut a2);
    server.introduce(&mut a1);
    assert_eq!(
        meta(&mut a1, "device_list"),
        Some(bytes(&recovered["device_list"]))
    );

    // Once it has the identity, it recovers nothing more.
    let again = error(
        &mut a2.core,
        recovering(identity["recovery_key"].as_str().unwrap(), &identity, &list),
    );
    assert_eq!(refusal(&again), expect("exists", "identity exists already"));
}

#[test]
fn approval_by_code() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let mut n = server.bare_device(a);

    // A device with the identity has nothing to be approved for, and one without it can't approve.
    let refused = error(&mut a1.core, json!({"cmd": "approval_begin"}));
    assert_eq!(
        refusal(&refused),
        expect("exists", "identity exists already")
    );
    let refused = error(&mut n.core, confirm("000000"));
    assert_eq!(refusal(&refused), expect("not_found", "approval"));
    // Nor is there a code to accept before an attempt, or before it took an offer.
    let refused = error(&mut n.core, accept("000000"));
    assert_eq!(refusal(&refused), expect("not_found", "approval"));

    // The new device sends its commitment through the server; the approver answers with its
    // offer; only then does the new device reveal what the commitment hid.
    let begun = begin(&mut n);
    let refused = error(&mut n.core, accept("000000"));
    assert_eq!(refusal(&refused), expect("not_found", "code"));
    let refused = error(&mut n.core, offer(&begun["commitment"]));
    assert_eq!(refusal(&refused), expect("not_found", "identity"));
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));

    // The new device answers with its reveal alone: its own code stays in the core, which compares
    // it with the one the person types there from the approver's screen. The approver shows a code
    // of 6 digits.
    assert_eq!(revealed, json!({"reveal": revealed["reveal"]}));
    let code = checked["code"].as_str().unwrap();
    assert_eq!(code.len(), 6);
    assert!(code.bytes().all(|digit| digit.is_ascii_digit()), "{code}");

    // The blobs are the contract's: the commitment holds the new device and the hash of the key
    // and nonce it reveals, the offer the approver's certificate and its nonce, and the code is
    // computed from them.
    let commitment: Commitment = read(&begun["commitment"]);
    let offer: Offer = read(&offered["offer"]);
    let revealed_parts: Reveal = read(&revealed["reveal"]);
    let (signature_key, hpke_key) = own_keys(&mut n);
    assert_eq!(
        (commitment.v, commitment.user, commitment.device),
        (1, a, n.id)
    );
    assert_eq!(commitment.signature_key, signature_key);
    assert_eq!(commitment.hpke_key, hpke_key);
    assert_eq!(
        commitment.hash,
        commitment_hash(&revealed_parts.key, &revealed_parts.nonce)
    );
    assert_eq!(
        (revealed_parts.key.len(), revealed_parts.nonce.len()),
        (32, 32)
    );
    assert_eq!((offer.v, offer.nonce.len()), (1, 32));
    assert_eq!(offer.hash, commitment.hash);
    assert_eq!(offer.certificate, bytes(&identity["certificate"]));
    assert_eq!(code_of(&revealed_parts, &offer, &commitment), code);
    let qr: Qr = read(&begun["qr"]);
    assert_ne!(
        qr.key, revealed_parts.key,
        "the QR's key is its own: the reveal doesn't disclose it"
    );

    // The person sees the codes match, and confirms on the approver: it hands the server the new
    // device's certificate and the next list, and the transfer for the new device's inbox. On the
    // new device, they type the code the approver shows.
    let approved = ok(&mut a1.core, confirm(code));
    server.take_device(a, &approved["certificate"], &approved["device_list"]);
    server.post(n.id, bytes(&approved["transfer"]));
    let inbox = server.inbox(n.id);
    assert_eq!(inbox.len(), 1);
    assert_eq!(ok(&mut n.core, accept(code)), json!({}));
    let received = ok(&mut n.core, receive_direct(&inbox[0]));
    assert_eq!(received["type"], "approval.transfer");
    assert_eq!(received["identity_key"], identity["identity_key"]);
    assert_eq!(received["certificate"], approved["certificate"]);

    // The new device has the identity and the backup key...
    let state = status(&mut n);
    assert_eq!(state["has_identity"], true);
    assert_eq!(state["identity_key"], identity["identity_key"]);
    for row in ["identity_key", "identity_secret", "backup_key"] {
        assert_eq!(meta(&mut n, row), meta(&mut a1, row), "{row}");
    }
    // ...and its certificate verifies: the user's identity certifies its own keys.
    let identity_key = key32(&bytes(&identity["identity_key"]));
    let certificate =
        DeviceCertificate::verify(&bytes(&received["certificate"]), &identity_key).unwrap();
    assert_eq!((certificate.user, certificate.device), (a, n.id));
    assert_eq!(certificate.signature_key, signature_key);
    assert_eq!(certificate.hpke_key, hpke_key);
    // The next list has both devices, on both devices.
    let list = DeviceList::verify(&bytes(&approved["device_list"]), &identity_key).unwrap();
    assert_eq!(list.version, 2);
    assert_eq!(
        list.devices,
        BTreeSet::from([a1.id, n.id])
            .into_iter()
            .collect::<Vec<_>>()
    );
    for device in [&mut a1, &mut n] {
        assert_eq!(
            meta(device, "device_list"),
            Some(bytes(&approved["device_list"]))
        );
    }
    // It signs as the identity, and makes key packages with its certificate.
    let signed = ok(
        &mut n.core,
        json!({"cmd": "sign_device_list", "remove": []}),
    );
    let signed = DeviceList::verify(&bytes(&signed["device_list"]), &identity_key).unwrap();
    assert_eq!(signed.version, 3);
    server.publish(&mut n);

    // The attempt is over on both sides.
    assert_eq!(
        refusal(&error(&mut a1.core, confirm(code))),
        expect("not_found", "approval")
    );
    assert_eq!(
        refusal(&error(&mut n.core, receive_direct(&inbox[0]))),
        expect("exists", "identity exists already")
    );
}

#[test]
fn approval_rejects_a_reveal_that_breaks_the_commitment() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);
    let mut n = server.bare_device(a);
    let begun = begin(&mut n);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    let honest: Reveal = read(&revealed["reveal"]);

    // Another key, another nonce, or both: none holds to the commitment.
    let mut nonce = honest.nonce.clone();
    nonce[31] ^= 1;
    let forged = [
        Reveal {
            key: random32().to_vec(),
            ..honest.clone()
        },
        Reveal {
            nonce,
            ..honest.clone()
        },
        Reveal {
            v: 1,
            key: random32().to_vec(),
            nonce: random32().to_vec(),
        },
    ];
    for forged in forged {
        let refused = error(&mut a1.core, check(&json!(b64(&cbor(&forged)))));
        assert_eq!(refusal(&refused), expect("invalid_signature", "reveal"));
    }
    // What isn't a reveal at all.
    let refused = error(&mut a1.core, check(&json!(b64(b"not a reveal"))));
    assert_eq!(refusal(&refused), expect("bad_command", "reveal"));

    // Nothing held, so there's no code to confirm, not even the new device's own (computed apart).
    let own = code_of(
        &honest,
        &read(&offered["offer"]),
        &read(&begun["commitment"]),
    );
    let refused = error(&mut a1.core, confirm(&own));
    assert_eq!(refusal(&refused), expect("not_found", "code"));

    // The new device's own reveal holds, and the approver shows its code.
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    assert_eq!(checked["code"], own);
}

#[test]
fn confirm_takes_the_code_the_person_compared() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);
    let (mut n1, mut n2) = (server.bare_device(a), server.bare_device(a));

    // The person reads the code of a first request on the approver...
    let first = begin(&mut n1);
    let offered = ok(&mut a1.core, offer(&first["commitment"]));
    let revealed = ok(&mut n1.core, reveal(&offered["offer"]));
    let shown = ok(&mut a1.core, check(&revealed["reveal"]));
    // ...and before they tap, they take a second notice, whose attempt replaces the first.
    let second = begin(&mut n2);
    let offered = ok(&mut a1.core, offer(&second["commitment"]));
    let revealed = ok(&mut n2.core, reveal(&offered["offer"]));
    let current = ok(&mut a1.core, check(&revealed["reveal"]));

    // The tap with the code they compared approves nothing: it's not the current attempt's.
    let before = identity_rows(&mut a1);
    let refused = error(&mut a1.core, confirm(shown["code"].as_str().unwrap()));
    assert_eq!(refusal(&refused), expect("not_found", "code"));
    assert_eq!(identity_rows(&mut a1), before);

    // With the current attempt's code, it approves that attempt's device.
    let approved = ok(&mut a1.core, confirm(current["code"].as_str().unwrap()));
    let certificate = DeviceCertificate::read_unverified(&bytes(&approved["certificate"])).unwrap();
    assert_eq!(certificate.device, n2.id);
}

#[test]
fn the_same_commitment_gets_the_same_offer() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);
    let (mut n, mut other) = (server.bare_device(a), server.bare_device(a));
    let begun = begin(&mut n);
    let theirs = begin(&mut other);

    // A commitment the approver answered, sent again within its 10 minutes, gets the same offer,
    // its nonce included, whatever came between: no new try at the code.
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    assert_eq!(ok(&mut a1.core, offer(&begun["commitment"])), offered);
    let between = ok(&mut a1.core, offer(&theirs["commitment"]));
    assert_eq!(ok(&mut a1.core, offer(&begun["commitment"])), offered);
    // It's the attempt under way again: its reveal holds. Then the one that came between gets its
    // own answer again too, and back to the first, the code the person compared confirms it.
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    server.clock.advance(TEN_MINUTES_MS - 1);
    assert_eq!(ok(&mut a1.core, offer(&theirs["commitment"])), between);
    assert_eq!(ok(&mut a1.core, offer(&begun["commitment"])), offered);
    let approved = ok(&mut a1.core, confirm(checked["code"].as_str().unwrap()));
    let certificate = DeviceCertificate::read_unverified(&bytes(&approved["certificate"])).unwrap();
    assert_eq!(certificate.device, n.id);

    // Once its 10 minutes are over, the same commitment begins another attempt, with a nonce of its
    // own.
    let mut m = server.bare_device(a);
    let begun = begin(&mut m);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    server.clock.advance(TEN_MINUTES_MS);
    let again: Offer = read(&ok(&mut a1.core, offer(&begun["commitment"]))["offer"]);
    assert_ne!(again.nonce, read::<Offer>(&offered["offer"]).nonce);
}

#[test]
fn each_approval_step_refuses_what_it_cant_take() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, _) = server.first_device(a);
    let mut n = server.bare_device(a);
    let mut stranger = server.bare_device(b);
    let begun = begin(&mut n);
    let theirs = begin(&mut stranger);
    let commitment: Commitment = read(&begun["commitment"]);
    let qr: Qr = read(&begun["qr"]);

    // The approver offers and approves by QR only for an approval's blob of this version, and
    // only for a device of its own user, one whose QR it scanned included.
    let cases = [
        (
            offer(&json!(b64(b"not a commitment"))),
            expect("bad_command", "commitment"),
        ),
        (
            offer(&json!(b64(&cbor(&Commitment {
                v: 2,
                ..commitment.clone()
            })))),
            expect("bad_command", "commitment"),
        ),
        (
            offer(&theirs["commitment"]),
            expect("rule_violation", "wrong_user"),
        ),
        (
            from_qr(&json!(b64(b"not a QR"))),
            expect("bad_command", "qr"),
        ),
        (
            from_qr(&json!(b64(&cbor(&Qr { v: 2, ..qr.clone() })))),
            expect("bad_command", "qr"),
        ),
        (
            from_qr(&theirs["qr"]),
            expect("rule_violation", "wrong_user"),
        ),
    ];
    let before = identity_rows(&mut a1);
    for (command, expected) in cases {
        let refused = error(&mut a1.core, command.clone());
        assert_eq!(refusal(&refused), expected, "{command}");
    }
    assert_eq!(identity_rows(&mut a1), before);

    // The new device reveals only for an offer of this version, to its own commitment, whose
    // certificate is one, of another device of its user.
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let honest: Offer = read(&offered["offer"]);
    let certificate = |user, device| {
        DeviceCertificate::new(user, device, [1; 32], [2; 32], 1)
            .sign(&Forger::new().identity)
            .unwrap()
    };
    let cases = [
        (json!(b64(b"not an offer")), expect("bad_command", "offer")),
        (
            json!(b64(&cbor(&Offer {
                v: 2,
                ..honest.clone()
            }))),
            expect("bad_command", "offer"),
        ),
        (
            json!(b64(&cbor(&Offer {
                certificate: b"not a certificate".to_vec(),
                ..honest.clone()
            }))),
            expect("bad_command", "offer"),
        ),
        (
            json!(b64(&cbor(&Offer {
                hash: random32().to_vec(),
                ..honest.clone()
            }))),
            expect("not_found", "approval"),
        ),
        (
            json!(b64(&cbor(&Offer {
                certificate: certificate(b, new_id()),
                ..honest.clone()
            }))),
            expect("rule_violation", "wrong_user"),
        ),
        (
            json!(b64(&cbor(&Offer {
                certificate: certificate(a, n.id),
                ..honest.clone()
            }))),
            expect("rule_violation", "wrong_device"),
        ),
    ];
    let before = identity_rows(&mut n);
    for (blob, expected) in cases {
        let refused = error(&mut n.core, reveal(&blob));
        assert_eq!(refusal(&refused), expected, "{blob}");
    }
    assert_eq!(identity_rows(&mut n), before);
    ok(&mut n.core, reveal(&offered["offer"]));

    // An approver that its user's list no longer holds approves nothing.
    ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a1.id]}),
    );
    let begun = begin(&mut n);
    for command in [offer(&begun["commitment"]), from_qr(&begun["qr"])] {
        let refused = error(&mut a1.core, command.clone());
        assert_eq!(
            refusal(&refused),
            expect("rule_violation", "device_not_listed"),
            "{command}"
        );
    }
}

#[test]
fn server_cannot_force_the_code() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);
    let mut n = server.bare_device(a);
    // Another device of A, whose certificate the server holds as it holds every device's.
    let other = server.virtual_device(a);
    let other_certificate = bytes(&server.observed(a)["certificates"][1]);
    assert_eq!(
        DeviceCertificate::read_unverified(&other_certificate)
            .unwrap()
            .device,
        other
    );

    // Each time, the person types into the new device the code the approver shows, and the new
    // device refuses it: it isn't its own.
    let refused_there = |n: &mut TestDevice, checked: &Value| {
        let refused = error(&mut n.core, accept(checked["code"].as_str().unwrap()));
        assert_eq!(refusal(&refused), expect("rule_violation", "code_mismatch"));
    };

    // The server stands in for the new device with a key of its own: it commits to that key under
    // the new device's request, and reveals it once the approver's offer is out. The approver's
    // check of the commitment passes, but its code isn't the new device's.
    let begun = begin(&mut n);
    let commitment: Commitment = read(&begun["commitment"]);
    let (key, nonce) = (random32(), random32());
    let substituted = Commitment {
        hash: commitment_hash(&key, &nonce),
        ..commitment.clone()
    };
    let offered = ok(&mut a1.core, offer(&json!(b64(&cbor(&substituted)))));
    // The offer goes on to the new device as an answer to its own commitment.
    let to_new = Offer {
        hash: commitment.hash.clone(),
        ..read(&offered["offer"])
    };
    ok(&mut n.core, reveal(&json!(b64(&cbor(&to_new)))));
    let own = Reveal {
        v: 1,
        key: key.to_vec(),
        nonce: nonce.to_vec(),
    };
    let checked = ok(&mut a1.core, check(&json!(b64(&cbor(&own)))));
    refused_there(&mut n, &checked);

    // The server puts keys of its own in the new device's request: the approver would certify
    // them, but its code isn't the new device's.
    let begun = begin(&mut n);
    let commitment: Commitment = read(&begun["commitment"]);
    let substituted = Commitment {
        signature_key: random32().to_vec(),
        hpke_key: random32().to_vec(),
        ..commitment
    };
    let offered = ok(&mut a1.core, offer(&json!(b64(&cbor(&substituted)))));
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    refused_there(&mut n, &checked);

    // The server changes the approver's nonce on its way to the new device.
    let begun = begin(&mut n);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let substituted = Offer {
        nonce: random32().to_vec(),
        ..read(&offered["offer"])
    };
    let revealed = ok(&mut n.core, reveal(&json!(b64(&cbor(&substituted)))));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    refused_there(&mut n, &checked);

    // The server hands the new device another device's certificate as the approver's.
    let begun = begin(&mut n);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let substituted = Offer {
        certificate: other_certificate,
        ..read(&offered["offer"])
    };
    let revealed = ok(&mut n.core, reveal(&json!(b64(&cbor(&substituted)))));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    refused_there(&mut n, &checked);

    // Untouched, the two codes match.
    let begun = begin(&mut n);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    // The attempt took that offer: the same one again gets the same answer, and another none.
    assert_eq!(ok(&mut n.core, reveal(&offered["offer"])), revealed);
    let substituted = Offer {
        nonce: random32().to_vec(),
        ..read(&offered["offer"])
    };
    let refused = error(&mut n.core, reveal(&json!(b64(&cbor(&substituted)))));
    assert_eq!(refusal(&refused), expect("exists", "offer exists already"));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    ok(&mut n.core, accept(checked["code"].as_str().unwrap()));
}

#[test]
fn approval_by_qr() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let mut n = server.bare_device(a);

    // The QR holds the new device as it asks to be certified, and the attempt's key: an X25519
    // key of its own, not the device's.
    let begun = begin(&mut n);
    let qr: Qr = read(&begun["qr"]);
    let (signature_key, hpke_key) = own_keys(&mut n);
    assert_eq!((qr.v, qr.user, qr.device), (1, a, n.id));
    assert_eq!(qr.signature_key, signature_key);
    assert_eq!(qr.hpke_key, hpke_key);
    assert_eq!(qr.key.len(), 32);
    assert_ne!(qr.key, hpke_key);
    // The commitment the server would see doesn't hold that key.
    let commitment = bytes(&begun["commitment"]);
    assert!(!commitment.windows(32).any(|window| window == qr.key));

    // The approver scans it: the new device's certificate and the next list for the server, and
    // the transfer for the new device.
    let approved = ok(&mut a1.core, from_qr(&begun["qr"]));
    let identity_key = key32(&bytes(&identity["identity_key"]));
    let certificate =
        DeviceCertificate::verify(&bytes(&approved["certificate"]), &identity_key).unwrap();
    assert_eq!((certificate.user, certificate.device), (a, n.id));
    assert_eq!(certificate.signature_key, signature_key);
    let list = DeviceList::verify(&bytes(&approved["device_list"]), &identity_key).unwrap();
    assert_eq!(list.version, 2);
    assert!(list.contains(n.id) && list.contains(a1.id));

    // The transfer is a message from the approver to the new device, sealed to the QR's key: the
    // new device's own key doesn't open it.
    let transfer = bytes(&approved["transfer"]);
    let body: Body = read_bytes(&read_bytes::<Signed>(&transfer).body);
    assert_eq!((body.v, body.from, body.to), (1, a1.id, n.id));
    assert_eq!(body.kind, "approval.transfer");
    let approver_key = signature_key_of(&identity["certificate"]);
    let with_own_key = n.core.transaction(|tx| {
        let own = tx.own_device()?;
        DirectMessage::open(
            tx.provider(),
            &own.hpke.private,
            own.device,
            a1.id,
            &approver_key,
            &transfer,
        )
    });
    assert_eq!(
        with_own_key.map(|_| ()).map_err(|error| error.code()),
        Err("decrypt_failed")
    );

    // Through the server's inbox, the new device takes it with the attempt's key.
    server.take_device(a, &approved["certificate"], &approved["device_list"]);
    server.post(n.id, transfer);
    let message = server.inbox(n.id).remove(0);
    let received = ok(&mut n.core, approval_receive(&json!(b64(&message))));
    assert_eq!(received["identity_key"], identity["identity_key"]);
    assert_eq!(received["certificate"], approved["certificate"]);
    assert_eq!(status(&mut n)["has_identity"], true);
    for row in ["identity_secret", "backup_key"] {
        assert_eq!(meta(&mut n, row), meta(&mut a1, row), "{row}");
    }
    server.publish(&mut n);

    // The QR is spent: its device is on the list already.
    let again = error(&mut a1.core, from_qr(&begun["qr"]));
    assert_eq!(refusal(&again), expect("exists", "device exists already"));

    // Each attempt has a key of its own: the transfer for an attempt the device has since replaced
    // doesn't open.
    let mut m = server.bare_device(a);
    let first = begin(&mut m);
    let second = begin(&mut m);
    assert_ne!(read::<Qr>(&first["qr"]).key, read::<Qr>(&second["qr"]).key);
    let approved = ok(&mut a1.core, from_qr(&first["qr"]));
    let refused = error(&mut m.core, approval_receive(&approved["transfer"]));
    assert_eq!(refusal(&refused), expect("decrypt_failed", "direct"));
    assert_eq!(status(&mut m)["has_identity"], false);
}

/// Someone who forges transfers: an identity and a device of their own.
struct Forger {
    seed: [u8; 32],
    identity: SignatureKeyPair,
    device: Uuid,
    signer: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
}

impl Forger {
    fn new() -> Forger {
        let seed = random32();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Forger {
            seed,
            identity: SignatureKeyPair::from_raw(
                SignatureScheme::ED25519,
                seed.to_vec(),
                public.to_vec(),
            ),
            device: new_id(),
            signer: SignatureKeyPair::new(SignatureScheme::ED25519).unwrap(),
            provider: OpenMlsRustCrypto::default(),
        }
    }

    fn identity_key(&self) -> [u8; 32] {
        key32(self.identity.public())
    }

    /// A list `identity` signs for `user`.
    fn list(&self, user: Uuid, devices: &[Uuid], identity: &SignatureKeyPair) -> Vec<u8> {
        DeviceList::new(user, key32(identity.public()), 2, devices.to_vec())
            .sign(identity)
            .unwrap()
    }

    /// The certificate `identity` signs for the forger's own device.
    fn own_certificate(&self, user: Uuid, identity: &SignatureKeyPair) -> Vec<u8> {
        self.certificate_as(user, self.device, identity)
    }

    /// The certificate `identity` signs for the forger's signature key, as `device` of `user`.
    fn certificate_as(&self, user: Uuid, device: Uuid, identity: &SignatureKeyPair) -> Vec<u8> {
        DeviceCertificate::new(user, device, key32(self.signer.public()), [5; 32], 1)
            .sign(identity)
            .unwrap()
    }

    /// The certificate the forger's identity signs for `asked`, a new device.
    fn certificate_for(&self, asked: &Commitment) -> Vec<u8> {
        DeviceCertificate::new(
            asked.user,
            asked.device,
            key32(&asked.signature_key),
            key32(&asked.hpke_key),
            1,
        )
        .sign(&self.identity)
        .unwrap()
    }

    /// A transfer from the forger's device to `to`, sealed to `key`.
    fn transfer(
        &self,
        to: Uuid,
        key: &[u8],
        certificate: Vec<u8>,
        list: Vec<u8>,
        approver: Vec<u8>,
    ) -> Vec<u8> {
        let payload = Transfer {
            v: 1,
            identity: self.seed.to_vec(),
            backup_key: [6; 32].to_vec(),
            certificate,
            device_list: list,
            approver,
        };
        DirectMessage::seal(
            &self.provider,
            &self.signer,
            self.device,
            to,
            &key32(key),
            "approval.transfer",
            &cbor(&payload),
        )
        .unwrap()
    }
}

/// The request a QR shows, as a commitment would carry it.
fn asked_of(qr: &Qr) -> Commitment {
    Commitment {
        v: 1,
        user: qr.user,
        device: qr.device,
        signature_key: qr.signature_key.clone(),
        hpke_key: qr.hpke_key.clone(),
        hash: Vec::new(),
    }
}

#[test]
fn transfer_from_a_forged_identity_is_rejected() {
    let mut server = FakeServer::new();
    let (a, b) = (new_id(), new_id());
    let (mut a1, identity) = server.first_device(a);
    let mut n = server.bare_device(a);
    let begun = begin(&mut n);
    let qr: Qr = read(&begun["qr"]);
    let asked = asked_of(&qr);
    let real_list = bytes(&server.observed(a)["device_list"]);

    // Someone who saw the QR sends transfers with an identity of their own, X.
    let forger = Forger::new();
    let other = Forger::new();
    let x = &forger.identity;
    let approver = forger.own_certificate(a, x);
    let both = [forger.device, n.id];
    let elsewhere = new_id();
    let cases = [
        // A's real list, which X doesn't sign.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                real_list,
                approver.clone(),
            ),
            expect("invalid_signature", "device_list"),
        ),
        // A list X signs for A, without the new device.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                forger.list(a, &[forger.device], x),
                approver.clone(),
            ),
            expect("rule_violation", "device_not_listed"),
        ),
        // A list X signs with the new device, for another user.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                forger.list(b, &both, x),
                approver.clone(),
            ),
            expect("rule_violation", "wrong_user"),
        ),
        // The sender's certificate signed by yet another identity.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                forger.list(a, &both, x),
                forger.own_certificate(a, &other.identity),
            ),
            expect("invalid_signature", "certificate"),
        ),
        // The new device's certificate, for other keys.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&Commitment {
                    signature_key: random32().to_vec(),
                    ..asked.clone()
                }),
                forger.list(a, &both, x),
                approver.clone(),
            ),
            expect("rule_violation", "wrong_device"),
        ),
        // The sender's certificate, for a device of another user.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                forger.list(a, &both, x),
                forger.own_certificate(b, x),
            ),
            expect("rule_violation", "wrong_user"),
        ),
        // The sender's certificate, for another device than the one that sent the message.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&asked),
                forger.list(a, &[elsewhere, n.id], x),
                forger.certificate_as(a, elsewhere, x),
            ),
            expect("rule_violation", "wrong_device"),
        ),
        // The new device's certificate, signed by yet another identity.
        (
            forger.transfer(
                n.id,
                &qr.key,
                other.certificate_for(&asked),
                forger.list(a, &both, x),
                approver.clone(),
            ),
            expect("invalid_signature", "certificate"),
        ),
        // The new device's certificate, for a device of another user.
        (
            forger.transfer(
                n.id,
                &qr.key,
                forger.certificate_for(&Commitment {
                    user: b,
                    ..asked.clone()
                }),
                forger.list(a, &both, x),
                approver.clone(),
            ),
            expect("rule_violation", "wrong_user"),
        ),
        // A payload that isn't a transfer.
        (
            DirectMessage::seal(
                &forger.provider,
                &forger.signer,
                forger.device,
                n.id,
                &key32(&qr.key),
                "approval.transfer",
                b"not a transfer",
            )
            .unwrap(),
            expect("decrypt_failed", "transfer"),
        ),
    ];
    let before = identity_rows(&mut n);
    for (transfer, expected) in cases {
        let refused = error(&mut n.core, receive_direct(&transfer));
        assert_eq!(refusal(&refused), expected);
        assert_eq!(identity_rows(&mut n), before, "{expected:?}");
    }
    assert_ne!(
        forger.identity_key(),
        key32(&bytes(&identity["identity_key"]))
    );

    // A message of another type is no transfer, and one of a type the core doesn't read is refused.
    let other_type = DirectMessage::seal(
        &forger.provider,
        &forger.signer,
        forger.device,
        n.id,
        &key32(&qr.key),
        "history.key",
        b"a key",
    )
    .unwrap();
    let refused = error(&mut n.core, approval_receive(&json!(b64(&other_type))));
    assert_eq!(refusal(&refused), expect("bad_command", "transfer"));
    let unknown = DirectMessage::seal(
        &forger.provider,
        &forger.signer,
        forger.device,
        n.id,
        &key32(&qr.key),
        "nothing.known",
        b"",
    )
    .unwrap();
    let refused = error(&mut n.core, receive_direct(&unknown));
    assert_eq!(refusal(&refused), expect("bad_command", "message"));
    assert_eq!(identity_rows(&mut n), before);

    // The real approval still goes through.
    let approved = ok(&mut a1.core, from_qr(&begun["qr"]));
    let received = ok(&mut n.core, approval_receive(&approved["transfer"]));
    assert_eq!(received["identity_key"], identity["identity_key"]);

    // By the code, the server holds the commitment's key once it's revealed, so it can seal a
    // transfer that holds together, its own identity signing everything. The new device takes no
    // transfer sealed to that key before the person types the approver's code, and then only the
    // approver's.
    let mut n2 = server.bare_device(a);
    let begun = begin(&mut n2);
    let asked: Commitment = read(&begun["commitment"]);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut n2.core, reveal(&offered["offer"]));
    let key = read::<Reveal>(&revealed["reveal"]).key;
    let consistent = forger.transfer(
        n2.id,
        &key,
        forger.certificate_for(&asked),
        forger.list(a, &[forger.device, n2.id], x),
        approver,
    );
    let refused = error(&mut n2.core, receive_direct(&consistent));
    assert_eq!(refusal(&refused), expect("not_found", "code"));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    ok(&mut n2.core, accept(checked["code"].as_str().unwrap()));
    let refused = error(&mut n2.core, receive_direct(&consistent));
    assert_eq!(refusal(&refused), expect("invalid_signature", "transfer"));
    assert_eq!(status(&mut n2)["has_identity"], false);
    let approved = ok(&mut a1.core, confirm(checked["code"].as_str().unwrap()));
    let received = ok(&mut n2.core, receive_direct(&bytes(&approved["transfer"])));
    assert_eq!(received["identity_key"], identity["identity_key"]);
}

#[test]
fn a_transfer_by_the_notice_waits_for_the_code() {
    let mut server = FakeServer::new();
    let a = new_id();
    server.first_device(a);
    let mut n = server.bare_device(a);
    let begun = begin(&mut n);
    let asked: Commitment = read(&begun["commitment"]);

    // The server answers the commitment with an offer of its own: a device of the user that an
    // identity of its own, X, certifies. No approver took part.
    let forger = Forger::new();
    let x = &forger.identity;
    let server_offer = Offer {
        v: 1,
        hash: asked.hash.clone(),
        certificate: forger.own_certificate(a, x),
        nonce: random32().to_vec(),
    };
    let revealed = ok(&mut n.core, reveal(&json!(b64(&cbor(&server_offer)))));
    // The reveal hands it the commitment's key, so it seals a transfer that holds together under X.
    let key = read::<Reveal>(&revealed["reveal"]).key;
    let consistent = forger.transfer(
        n.id,
        &key,
        forger.certificate_for(&asked),
        forger.list(a, &[forger.device, n.id], x),
        forger.own_certificate(a, x),
    );

    // Until the person types here the code the approver shows, neither command takes it, and
    // nothing changes.
    let before = identity_rows(&mut n);
    for command in [
        receive_direct(&consistent),
        approval_receive(&json!(b64(&consistent))),
    ] {
        let refused = error(&mut n.core, command);
        assert_eq!(refusal(&refused), expect("not_found", "code"));
    }
    assert_eq!(identity_rows(&mut n), before);
    // A code that isn't this device's (its own, computed apart, with every digit changed) is
    // refused, and leaves the attempt as it was.
    let wrong = other_code(&code_of(&read(&revealed["reveal"]), &server_offer, &asked));
    let refused = error(&mut n.core, accept(&wrong));
    assert_eq!(refusal(&refused), expect("rule_violation", "code_mismatch"));
    assert_eq!(identity_rows(&mut n), before);
    let refused = error(&mut n.core, receive_direct(&consistent));
    assert_eq!(refusal(&refused), expect("not_found", "code"));
    assert_eq!(status(&mut n)["has_identity"], false);
}

#[test]
fn a_server_offer_leaves_the_qr_alone() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let mut n = server.bare_device(a);
    let begun = begin(&mut n);

    // While the QR shows, the server answers the commitment with an offer of its own, and the new
    // device reveals for it.
    let forger = Forger::new();
    let server_offer = Offer {
        v: 1,
        hash: read::<Commitment>(&begun["commitment"]).hash,
        certificate: forger.own_certificate(a, &forger.identity),
        nonce: random32().to_vec(),
    };
    let revealed = ok(&mut n.core, reveal(&json!(b64(&cbor(&server_offer)))));

    // The real approver scans the QR, and the new device takes its transfer.
    let approved = ok(&mut a1.core, from_qr(&begun["qr"]));
    let received = ok(&mut n.core, receive_direct(&bytes(&approved["transfer"])));
    assert_eq!(received["identity_key"], identity["identity_key"]);
    assert_eq!(status(&mut n)["identity_key"], identity["identity_key"]);
    // The QR's key is its own: the reveal didn't disclose it.
    assert_ne!(
        read::<Reveal>(&revealed["reveal"]).key,
        read::<Qr>(&begun["qr"]).key
    );
}

#[test]
fn approval_state_lasts_ten_minutes() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, _) = server.first_device(a);

    // The new device's attempt waits 10 minutes for an offer: a millisecond short of them it still
    // takes one, and from then on it lasts 10 minutes from that offer. The approver's window began
    // with its offer, before, so its transfer is in time even when it confirms at the last moment.
    let mut n = server.bare_device(a);
    let begun = begin(&mut n);
    server.clock.advance(TEN_MINUTES_MS - 1);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut n.core, reveal(&offered["offer"]));
    server.clock.advance(TEN_MINUTES_MS - 1);
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    let code = checked["code"].as_str().unwrap();
    let approved = ok(&mut a1.core, confirm(code));
    ok(&mut n.core, accept(code));
    ok(&mut n.core, approval_receive(&approved["transfer"]));

    // 10 minutes from its offer, it's over: a transfer that comes later finds no attempt, and the
    // device, listed already, can't be approved again. Removed from the list, it can.
    let mut m = server.bare_device(a);
    let begun = begin(&mut m);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut m.core, reveal(&offered["offer"]));
    let checked = ok(&mut a1.core, check(&revealed["reveal"]));
    let code = checked["code"].as_str().unwrap();
    let approved = ok(&mut a1.core, confirm(code));
    ok(&mut m.core, accept(code));
    server.clock.advance(TEN_MINUTES_MS);
    let refused = error(&mut m.core, approval_receive(&approved["transfer"]));
    assert_eq!(refusal(&refused), expect("not_found", "approval"));
    let begun = begin(&mut m);
    let refused = error(&mut a1.core, from_qr(&begun["qr"]));
    assert_eq!(refusal(&refused), expect("exists", "device exists already"));
    ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [m.id]}),
    );
    let approved = ok(&mut a1.core, from_qr(&begun["qr"]));
    ok(&mut m.core, approval_receive(&approved["transfer"]));

    // The approver's attempt lasts 10 minutes from its offer.
    let mut o = server.bare_device(a);
    let begun = begin(&mut o);
    let offered = ok(&mut a1.core, offer(&begun["commitment"]));
    let revealed = ok(&mut o.core, reveal(&offered["offer"]));
    server.clock.advance(TEN_MINUTES_MS);
    let refused = error(&mut a1.core, check(&revealed["reveal"]));
    assert_eq!(refusal(&refused), expect("not_found", "approval"));
    let refused = error(&mut o.core, reveal(&offered["offer"]));
    assert_eq!(refusal(&refused), expect("not_found", "approval"));
}

/// `start`: `creator` makes `conversation`'s group, as the API has it, and the server takes it.
fn start(server: &mut FakeServer, creator: &mut TestDevice, conversation: Uuid) {
    let command = server.create_group(conversation);
    server
        .commit(creator, conversation, command)
        .expect("the server takes epoch 0");
}

/// An application message `device` sends in its group of `conversation`.
fn send(device: &mut TestDevice, conversation: Uuid, text: &[u8]) -> Vec<u8> {
    device
        .core
        .transaction(|tx| {
            let (mut group, _) = mls::load_group(tx, conversation)?;
            let own = tx.own_device()?;
            let message = group
                .create_message(tx.provider(), &own.signer, text)
                .map_err(|error| Error::Internal(error.to_string()))?;
            Ok(message.tls_serialize_detached().unwrap())
        })
        .unwrap()
}

/// What an application message says, as `device` decrypts it in its group of `conversation`.
fn decrypt(device: &mut TestDevice, conversation: Uuid, message: &[u8]) -> Vec<u8> {
    device
        .core
        .transaction(|tx| {
            let (mut group, _) = mls::load_group(tx, conversation)?;
            let message = MlsMessageIn::tls_deserialize_exact_bytes(message)
                .unwrap()
                .try_into_protocol_message()
                .unwrap();
            let processed = group
                .process_message(tx.provider(), message)
                .map_err(|error| Error::Internal(error.to_string()))?;
            match processed.into_content() {
                ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
                _ => Err(Error::Internal("not an application message".into())),
            }
        })
        .unwrap()
}

#[test]
fn new_device_joins_its_groups() {
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
    let (dm, group) = (new_id(), new_id());
    server.conversation(dm, Kind::Dm, None, &[a, b], false);
    server.conversation(group, Kind::Group, Some(a), &[a, b], false);
    start(&mut server, &mut a1, dm);
    start(&mut server, &mut a1, group);
    server.deliver_all(&mut [&mut a1, &mut b1]);

    // A's new device recovers with the key, and the server takes its certificate and A's next
    // list, which every device observes.
    let mut a2 = server.bare_device(a);
    let list = server.observed(a)["device_list"].clone();
    let recovered = ok(
        &mut a2.core,
        recovering(identity["recovery_key"].as_str().unwrap(), &identity, &list),
    );
    server.take_device(a, &recovered["certificate"], &recovered["device_list"]);
    for device in [&mut a1, &mut b1, &mut a2] {
        server.introduce(device);
    }

    // It joins each of its conversations' groups by external commit, which the server's validator
    // and every member take.
    for conversation in [dm, group] {
        let join = json!({
            "cmd": "join_external",
            "conversation_id": conversation,
            "generation": 0,
            "group_info": server.group_info(conversation),
        });
        server
            .commit(&mut a2, conversation, join)
            .expect("the server takes the external commit");
    }
    server.deliver_all(&mut [&mut a1, &mut b1, &mut a2]);
    for conversation in [dm, group] {
        let state = same_group(&mut [&mut a1, &mut b1, &mut a2], conversation);
        assert_eq!(state["epoch"], 2);
        assert_eq!(state["blocked"], false);
        assert_eq!(members(&state), [a, b]);
        assert_eq!(
            devices(&state).into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from([a1.id, a2.id, b1.id])
        );
    }

    // And it converses: what it sends reaches the others, and what they send reaches it.
    for conversation in [dm, group] {
        let hello = send(&mut a2, conversation, b"hello from the new device");
        for device in [&mut a1, &mut b1] {
            assert_eq!(
                decrypt(device, conversation, &hello),
                b"hello from the new device"
            );
        }
        let answer = send(&mut b1, conversation, b"welcome back");
        for device in [&mut a1, &mut a2] {
            assert_eq!(decrypt(device, conversation, &answer), b"welcome back");
        }
    }
}

/// A1 signs version 3 of A's list, and its upload never lands: the server took another device's
/// version 3, with a new device on it. Observing its own user, A1 takes the server's version 3,
/// which its identity signed and the server's compare-and-set chose, and its next list builds on
/// it. Once the server has served A1 its own list, another of that version is a conflict again.
#[test]
fn own_list_that_lost_to_another_of_its_version_is_replaced() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let mut a2 = server.device(a);
    server.introduce(&mut a1);
    ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    let a3 = server.device(a);

    let seen = ok(&mut a1.core, server.observed(a));
    assert_eq!(seen["state"], "same", "{seen}");
    let identity_key = key32(&bytes(&identity["identity_key"]));
    let held = a1.rolled_back(|tx| tx.device_list_of(a)).unwrap();
    assert_eq!((held.version, held.contains(a3.id)), (3, true));

    let other = ok(
        &mut a2.core,
        json!({"cmd": "sign_device_list", "remove": []}),
    );
    let mut served = server.observed(a);
    served["device_list"] = other["device_list"].clone();
    served["certificates"] = json!([]);
    let refused = ok(&mut a1.core, served);
    assert_eq!(
        (&refused["state"], &refused["reason"]),
        (&json!("rejected"), &json!("conflicting_list"))
    );

    let next = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": []}),
    );
    let next = DeviceList::verify(&bytes(&next["device_list"]), &identity_key).unwrap();
    assert_eq!(next.version, 4);
    assert!(next.contains(a2.id) && next.contains(a3.id));
}

/// A1 signs version 3 of A's list without A2, the server takes it, and the client confirms the
/// upload (`device_list_uploaded`). The server never serves A1 that list: it serves the one from
/// before (`older_list`). A3 recovers against that older list and signs it, with A2 and itself, into
/// a version 3 of its own: served to A1, it's a conflict, and A2 stays off the list A1 holds.
#[test]
fn own_list_confirmed_as_uploaded_gives_way_to_none_of_its_version() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, identity) = server.first_device(a);
    let a2 = server.device(a);
    server.introduce(&mut a1);
    let old = server.observed(a);
    let signed = ok(
        &mut a1.core,
        json!({"cmd": "sign_device_list", "remove": [a2.id]}),
    );
    server.take_list(a, &signed["device_list"]);
    let confirmed = run(
        &mut a1.core,
        &json!({"cmd": "device_list_uploaded", "version": 3}),
    );
    let seen = ok(&mut a1.core, old.clone());
    assert_eq!(
        (&seen["state"], &seen["reason"]),
        (&json!("rejected"), &json!("older_list"))
    );

    let mut a3 = server.bare_device(a);
    let recovered = ok(
        &mut a3.core,
        recovering(
            identity["recovery_key"].as_str().unwrap(),
            &identity,
            &old["device_list"],
        ),
    );
    let mut served = old.clone();
    served["device_list"] = recovered["device_list"].clone();
    served["certificates"]
        .as_array_mut()
        .unwrap()
        .push(recovered["certificate"].clone());
    let refused = ok(&mut a1.core, served);
    assert_eq!(
        (&refused["state"], &refused["reason"]),
        (&json!("rejected"), &json!("conflicting_list"))
    );
    let held = a1.rolled_back(|tx| tx.device_list_of(a)).unwrap();
    assert_eq!((held.version, held.contains(a2.id)), (3, false));
    assert_eq!(confirmed, json!({"ok": {}}));

    // Confirming a version this device doesn't hold is `not_found` `upload`.
    let stale = error(
        &mut a1.core,
        json!({"cmd": "device_list_uploaded", "version": 2}),
    );
    assert_eq!(
        (&stale["code"], &stale["what"]),
        (&json!("not_found"), &json!("upload"))
    );
}

/// What an identity command made, its reply lost before the upload, can be had again: a recovered
/// device's certificate and its user's list from `status`; `create_identity`'s and
/// `reset_identity`'s recovery key and blobs from the same command run again, until the client
/// confirms the upload (`identity_uploaded`), which wipes them.
#[test]
fn identity_replies_lost_before_their_upload_are_had_again() {
    let mut server = FakeServer::new();
    let a = new_id();
    let (mut a1, created) = server.first_device(a);
    assert_eq!(ok(&mut a1.core, json!({"cmd": "create_identity"})), created);
    let shown = status(&mut a1);
    assert_eq!(
        (&shown["certificate"], &shown["device_list"]),
        (&created["certificate"], &created["device_list"])
    );
    ok(&mut a1.core, json!({"cmd": "identity_uploaded"}));
    assert_eq!(meta(&mut a1, "kept_identity"), None);
    let again = error(&mut a1.core, json!({"cmd": "create_identity"}));
    assert_eq!(again["code"], "exists");
    let confirmed = error(&mut a1.core, json!({"cmd": "identity_uploaded"}));
    assert_eq!(
        (&confirmed["code"], &confirmed["what"]),
        (&json!("not_found"), &json!("upload"))
    );

    let mut a2 = server.bare_device(a);
    let served = server.observed(a);
    let recovered = ok(
        &mut a2.core,
        recovering(
            created["recovery_key"].as_str().unwrap(),
            &created,
            &served["device_list"],
        ),
    );
    let shown = status(&mut a2);
    assert_eq!(
        (&shown["certificate"], &shown["device_list"]),
        (&recovered["certificate"], &recovered["device_list"])
    );

    let mut b1 = server.bare_device(new_id());
    let reset = ok(&mut b1.core, json!({"cmd": "reset_identity"}));
    assert_eq!(ok(&mut b1.core, json!({"cmd": "reset_identity"})), reset);
}
