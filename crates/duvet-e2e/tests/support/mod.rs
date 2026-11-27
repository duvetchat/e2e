//! A fake of the API for the core's tests: each conversation's queue in order, the compare-and-set
//! of its generation and epoch, the key packages devices publish, each device's inbox, and the
//! API's commit validator on every commit, as the API runs it. Devices are cores, each in a
//! database of its own, driven by JSON as a client drives them.

// Each test file uses its share of these.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use duvet_e2e::{Clock, Core, Error, FakeClock, OpenConfig, Tx, recovery};
use duvet_e2e_rules::{
    DeviceCertificate, DeviceList, Kind, SUITE, group_id_parts, leaf_capabilities,
};
use duvet_e2e_validator::{Members, Op, Request, Response, validate_bytes};
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{
    BasicCredential, CredentialWithKey, KeyPackage, Lifetime, MlsMessageBodyIn, MlsMessageIn,
    OpenMlsProvider, OpenMlsRand, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde_bytes::ByteBuf;
use serde_json::{Value, json};
use tempfile::TempDir;
use uuid::Uuid;

pub const DAY_MS: i64 = 24 * 60 * 60 * 1000;

pub fn new_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0000_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn bytes(value: &Value) -> Vec<u8> {
    STANDARD
        .decode(value.as_str().expect("base64 text"))
        .expect("padded base64")
}

pub fn run(core: &mut Core, command: &Value) -> Value {
    serde_json::from_str(&core.handle(&command.to_string())).expect("a JSON reply")
}

/// The reply of a command that must succeed.
pub fn ok(core: &mut Core, command: Value) -> Value {
    let reply = run(core, &command);
    reply
        .get("ok")
        .cloned()
        .unwrap_or_else(|| panic!("{} failed: {reply}", command["cmd"]))
}

/// The error of a command that must fail.
pub fn error(core: &mut Core, command: Value) -> Value {
    let reply = run(core, &command);
    reply
        .get("error")
        .cloned()
        .unwrap_or_else(|| panic!("{} didn't fail: {reply}", command["cmd"]))
}

/// A device: a core in a database of its own, on the server's clock.
pub struct TestDevice {
    pub core: Core,
    pub user: Uuid,
    pub id: Uuid,
    /// The client's own record of conversations from before the cutover, by conversation: the
    /// owner and members it showed for each, which it hands `apply` as a welcome's `expected`.
    records: BTreeMap<Uuid, Value>,
    _dir: TempDir,
}

impl TestDevice {
    /// The owner and members this device's client showed for `conversation` before the cutover.
    pub fn remember(&mut self, conversation: Uuid, owner: Option<Uuid>, members: &[Uuid]) {
        self.records
            .insert(conversation, json!({"owner": owner, "members": members}));
    }

    /// The record of `conversation`'s forgotten group as this device's client kept it, as
    /// `forget_group` answered it (`expected`), which it hands `apply` as a welcome's `expected`.
    pub fn remember_forgotten(&mut self, conversation: Uuid, expected: &Value) {
        self.records.insert(conversation, expected.clone());
    }

    /// The `group` command's reply.
    pub fn group(&mut self, conversation: Uuid) -> Value {
        ok(
            &mut self.core,
            json!({"cmd": "group", "conversation_id": conversation}),
        )
    }

    /// The `group` command's error.
    pub fn no_group(&mut self, conversation: Uuid) -> Value {
        error(
            &mut self.core,
            json!({"cmd": "group", "conversation_id": conversation}),
        )
    }

    /// Runs `f` in a transaction of this device's database that is then rolled back: what it
    /// makes, the database doesn't keep.
    pub fn rolled_back<T>(&mut self, f: impl FnOnce(&mut Tx<'_>) -> Result<T, Error>) -> T {
        let mut made = None;
        let refused = self.core.transaction(|tx| {
            made = Some(f(tx));
            Err::<(), _>(Error::Internal("rolled back".into()))
        });
        assert!(refused.is_err());
        made.expect("the closure ran").expect("it worked")
    }
}

/// A user as the server and the test know them: the test holds their identity's secret, to sign
/// the certificates and lists of the devices it adds to them.
struct User {
    seed: [u8; 32],
    identity_key: [u8; 32],
    version: u64,
    devices: Vec<Uuid>,
    list: Vec<u8>,
    certificates: BTreeMap<Uuid, Vec<u8>>,
}

impl User {
    fn identity(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            self.seed.to_vec(),
            self.identity_key.to_vec(),
        )
    }
}

/// A device with no core of its own: the test makes its key packages, whatever their lifetime.
struct Virtual {
    user: Uuid,
    signer: SignatureKeyPair,
    certificate: Vec<u8>,
    provider: OpenMlsRustCrypto,
}

/// A key package a device published.
struct Published {
    data: String,
    last_resort: bool,
}

/// An entry of a conversation's queue.
#[derive(Clone, Debug)]
pub struct QueueEntry {
    pub seq: u64,
    pub kind: &'static str,
    pub data: Vec<u8>,
    /// The leave statement a removal proposal brings.
    pub statement: Option<Vec<u8>>,
    /// The fields the API adds to a message, an edit or a deletion: its `message_id`, who sent it
    /// and when, whom it mentions.
    pub meta: serde_json::Map<String, Value>,
}

impl QueueEntry {
    /// The entry as the API hands it out. It never carries `expected`, which a client adds from
    /// its own record.
    pub fn json(&self) -> Value {
        let mut entry = json!({"seq": self.seq, "kind": self.kind, "data": b64(&self.data)});
        if let Some(statement) = &self.statement {
            entry["statement"] = json!(b64(statement));
        }
        for (field, value) in &self.meta {
            entry[field] = value.clone();
        }
        entry
    }
}

/// A conversation as the API keeps it.
pub struct Chat {
    pub kind: Kind,
    pub owner: Option<Uuid>,
    pub users: Vec<Uuid>,
    /// From before the cutover: any member may make its epoch 0.
    pub legacy: bool,
    pub generation: Option<u32>,
    pub epoch: u64,
    state: Option<ByteBuf>,
    /// The group info of the latest epoch, for external commits.
    pub group_info: Option<Vec<u8>>,
    pub queue: Vec<QueueEntry>,
    /// The next entry each device gets.
    cursors: BTreeMap<Uuid, u64>,
    /// Each device's leaf.
    leaves: BTreeMap<Uuid, u32>,
    /// The devices whose removal the server proposes in every epoch until they're out, with the
    /// statement of their user's leaving.
    removals: BTreeMap<Uuid, Option<Vec<u8>>>,
}

impl Chat {
    fn push(&mut self, kind: &'static str, data: Vec<u8>, statement: Option<Vec<u8>>) -> u64 {
        let seq = self.queue.len() as u64 + 1;
        self.queue.push(QueueEntry {
            seq,
            kind,
            data,
            statement,
            meta: serde_json::Map::new(),
        });
        seq
    }

    /// The time the API took the last entry, as it gives every entry's.
    fn stamp(&mut self, sent_at: i64) {
        let entry = self.queue.last_mut().expect("an entry");
        entry.meta.insert("sent_at".into(), json!(sent_at));
    }
}

/// Why the server didn't take a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Another commit took the epoch first: HTTP 409.
    Conflict,
    /// The validator's code.
    Invalid(String),
}

pub struct FakeServer {
    pub clock: FakeClock,
    api: SigningKey,
    users: BTreeMap<Uuid, User>,
    virtuals: BTreeMap<Uuid, Virtual>,
    key_packages: BTreeMap<Uuid, Vec<Published>>,
    handed_out: BTreeSet<String>,
    pub chats: BTreeMap<Uuid, Chat>,
    inboxes: BTreeMap<Uuid, Vec<Vec<u8>>>,
    /// The messages the API took, by their sender's device and nonce: its nonce window.
    nonces: BTreeMap<(Uuid, String), (Uuid, u64)>,
}

impl Default for FakeServer {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeServer {
    pub fn new() -> FakeServer {
        let seed: [u8; 32] = OpenMlsRustCrypto::default().rand().random_array().unwrap();
        FakeServer {
            clock: FakeClock::now(),
            api: SigningKey::from_bytes(&seed),
            users: BTreeMap::new(),
            virtuals: BTreeMap::new(),
            key_packages: BTreeMap::new(),
            handed_out: BTreeSet::new(),
            chats: BTreeMap::new(),
            inboxes: BTreeMap::new(),
            nonces: BTreeMap::new(),
        }
    }

    /// The API's public key, every group's external sender, as `create_group` takes it.
    pub fn external_sender(&self) -> String {
        b64(self.api.verifying_key().as_bytes())
    }

    /// A new device of `user`. The user's first device makes their identity; the next ones get
    /// it as a recovered device would (the test signs their certificates and the list with them).
    pub fn device(&mut self, user: Uuid) -> TestDevice {
        self.device_with_id(user, new_id())
    }

    /// As [`FakeServer::device`], whose ID is `id`.
    pub fn device_with_id(&mut self, user: Uuid, id: Uuid) -> TestDevice {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(OpenConfig {
            clock: Box::new(self.clock.clone()),
            ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
        })
        .unwrap();
        let created = ok(
            &mut core,
            json!({"cmd": "create_device", "user_id": user, "device_id": id}),
        );
        if let Some(record) = self.users.get_mut(&user) {
            let certificate = DeviceCertificate::new(
                user,
                id,
                bytes(&created["signature_key"]).try_into().unwrap(),
                bytes(&created["hpke_key"]).try_into().unwrap(),
                self.clock.now_ms() as u64,
            )
            .sign(&record.identity())
            .unwrap();
            add_to_list(record, id, certificate.clone());
            let (identity_key, seed, list) =
                (record.identity_key, record.seed, record.list.clone());
            core.transaction(|tx| {
                tx.conn()
                    .execute("UPDATE device SET certificate = ?1", [&certificate])?;
                for (key, value) in [
                    ("identity_key", identity_key.as_slice()),
                    ("identity_secret", seed.as_slice()),
                    ("device_list", list.as_slice()),
                ] {
                    tx.conn().execute(
                        "INSERT INTO meta (key, value) VALUES (?1, ?2)",
                        rusqlite::params![key, value],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        } else {
            let identity = ok(&mut core, json!({"cmd": "create_identity"}));
            let recovery_key = recovery::parse(identity["recovery_key"].as_str().unwrap()).unwrap();
            let backup_key = recovery::unwrap_backup_key(
                &recovery_key,
                user,
                &bytes(&identity["wrapped_backup_key"]),
            )
            .unwrap();
            let seed = recovery::decrypt_identity(
                &backup_key,
                user,
                &bytes(&identity["encrypted_identity"]),
            )
            .unwrap();
            self.users.insert(
                user,
                User {
                    seed: *seed,
                    identity_key: bytes(&identity["identity_key"]).try_into().unwrap(),
                    version: 1,
                    devices: vec![id],
                    list: bytes(&identity["device_list"]),
                    certificates: BTreeMap::from([(id, bytes(&identity["certificate"]))]),
                },
            );
        }
        TestDevice {
            core,
            user,
            id,
            records: BTreeMap::new(),
            _dir: dir,
        }
    }

    /// A device of `user` with no core, on their list, whose key packages the test makes.
    pub fn virtual_device(&mut self, user: Uuid) -> Uuid {
        let id = new_id();
        let certificate = self.virtual_under(user, id);
        let record = self.users.get_mut(&user).expect("a user with an identity");
        add_to_list(record, id, certificate);
        id
    }

    /// A virtual device of `user` under `id`, with a new signature key the user's identity
    /// certifies, as any holder of that identity can make: its certificate. Under the ID of a
    /// device already listed, its key packages bring a second leaf under that device.
    pub fn virtual_under(&mut self, user: Uuid, id: Uuid) -> Vec<u8> {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let record = &self.users[&user];
        let certificate = DeviceCertificate::new(
            user,
            id,
            signer.public().try_into().unwrap(),
            [9; 32],
            self.clock.now_ms() as u64,
        )
        .sign(&record.identity())
        .unwrap();
        self.virtuals.insert(
            id,
            Virtual {
                user,
                signer,
                certificate: certificate.clone(),
                provider: OpenMlsRustCrypto::default(),
            },
        );
        certificate
    }

    /// A key package of a virtual device that lasts `seconds` from now, in base64.
    pub fn virtual_key_package(&self, device: Uuid, seconds: u64) -> String {
        let device = &self.virtuals[&device];
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(device.certificate.clone()).into(),
            signature_key: device.signer.public().into(),
        };
        let key_package: KeyPackage = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(now - 60, now + seconds))
            .leaf_node_capabilities(leaf_capabilities())
            .build(SUITE, &device.provider, &device.signer, credential)
            .unwrap()
            .key_package()
            .clone();
        b64(&openmls::prelude::tls_codec::Serialize::tls_serialize_detached(&key_package).unwrap())
    }

    /// `user`'s identity, latest list and the certificates of its devices, as `observe_user`
    /// takes them.
    pub fn observed(&self, user: Uuid) -> Value {
        let record = &self.users[&user];
        let certificates: Vec<String> = record
            .devices
            .iter()
            .map(|device| b64(&record.certificates[device]))
            .collect();
        json!({
            "cmd": "observe_user",
            "user_id": user,
            "identity_key": b64(&record.identity_key),
            "device_list": b64(&record.list),
            "certificates": certificates,
        })
    }

    /// `device` observes every user the server knows, its own included: their identities and
    /// latest lists.
    pub fn introduce(&self, device: &mut TestDevice) {
        for user in self.users.keys() {
            let observed = ok(&mut device.core, self.observed(*user));
            assert_ne!(observed["state"], "rejected", "{observed}");
        }
    }

    /// The device list a device of `user` signed (`sign_device_list`), which the server takes.
    pub fn take_list(&mut self, user: Uuid, list: &Value) {
        let record = self.users.get_mut(&user).unwrap();
        let signed = bytes(list);
        let taken = DeviceList::verify(&signed, &record.identity_key).unwrap();
        record.version = taken.version;
        record.devices = taken.devices.clone();
        record.list = signed;
    }

    /// The new identity a device of `user` made (`rotate_keys`, `reset_identity`'s `reply`), which
    /// the server takes in place of the one it had: the key, the secret its blobs hold (opened as a
    /// recovered device opens them), the list, the certificate of the device that made it, and
    /// those of the devices that stay, whose transfers wait in their inboxes. Every device on the
    /// list has its certificate.
    pub fn take_identity(&mut self, user: Uuid, reply: &Value) {
        let recovery_key = recovery::parse(reply["recovery_key"].as_str().unwrap()).unwrap();
        let backup_key =
            recovery::unwrap_backup_key(&recovery_key, user, &bytes(&reply["wrapped_backup_key"]))
                .unwrap();
        let seed =
            recovery::decrypt_identity(&backup_key, user, &bytes(&reply["encrypted_identity"]))
                .unwrap();
        let identity_key: [u8; 32] = bytes(&reply["identity_key"]).try_into().unwrap();
        let list = bytes(&reply["device_list"]);
        let taken = DeviceList::verify(&list, &identity_key).unwrap();
        let certificate = bytes(&reply["certificate"]);
        let device = DeviceCertificate::verify(&certificate, &identity_key)
            .unwrap()
            .device;
        let mut certificates = BTreeMap::from([(device, certificate)]);
        for handed in reply["transfers"].as_array().into_iter().flatten() {
            let staying: Uuid = handed["device_id"].as_str().unwrap().parse().unwrap();
            let certificate = bytes(&handed["certificate"]);
            let certified = DeviceCertificate::verify(&certificate, &identity_key).unwrap();
            assert_eq!(certified.device, staying, "the device's own certificate");
            certificates.insert(staying, certificate);
            self.post(staying, bytes(&handed["transfer"]));
        }
        assert_eq!(
            taken.devices,
            certificates.keys().copied().collect::<Vec<_>>(),
            "a certificate for each device on the list"
        );
        self.users.insert(
            user,
            User {
                seed: *seed,
                identity_key,
                version: taken.version,
                devices: taken.devices,
                list,
                certificates,
            },
        );
    }

    /// `device`'s key packages: all its live ones, which the server keeps.
    pub fn publish(&mut self, device: &mut TestDevice) {
        let reply = ok(&mut device.core, json!({"cmd": "key_packages"}));
        let published = reply["key_packages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kp| Published {
                data: kp["data"].as_str().unwrap().to_string(),
                last_resort: kp["last_resort"].as_bool().unwrap(),
            })
            .collect();
        self.key_packages.insert(device.id, published);
    }

    /// `device`'s last-resort key package, which a welcome doesn't use up.
    pub fn last_resort(&self, device: Uuid) -> String {
        self.key_packages[&device]
            .iter()
            .find(|kp| kp.last_resort)
            .expect("a last-resort key package")
            .data
            .clone()
    }

    /// A key package for each device of each of `users` that published some, as `create_group`
    /// and `reset_group` take them: a single-use one never handed out before, else the last resort.
    pub fn claim(&mut self, users: &[Uuid]) -> Value {
        let mut claimed = serde_json::Map::new();
        for user in users {
            let mut theirs = Vec::new();
            for device in &self.users[user].devices {
                let Some(published) = self.key_packages.get(device) else {
                    continue;
                };
                let single = published
                    .iter()
                    .find(|kp| !kp.last_resort && !self.handed_out.contains(&kp.data));
                let chosen = single.or_else(|| published.iter().find(|kp| kp.last_resort));
                if let Some(kp) = chosen {
                    self.handed_out.insert(kp.data.clone());
                    theirs.push(json!(kp.data));
                }
            }
            claimed.insert(user.to_string(), Value::Array(theirs));
        }
        Value::Object(claimed)
    }

    /// A conversation the API has: its kind, owner and members.
    pub fn conversation(
        &mut self,
        id: Uuid,
        kind: Kind,
        owner: Option<Uuid>,
        users: &[Uuid],
        legacy: bool,
    ) {
        self.chats.insert(
            id,
            Chat {
                kind,
                owner,
                users: users.to_vec(),
                legacy,
                generation: None,
                epoch: 0,
                state: None,
                group_info: None,
                queue: Vec::new(),
                cursors: BTreeMap::new(),
                leaves: BTreeMap::new(),
                removals: BTreeMap::new(),
            },
        );
    }

    /// `create_group` for `conversation`, as the API has it, with a key package for each device.
    pub fn create_group(&mut self, conversation: Uuid) -> Value {
        let chat = &self.chats[&conversation];
        let (kind, owner, users, legacy) = (chat.kind, chat.owner, chat.users.clone(), chat.legacy);
        json!({
            "cmd": "create_group",
            "conversation_id": conversation,
            "kind": kind,
            "owner": owner,
            "members": users,
            "key_packages": self.claim(&users),
            "external_sender": self.external_sender(),
            "legacy": legacy,
        })
    }

    /// `reset_group` for `conversation`, with its members and owner as the API has them, and a key
    /// package for each device of `users`.
    pub fn reset_group(&mut self, conversation: Uuid, users: &[Uuid]) -> Value {
        let chat = &self.chats[&conversation];
        let (owner, members) = (chat.owner, chat.users.clone());
        json!({
            "cmd": "reset_group",
            "conversation_id": conversation,
            "owner": owner,
            "members": members,
            "key_packages": self.claim(users),
        })
    }

    /// The group info of `conversation`'s latest epoch, in base64, for `join_external`.
    pub fn group_info(&self, conversation: Uuid) -> String {
        b64(self.chats[&conversation].group_info.as_ref().unwrap())
    }

    /// Every entry of `conversation`'s queue, in JSON.
    pub fn entries(&self, conversation: Uuid) -> Vec<Value> {
        self.chats[&conversation]
            .queue
            .iter()
            .map(QueueEntry::json)
            .collect()
    }

    /// Runs `command` on `device` and hands the commit it makes to the server: `Ok` once the server
    /// took it, with the command's reply.
    pub fn commit(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        command: Value,
    ) -> Result<Value, Refusal> {
        let reply = ok(&mut device.core, command);
        self.submit(device, conversation, &reply)?;
        Ok(reply)
    }

    /// The server's side of a commit `device` made (`reply`, the command's): the compare-and-set
    /// of the generation and epoch, then the validator. The device hears the answer through
    /// `commit_result`: the commit's number when it's taken, and `invalid` when the validator
    /// refused it.
    pub fn submit(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        reply: &Value,
    ) -> Result<(), Refusal> {
        let taken = self.take(device, conversation, reply);
        let mut answer = json!({
            "cmd": "commit_result",
            "conversation_id": conversation,
            "accepted": taken.is_ok(),
        });
        match &taken {
            Ok(seq) => answer["seq"] = json!(seq),
            Err(Refusal::Invalid(_)) => answer["invalid"] = json!(true),
            Err(Refusal::Conflict) => {}
        }
        let result = ok(&mut device.core, answer);
        if taken.is_ok() {
            assert_eq!(
                result["epoch"],
                json!(self.chats[&conversation].epoch),
                "the device's epoch is the server's"
            );
        }
        taken.map(|_| ())
    }

    /// The server's side of a commit `device` made, whose answer the device doesn't get: it hears
    /// only that the commit wasn't accepted, as from a retry's 409, and can't tell whether it
    /// entered.
    pub fn answer_lost(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        reply: &Value,
    ) -> Result<u64, Refusal> {
        let taken = self.take(device, conversation, reply);
        ok(
            &mut device.core,
            json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": false}),
        );
        taken
    }

    /// The server takes the commit `device` made (`reply`), but the device hears it refused: the
    /// answer was lost, and the retry got the 409 the first try caused. The commit's number.
    pub fn take_unheard(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        reply: &Value,
    ) -> u64 {
        self.answer_lost(device, conversation, reply)
            .expect("the server takes it")
    }

    /// The API loses `conversation`'s group and its queue, as a database restored to before the
    /// group's founding: the conversation stays, with its members and owner, and no group.
    pub fn lose_group(&mut self, conversation: Uuid) {
        let chat = self.chats.get_mut(&conversation).unwrap();
        chat.generation = None;
        chat.epoch = 0;
        chat.state = None;
        chat.group_info = None;
        chat.queue.clear();
        chat.cursors.clear();
        chat.leaves.clear();
        chat.removals.clear();
    }

    /// `device` founds `conversation`'s group, and the API answers it as taken at the queue's next
    /// number but keeps nothing of it, as a lying server does, or a database restored to before the
    /// founding: the device holds a group the API doesn't. The `create_group` reply.
    pub fn found_unkept(&mut self, device: &mut TestDevice, conversation: Uuid) -> Value {
        let created = ok(&mut device.core, self.create_group(conversation));
        let seq = self.chats[&conversation].queue.len() + 1;
        ok(
            &mut device.core,
            json!({"cmd": "commit_result", "conversation_id": conversation, "accepted": true, "seq": seq}),
        );
        created
    }

    /// The validator's word on a commit, without keeping it.
    pub fn check(&self, conversation: Uuid, commit: &[u8], group_info: &[u8]) -> Response {
        let chat = &self.chats[&conversation];
        let request = Request {
            state: chat.state.clone(),
            message: Some(ByteBuf::from(commit.to_vec())),
            new_group_info: Some(ByteBuf::from(group_info.to_vec())),
            identities: self.identities(),
            device_lists: self.device_lists(),
            ..Request::new(Op::Commit, conversation, chat.generation.unwrap())
        };
        validate(&request)
    }

    /// The server's side of a commit: the commit's number once it's taken.
    fn take(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        reply: &Value,
    ) -> Result<u64, Refusal> {
        let commit = bytes(&reply["commit"]);
        let new_group_info = bytes(&reply["group_info"]);
        let message = MlsMessageIn::tls_deserialize_exact_bytes(&commit)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        let (_, generation) = group_id_parts(message.group_id()).unwrap();
        let epoch = message.epoch().as_u64();
        let identities = self.identities();
        let device_lists = self.device_lists();
        let api_key = ByteBuf::from(self.api.verifying_key().as_bytes().to_vec());
        let chat = self.chats.get_mut(&conversation).unwrap();
        let create = reply.get("initial_group_info").is_some();
        let request = if create {
            if generation != chat.generation.map_or(0, |current| current + 1) {
                return Err(Refusal::Conflict);
            }
            Request {
                group_info: Some(ByteBuf::from(bytes(&reply["initial_group_info"]))),
                message: Some(ByteBuf::from(commit.clone())),
                new_group_info: Some(ByteBuf::from(new_group_info.clone())),
                members: Some(Members {
                    kind: chat.kind,
                    owner: chat.owner,
                    users: chat.users.clone(),
                }),
                identities,
                device_lists,
                external_sender: Some(api_key),
                legacy: chat.legacy && generation == 0,
                ..Request::new(Op::Create, conversation, generation)
            }
        } else {
            if Some(generation) != chat.generation || epoch != chat.epoch {
                return Err(Refusal::Conflict);
            }
            Request {
                state: chat.state.clone(),
                message: Some(ByteBuf::from(commit.clone())),
                new_group_info: Some(ByteBuf::from(new_group_info.clone())),
                identities,
                device_lists,
                ..Request::new(Op::Commit, conversation, generation)
            }
        };
        let response = validate(&request);
        if !response.ok {
            return Err(Refusal::Invalid(response.error.unwrap().code));
        }
        let change = response.change.unwrap();
        chat.state = response.state;
        chat.epoch = response.epoch.unwrap();
        chat.generation = Some(generation);
        chat.group_info = Some(new_group_info);
        // A create's change is from an empty group: everyone entered.
        if create {
            chat.users.clear();
            chat.leaves.clear();
        }
        chat.users
            .retain(|user| !change.users_removed.contains(user));
        chat.users.extend(change.users_added.iter().copied());
        chat.owner = change.owner;
        for removed in &change.devices_removed {
            chat.leaves.remove(&removed.device);
        }
        for added in &change.devices_added {
            chat.leaves.insert(added.device, added.leaf);
        }
        let seq = chat.push("commit", commit, None);
        chat.stamp(self.clock.now_ms());
        // The committer gets the queue from its own commit on, when it had none of it before, as
        // does a device that joins by external commit.
        let joined = !create
            && change
                .devices_added
                .iter()
                .any(|added| added.device == device.id);
        if joined {
            chat.cursors.insert(device.id, seq);
        } else {
            chat.cursors.entry(device.id).or_insert(seq);
        }
        if let Some(welcome) = reply["welcome"].as_str() {
            let welcome_seq = chat.push("welcome", STANDARD.decode(welcome).unwrap(), None);
            chat.stamp(self.clock.now_ms());
            // A device new to the conversation gets the queue from its welcome on; one that had it
            // (a reset brings everyone in again) goes on in order.
            for added in &change.devices_added {
                if added.device != device.id {
                    chat.cursors.entry(added.device).or_insert(welcome_seq);
                }
            }
        }
        // Proposals last one epoch: the removals still to make are proposed again.
        let (again, done): (Vec<Uuid>, Vec<Uuid>) = chat
            .removals
            .keys()
            .copied()
            .partition(|device| chat.leaves.contains_key(device));
        for device in done {
            chat.removals.remove(&device);
        }
        for device in again {
            self.propose_removal(conversation, device);
        }
        Ok(seq)
    }

    /// The API proposes removing `device`'s leaf from `conversation`'s group (a logout, a device
    /// removed from its list, a device inactive for 45 days), and again in each epoch until it's
    /// out.
    pub fn remove_device(&mut self, conversation: Uuid, device: Uuid) {
        let chat = self.chats.get_mut(&conversation).unwrap();
        chat.removals.insert(device, None);
        self.propose_removal(conversation, device);
    }

    /// `device`'s user leaves `conversation` with their statement: the API takes them off the
    /// conversation at once, a group's owner handing it on to the first of those who stay, and
    /// proposes the removal of each of the user's leaves, with the statement for the commit that
    /// takes them out.
    pub fn leave(&mut self, device: &mut TestDevice, conversation: Uuid) {
        let left = ok(
            &mut device.core,
            json!({"cmd": "leave", "conversation_id": conversation}),
        );
        let statement = bytes(&left["statement"]);
        let devices = self.users[&device.user].devices.clone();
        let chat = self.chats.get_mut(&conversation).unwrap();
        chat.users.retain(|&user| user != device.user);
        if chat.owner == Some(device.user)
            && let Some(&first) = chat.users.first()
        {
            chat.owner = Some(first);
        }
        let leaving: Vec<Uuid> = devices
            .into_iter()
            .filter(|device| chat.leaves.contains_key(device))
            .collect();
        for device in &leaving {
            chat.removals.insert(*device, Some(statement.clone()));
        }
        for device in leaving {
            self.propose_removal(conversation, device);
        }
    }

    fn propose_removal(&mut self, conversation: Uuid, device: Uuid) {
        let chat = self.chats.get_mut(&conversation).unwrap();
        let request = Request {
            state: chat.state.clone(),
            signer_key: Some(ByteBuf::from(self.api.to_bytes().to_vec())),
            leaf_index: Some(chat.leaves[&device]),
            ..Request::new(Op::ProposeRemove, conversation, chat.generation.unwrap())
        };
        let response = validate(&request);
        assert!(response.ok, "{:?}", response.error);
        chat.state = response.state;
        let statement = chat.removals[&device].clone();
        chat.push("proposal", response.message.unwrap().into_vec(), statement);
        chat.stamp(self.clock.now_ms());
    }

    /// Puts an entry in `conversation`'s queue without the validator, as a server that skips it
    /// would.
    pub fn force(&mut self, conversation: Uuid, kind: &'static str, data: Vec<u8>) -> u64 {
        self.chats
            .get_mut(&conversation)
            .unwrap()
            .push(kind, data, None)
    }

    /// Hands `device` the entries of each of its conversations it hasn't had yet, through `apply`,
    /// with the API's key as a client gives it: the replies. It adds the device's own record of a
    /// conversation from before the cutover to that conversation's welcomes, as their `expected`,
    /// which the core holds each one to.
    pub fn deliver(&mut self, device: &mut TestDevice) -> Vec<Value> {
        let api = self.external_sender();
        let mut replies = Vec::new();
        for (conversation, chat) in &mut self.chats {
            let Some(&next) = chat.cursors.get(&device.id) else {
                continue;
            };
            let record = device.records.get(conversation);
            let entries: Vec<Value> = chat
                .queue
                .iter()
                .filter(|entry| entry.seq >= next)
                .map(|entry| {
                    let mut json = entry.json();
                    if let (Some(record), "welcome") = (record, entry.kind) {
                        json["expected"] = record.clone();
                    }
                    json
                })
                .collect();
            if entries.is_empty() {
                continue;
            }
            let reply = ok(
                &mut device.core,
                json!({
                    "cmd": "apply",
                    "conversation_id": conversation,
                    "entries": entries,
                    "external_sender": api,
                }),
            );
            chat.cursors.insert(device.id, chat.queue.len() as u64 + 1);
            replies.push(reply);
        }
        replies
    }

    /// Delivers to each of `devices`.
    pub fn deliver_all(&mut self, devices: &mut [&mut TestDevice]) {
        for device in devices.iter_mut() {
            self.deliver(device);
        }
    }

    /// The device-to-device channel: `message` waits in `device`'s inbox.
    pub fn post(&mut self, device: Uuid, message: Vec<u8>) {
        self.inboxes.entry(device).or_default().push(message);
    }

    /// What waits in `device`'s inbox, which it takes.
    pub fn inbox(&mut self, device: Uuid) -> Vec<Vec<u8>> {
        self.inboxes.remove(&device).unwrap_or_default()
    }

    /// A new installation of `user`: a device with no identity yet and on no list, as it is before
    /// it's recovered or approved.
    pub fn bare_device(&mut self, user: Uuid) -> TestDevice {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(OpenConfig {
            clock: Box::new(self.clock.clone()),
            ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
        })
        .unwrap();
        let id = new_id();
        ok(
            &mut core,
            json!({"cmd": "create_device", "user_id": user, "device_id": id}),
        );
        TestDevice {
            core,
            user,
            id,
            records: BTreeMap::new(),
            _dir: dir,
        }
    }

    /// `user`'s first device, which makes their identity, with `create_identity`'s reply: the
    /// recovery key, and the blobs the server keeps for a new device to recover with.
    pub fn first_device(&mut self, user: Uuid) -> (TestDevice, Value) {
        assert!(
            !self.users.contains_key(&user),
            "a user with no identity yet"
        );
        let mut device = self.bare_device(user);
        let identity = ok(&mut device.core, json!({"cmd": "create_identity"}));
        let recovery_key = recovery::parse(identity["recovery_key"].as_str().unwrap()).unwrap();
        let backup_key = recovery::unwrap_backup_key(
            &recovery_key,
            user,
            &bytes(&identity["wrapped_backup_key"]),
        )
        .unwrap();
        let seed =
            recovery::decrypt_identity(&backup_key, user, &bytes(&identity["encrypted_identity"]))
                .unwrap();
        self.users.insert(
            user,
            User {
                seed: *seed,
                identity_key: bytes(&identity["identity_key"]).try_into().unwrap(),
                version: 1,
                devices: vec![device.id],
                list: bytes(&identity["device_list"]),
                certificates: BTreeMap::from([(device.id, bytes(&identity["certificate"]))]),
            },
        );
        (device, identity)
    }

    /// The certificate and the device list a recovered or approved device of `user` brings, which
    /// the server takes.
    pub fn take_device(&mut self, user: Uuid, certificate: &Value, list: &Value) {
        let record = self.users.get_mut(&user).unwrap();
        let certificate = bytes(certificate);
        let device = DeviceCertificate::verify(&certificate, &record.identity_key)
            .unwrap()
            .device;
        let signed = bytes(list);
        let taken = DeviceList::verify(&signed, &record.identity_key).unwrap();
        assert!(taken.version > record.version, "a newer list");
        assert!(taken.contains(device), "a list with the new device");
        record.version = taken.version;
        record.devices = taken.devices.clone();
        record.list = signed;
        record.certificates.insert(device, certificate);
    }

    /// `device` posts a message to `conversation`: its `ciphertext` goes in the queue as the API keeps
    /// it, with a new message ID, who sent it and when, and whom it mentions. The API knows a message
    /// by its sender's device and its `nonce`: posted again, it's the message the API has. The
    /// message's ID and number.
    pub fn post_message(
        &mut self,
        device: &TestDevice,
        conversation: Uuid,
        nonce: &str,
        ciphertext: Vec<u8>,
        mentions: &[Uuid],
    ) -> (Uuid, u64) {
        let key = (device.id, nonce.to_owned());
        if let Some(&posted) = self.nonces.get(&key) {
            return posted;
        }
        let message_id = new_id();
        let seq = self.post_entry(
            device,
            conversation,
            "message",
            message_id,
            ciphertext,
            mentions,
        );
        self.nonces.insert(key, (message_id, seq));
        (message_id, seq)
    }

    /// `device` posts an edit or a deletion (`kind`) of the message `message_id`, which goes in the
    /// queue under that message's ID. Its number.
    pub fn post_change(
        &mut self,
        device: &TestDevice,
        conversation: Uuid,
        kind: &'static str,
        message_id: Uuid,
        ciphertext: Vec<u8>,
    ) -> u64 {
        self.post_entry(device, conversation, kind, message_id, ciphertext, &[])
    }

    fn post_entry(
        &mut self,
        device: &TestDevice,
        conversation: Uuid,
        kind: &'static str,
        message_id: Uuid,
        ciphertext: Vec<u8>,
        mentions: &[Uuid],
    ) -> u64 {
        let sent_at = self.clock.now_ms();
        let chat = self.chats.get_mut(&conversation).unwrap();
        let seq = chat.push(kind, ciphertext, None);
        let meta = &mut chat.queue.last_mut().unwrap().meta;
        meta.insert("message_id".into(), json!(message_id));
        meta.insert("sender_user".into(), json!(device.user));
        meta.insert("sender_device".into(), json!(device.id));
        meta.insert("sent_at".into(), json!(sent_at));
        if !mentions.is_empty() {
            meta.insert("mentions".into(), json!(mentions));
        }
        seq
    }

    /// `user` starts over: the server forgets their identity and their devices, and their next
    /// device makes a new identity.
    pub fn forget_user(&mut self, user: Uuid) {
        self.users.remove(&user);
    }

    fn identities(&self) -> BTreeMap<Uuid, ByteBuf> {
        self.users
            .iter()
            .map(|(user, record)| (*user, ByteBuf::from(record.identity_key.to_vec())))
            .collect()
    }

    fn device_lists(&self) -> BTreeMap<Uuid, ByteBuf> {
        self.users
            .iter()
            .map(|(user, record)| (*user, ByteBuf::from(record.list.clone())))
            .collect()
    }
}

/// Adds `device` to its user's list, under the next version, signed by their identity.
fn add_to_list(record: &mut User, device: Uuid, certificate: Vec<u8>) {
    record.version += 1;
    record.devices.push(device);
    let user = DeviceCertificate::read_unverified(&certificate)
        .unwrap()
        .user;
    record.list = DeviceList::new(
        user,
        record.identity_key,
        record.version,
        record.devices.clone(),
    )
    .sign(&record.identity())
    .unwrap();
    record.certificates.insert(device, certificate);
}

fn validate(request: &Request) -> Response {
    let mut input = Vec::new();
    ciborium::into_writer(request, &mut input).unwrap();
    ciborium::from_reader(validate_bytes(&input).as_slice()).unwrap()
}

/// The group of `conversation` as each of `devices` has it: they must all have the same
/// generation, epoch, members and authenticator. The state they share.
pub fn same_group(devices: &mut [&mut TestDevice], conversation: Uuid) -> Value {
    let states: Vec<Value> = devices
        .iter_mut()
        .map(|device| device.group(conversation))
        .collect();
    for state in &states[1..] {
        for field in [
            "generation",
            "epoch",
            "kind",
            "owner",
            "members",
            "devices",
            "authenticator",
        ] {
            assert_eq!(state[field], states[0][field], "{field}");
        }
    }
    states[0].clone()
}

/// The users of a `group` reply's members, in order.
pub fn members(state: &Value) -> Vec<Uuid> {
    state["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["user_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// The devices of a `group` reply, in leaf order.
pub fn devices(state: &Value) -> Vec<Uuid> {
    state["devices"]
        .as_array()
        .unwrap()
        .iter()
        .map(|device| device["device_id"].as_str().unwrap().parse().unwrap())
        .collect()
}

/// The welcome a commit's reply carries, as OpenMLS reads it.
pub fn welcome_of(reply: &Value) -> openmls::prelude::Welcome {
    match MlsMessageIn::tls_deserialize_exact_bytes(&bytes(&reply["welcome"]))
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => panic!("not a welcome"),
    }
}

impl FakeServer {
    /// As `bare_device`, on a clock of its own instead of the server's: a device whose clock is off.
    pub fn bare_device_on(&mut self, user: Uuid, clock: FakeClock) -> TestDevice {
        let dir = tempfile::tempdir().unwrap();
        let mut core = Core::open(OpenConfig {
            clock: Box::new(clock),
            ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
        })
        .unwrap();
        let id = new_id();
        ok(
            &mut core,
            json!({"cmd": "create_device", "user_id": user, "device_id": id}),
        );
        TestDevice {
            core,
            user,
            id,
            records: BTreeMap::new(),
            _dir: dir,
        }
    }
}

// The end-to-end scenarios and the server as an attacker: what the server holds, the API's key as
// an attacker server signs with it, and one installation opened again.

impl FakeServer {
    /// Every blob the server holds, each with where it holds it: each queue entry's MLS message,
    /// the statement beside it and the fields the API adds to it; each group's info and its
    /// validator state; the key packages; what waits in the inboxes; each user's identity key,
    /// lists and certificates; and the nonces devices sent their messages under.
    pub fn held(&self) -> Vec<(String, Vec<u8>)> {
        let mut held = Vec::new();
        for (conversation, chat) in &self.chats {
            for entry in &chat.queue {
                let place = format!("conversation {conversation}, entry {}", entry.seq);
                held.push((format!("{place}: data"), entry.data.clone()));
                if let Some(statement) = &entry.statement {
                    held.push((format!("{place}: statement"), statement.clone()));
                }
                let meta = Value::Object(entry.meta.clone()).to_string();
                held.push((format!("{place}: meta"), meta.into_bytes()));
            }
            if let Some(info) = &chat.group_info {
                held.push((
                    format!("conversation {conversation}: group info"),
                    info.clone(),
                ));
            }
            if let Some(state) = &chat.state {
                held.push((
                    format!("conversation {conversation}: state"),
                    state.to_vec(),
                ));
            }
        }
        for (device, published) in &self.key_packages {
            for key_package in published {
                let data = STANDARD.decode(&key_package.data).expect("padded base64");
                held.push((format!("device {device}: key package"), data));
            }
        }
        for (device, inbox) in &self.inboxes {
            for message in inbox {
                held.push((format!("device {device}: inbox"), message.clone()));
            }
        }
        for (user, record) in &self.users {
            held.push((
                format!("user {user}: identity key"),
                record.identity_key.to_vec(),
            ));
            held.push((format!("user {user}: device list"), record.list.clone()));
            for (device, certificate) in &record.certificates {
                held.push((
                    format!("user {user}: certificate of {device}"),
                    certificate.clone(),
                ));
            }
        }
        for (device, nonce) in self.nonces.keys() {
            held.push((format!("device {device}: nonce"), nonce.as_bytes().to_vec()));
        }
        held
    }

    /// The API's key, every group's external sender: what an attacker server signs its own
    /// proposals with.
    pub fn api_signer(&self) -> SignatureKeyPair {
        SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            self.api.to_bytes().to_vec(),
            self.api.verifying_key().to_bytes().to_vec(),
        )
    }
}

impl TestDevice {
    /// The same installation opened again: its client closed the core (a session that ended, a
    /// logout, the app quitting) and opens the database it left, with its key.
    pub fn reopened(self, clock: FakeClock) -> TestDevice {
        let TestDevice {
            core,
            user,
            id,
            records,
            _dir: dir,
        } = self;
        core.close();
        let core = Core::open(OpenConfig {
            clock: Box::new(clock),
            ..OpenConfig::new(dir.path().join("core.db"), [1; 32])
        })
        .expect("the same database opens again");
        TestDevice {
            core,
            user,
            id,
            records,
            _dir: dir,
        }
    }
}

impl TestDevice {
    /// The file of the device's database, which every command commits to before it answers.
    pub fn db_path(&self) -> std::path::PathBuf {
        self._dir.path().join("core.db")
    }
}

impl FakeServer {
    /// The server takes the commit `device` made (`reply`), and the device hears nothing: the
    /// answer is still on its way. The commit's number.
    pub fn take_unanswered(
        &mut self,
        device: &mut TestDevice,
        conversation: Uuid,
        reply: &Value,
    ) -> u64 {
        self.take(device, conversation, reply)
            .expect("the server takes it")
    }

    /// The validator's request for `commit` on `conversation`'s state, in CBOR, as `check` builds
    /// it: a seed for the fuzz target of the validator's input.
    pub fn commit_request(&self, conversation: Uuid, commit: &[u8], group_info: &[u8]) -> Vec<u8> {
        let chat = &self.chats[&conversation];
        let request = Request {
            state: chat.state.clone(),
            message: Some(ByteBuf::from(commit.to_vec())),
            new_group_info: Some(ByteBuf::from(group_info.to_vec())),
            identities: self.identities(),
            device_lists: self.device_lists(),
            ..Request::new(Op::Commit, conversation, chat.generation.unwrap())
        };
        let mut out = Vec::new();
        ciborium::into_writer(&request, &mut out).unwrap();
        out
    }
}

// A history package's import, for the tests that bound what an import holds (history_memory.rs,
// hostile.rs).

/// A group of A and B, a device each, both in it: its conversation and the devices.
pub fn group(server: &mut FakeServer, a: Uuid, b: Uuid) -> (Uuid, TestDevice, TestDevice) {
    let mut devices = [a, b].map(|user| server.device(user));
    for device in &mut devices {
        server.publish(device);
    }
    for device in &mut devices {
        server.introduce(device);
    }
    let [mut a1, mut b1] = devices;
    let conversation = new_id();
    server.conversation(conversation, Kind::Group, Some(a), &[a, b], false);
    let create = server.create_group(conversation);
    server.commit(&mut a1, conversation, create).unwrap();
    server.deliver_all(&mut [&mut a1, &mut b1]);
    (conversation, a1, b1)
}

/// The certificates of `user`'s devices as the server serves them.
pub fn certificates(server: &FakeServer, user: Uuid) -> Vec<Vec<u8>> {
    server.observed(user)["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .map(bytes)
        .collect()
}

/// The certificate of `user`'s `device`, in base64.
pub fn certificate(server: &FakeServer, user: Uuid, device: Uuid) -> String {
    let found = certificates(server, user)
        .into_iter()
        .find(|signed| DeviceCertificate::read_unverified(signed).unwrap().device == device)
        .expect("the device's certificate");
    b64(&found)
}

/// A1's package of `deflated` records for B, whose key B1 takes: the command that imports it.
pub fn import_of(
    server: &FakeServer,
    a1: &mut TestDevice,
    b1: &mut TestDevice,
    conversation: Uuid,
    deflated: &[u8],
) -> String {
    import_package(server, a1, b1, conversation, |own, header| {
        duvet_e2e::history::package(&own.signer, header, deflated)
    })
}

/// The package `make` makes on A1 from its device and the share's header, sealed for B, whose key
/// B1 takes: the command that imports it.
pub fn import_package(
    server: &FakeServer,
    a1: &mut TestDevice,
    b1: &mut TestDevice,
    conversation: Uuid,
    make: impl FnOnce(&duvet_e2e::OwnDevice, &duvet_e2e::history::Header) -> Result<Vec<u8>, Error>,
) -> String {
    use duvet_e2e::history::{self, Header, ShareKind};

    let (a, b) = (a1.user, b1.user);
    let devices = certificates(server, b);
    let sealed = a1
        .core
        .transaction(|tx| {
            let own = tx.own_device()?;
            let header = Header {
                kind: ShareKind::Share,
                conversation,
                user: a,
                device: own.device,
                to: b,
            };
            let package = make(&own, &header)?;
            history::seal(tx, ShareKind::Share, conversation, b, &package, &devices)
        })
        .unwrap();
    let shared = serde_json::to_value(&sealed).unwrap();
    let key = json!({
        "cmd": "receive_direct",
        "message": shared["keys"][0]["message"],
        "from_certificate": certificate(server, a, a1.id),
    });
    ok(&mut b1.core, key);
    json!({
        "cmd": "history_import",
        "share_id": shared["share_id"],
        "parts": shared["parts"],
    })
    .to_string()
}
