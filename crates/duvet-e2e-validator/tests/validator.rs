//! The validator through its one entry point, on real OpenMLS groups: the commits it takes, those it
//! refuses and why, and the state it hands back for the next request.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ciborium::Value;
use duvet_e2e_rules::{
    CommitAad, DeviceCertificate, DeviceList, Entry, Kind, MemberList, SUITE, group_config,
    group_id, join_config, leaf_capabilities,
};
use duvet_e2e_validator::{Change, DeviceLeaf, Members, Op, Request, Response, validate_bytes};
use ed25519_dalek::SigningKey;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls::treesync::errors::{LeafNodeValidationError, LifetimeError};
use openmls_basic_credential::SignatureKeyPair;
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use serde::Serialize;
use serde_bytes::ByteBuf;
use uuid::Uuid;

const CONVERSATION: Uuid = Uuid::from_u128(0x0193a1b2_c3d4_7e5f_8a6b_7c8d9e0f1a2b);
const GENERATION: u32 = 0;

// The people of most tests: the owner, A, B, and C, outside the group.
const O: usize = 0;
const A: usize = 1;
const B: usize = 2;
const C: usize = 3;

fn new_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0000_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn signer() -> SignatureKeyPair {
    SignatureKeyPair::new(SignatureScheme::ED25519).unwrap()
}

fn public(signer: &SignatureKeyPair) -> [u8; 32] {
    signer.public().try_into().unwrap()
}

fn random_key() -> SigningKey {
    let seed: [u8; 32] = OpenMlsRustCrypto::default().rand().random_array().unwrap();
    SigningKey::from_bytes(&seed)
}

fn tls(message: &MlsMessageOut) -> Vec<u8> {
    message.tls_serialize_detached().unwrap()
}

/// A group info as the API keeps it: an MLS message.
fn info_bytes(info: &GroupInfo) -> Vec<u8> {
    tls(&MlsMessageOut::from(info.clone()))
}

fn incoming(bytes: &[u8]) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(bytes).unwrap()
}

fn encode(value: &impl Serialize) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).unwrap();
    out
}

/// The validator's answer to `request`, through its bytes as the API sends them.
fn run(request: &Request) -> Response {
    ciborium::from_reader(validate_bytes(&encode(request)).as_slice()).unwrap()
}

/// The code of a refusal.
fn code(response: &Response) -> &str {
    assert!(!response.ok, "accepted: {response:?}");
    &response.error.as_ref().expect("an error").code
}

fn adding(list: &MemberList, user: Uuid, epoch: u64) -> MemberList {
    let mut list = list.clone();
    list.users.push(Entry {
        user,
        generation: GENERATION,
        epoch,
    });
    list
}

/// `device`'s group from `welcome`, taken as clients take one: without holding the tree's leaves
/// to their lifetimes, so a device that never renewed its leaf keeps nobody out.
fn welcomed(device: &Device, welcome: &Welcome) -> MlsGroup {
    StagedWelcome::build_from_welcome(&device.provider, &join_config(), welcome.clone())
        .unwrap()
        .skip_lifetime_validation()
        .build()
        .unwrap()
        .into_group(&device.provider)
        .unwrap()
}

/// How many proposals a state keeps.
fn queued_proposals(state: &[u8]) -> usize {
    let values: BTreeMap<ByteBuf, ByteBuf> = ciborium::from_reader(state).unwrap();
    values
        .keys()
        .filter(|key| key.starts_with(b"QueuedProposal"))
        .count()
}

struct Device {
    user: Uuid,
    id: Uuid,
    signer: SignatureKeyPair,
    provider: OpenMlsRustCrypto,
    certificate: Vec<u8>,
}

impl Device {
    /// A device of `user`, its certificate signed by `identity`.
    fn new(user: Uuid, identity: &SignatureKeyPair) -> Device {
        let id = new_id();
        let signer = signer();
        let certificate = DeviceCertificate::new(user, id, public(&signer), [7; 32], 1)
            .sign(identity)
            .unwrap();
        Device {
            user,
            id,
            signer,
            provider: OpenMlsRustCrypto::default(),
            certificate,
        }
    }

    fn credential(&self) -> CredentialWithKey {
        CredentialWithKey {
            credential: BasicCredential::new(self.certificate.clone()).into(),
            signature_key: self.signer.public().into(),
        }
    }

    fn key_package(&self) -> KeyPackage {
        self.key_package_with(Lifetime::default())
    }

    fn key_package_with(&self, lifetime: Lifetime) -> KeyPackage {
        KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(leaf_capabilities())
            .build(SUITE, &self.provider, &self.signer, self.credential())
            .unwrap()
            .key_package()
            .clone()
    }
}

struct User {
    id: Uuid,
    identity: SignatureKeyPair,
    devices: Vec<Device>,
    /// The user's device list, signed.
    list: Vec<u8>,
}

impl User {
    /// A user with `devices` devices, all on their list.
    fn new(devices: usize) -> User {
        let id = new_id();
        let identity = signer();
        let devices: Vec<Device> = (0..devices).map(|_| Device::new(id, &identity)).collect();
        let list = DeviceList::new(
            id,
            public(&identity),
            1,
            devices.iter().map(|d| d.id).collect(),
        )
        .sign(&identity)
        .unwrap();
        User {
            id,
            identity,
            devices,
            list,
        }
    }
}

/// The people, and the API with its signature key: the groups' one external sender.
struct World {
    users: Vec<User>,
    api: SigningKey,
}

/// Epoch 0 of a group, and its first commit, staged by its creator.
struct First {
    creator: (usize, usize),
    group: MlsGroup,
    /// Epoch 0's group info, with its tree.
    info: Vec<u8>,
    bundle: CommitMessageBundle,
    joined: Vec<(usize, usize)>,
}

impl World {
    fn new(devices: &[usize]) -> World {
        World {
            users: devices.iter().map(|&n| User::new(n)).collect(),
            api: random_key(),
        }
    }

    fn device(&self, (user, device): (usize, usize)) -> &Device {
        &self.users[user].devices[device]
    }

    fn id(&self, user: usize) -> Uuid {
        self.users[user].id
    }

    fn api_key(&self) -> ByteBuf {
        ByteBuf::from(self.api.verifying_key().to_bytes().to_vec())
    }

    fn external_sender(&self) -> ExternalSender {
        ExternalSender::new(
            self.api.verifying_key().as_bytes().as_slice().into(),
            BasicCredential::new(b"duvet".to_vec()).into(),
        )
    }

    /// Every user's identity key, as the API passes them.
    fn identities(&self) -> BTreeMap<Uuid, ByteBuf> {
        self.users
            .iter()
            .map(|u| (u.id, ByteBuf::from(public(&u.identity).to_vec())))
            .collect()
    }

    /// Every user's signed device list, as the API passes them.
    fn device_lists(&self) -> BTreeMap<Uuid, ByteBuf> {
        self.users
            .iter()
            .map(|u| (u.id, ByteBuf::from(u.list.clone())))
            .collect()
    }

    /// A member list of `users`, entered at epoch 0.
    fn list(&self, kind: Kind, owner: Option<usize>, users: &[usize]) -> MemberList {
        let entries = users
            .iter()
            .map(|&user| Entry {
                user: self.id(user),
                generation: GENERATION,
                epoch: 0,
            })
            .collect();
        MemberList::new(kind, owner.map(|user| self.id(user)), entries)
    }

    /// `creator` makes epoch 0 with `members` as its list, and stages the first commit, adding `joined`.
    fn first_commit(
        &self,
        creator: (usize, usize),
        members: &MemberList,
        joined: &[(usize, usize)],
    ) -> First {
        let key_packages = joined
            .iter()
            .map(|&device| (device, self.device(device).key_package()))
            .collect();
        self.first_commit_with(creator, members, key_packages)
    }

    /// As [`World::first_commit`], with the key packages given.
    fn first_commit_with(
        &self,
        creator: (usize, usize),
        members: &MemberList,
        key_packages: Vec<((usize, usize), KeyPackage)>,
    ) -> First {
        let device = self.device(creator);
        let config = group_config(members, self.external_sender());
        let mut group = MlsGroup::new_with_group_id(
            &device.provider,
            &device.signer,
            &config,
            group_id(CONVERSATION, GENERATION),
            device.credential(),
        )
        .unwrap();
        let info = tls(&group
            .export_group_info(device.provider.crypto(), &device.signer, true)
            .unwrap());
        let joined = key_packages.iter().map(|(device, _)| *device).collect();
        let bundle = group
            .commit_builder()
            .propose_adds(key_packages.into_iter().map(|(_, key_package)| key_package))
            .load_psks(device.provider.storage())
            .unwrap()
            .build(
                device.provider.rand(),
                device.provider.crypto(),
                &device.signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&device.provider)
            .unwrap();
        First {
            creator,
            group,
            info,
            bundle,
            joined,
        }
    }

    /// The API's request to take `first`, for a conversation whose members it has as `api`.
    fn create_request(&self, first: &First, api: &MemberList) -> Request {
        Request {
            group_info: Some(ByteBuf::from(first.info.clone())),
            message: Some(ByteBuf::from(tls(first.bundle.commit()))),
            new_group_info: Some(ByteBuf::from(info_bytes(
                first.bundle.group_info().expect("a group info"),
            ))),
            members: Some(Members {
                kind: api.kind,
                owner: api.owner,
                users: api.users.iter().map(|entry| entry.user).collect(),
            }),
            identities: self.identities(),
            device_lists: self.device_lists(),
            external_sender: Some(self.api_key()),
            ..Request::new(Op::Create, CONVERSATION, GENERATION)
        }
    }
}

/// A commit for [`Chat::stage`]. Every commit renews its committer's leaf.
#[derive(Clone, Default)]
struct Commit {
    adds: Vec<(usize, usize)>,
    /// Devices whose leaves the commit removes.
    removes: Vec<(usize, usize)>,
    /// The member list after the commit; the context's other extensions stay.
    members: Option<MemberList>,
    /// Leaves out the proposals the server made.
    leave_out_pending: bool,
}

/// A commit a device made, waiting for the validator's word.
struct Staged {
    by: (usize, usize),
    bundle: CommitMessageBundle,
    joined: Vec<(usize, usize)>,
    /// The group of a device joining by external commit, already at the new epoch.
    joiner: Option<MlsGroup>,
}

/// A conversation's group as its devices and the API see it: each device's own view, and the
/// validator's state with the latest group info, which the API keeps.
struct Chat {
    world: World,
    groups: BTreeMap<(usize, usize), MlsGroup>,
    state: ByteBuf,
    epoch: u64,
    info: Vec<u8>,
}

impl Chat {
    /// `creator` makes the group with `members`, adding `joined`, and the validator takes it.
    fn start(
        world: World,
        members: MemberList,
        creator: (usize, usize),
        joined: &[(usize, usize)],
    ) -> Chat {
        let first = world.first_commit(creator, &members, joined);
        let created = run(&world.create_request(&first, &members));
        Chat::created(world, first, &created)
    }

    /// The owner, A and B; C outside.
    fn group() -> Chat {
        let world = World::new(&[1, 1, 1, 1]);
        let members = world.list(Kind::Group, Some(O), &[O, A, B]);
        Chat::start(world, members, (O, 0), &[(A, 0), (B, 0)])
    }

    /// The group once the validator took `first`.
    fn created(world: World, first: First, created: &Response) -> Chat {
        assert!(created.ok, "create refused: {:?}", created.error);
        let First {
            creator,
            mut group,
            bundle,
            joined,
            ..
        } = first;
        group
            .merge_pending_commit(&world.device(creator).provider)
            .unwrap();
        let mut groups = BTreeMap::from([(creator, group)]);
        for joiner in joined {
            let welcome = bundle.welcome().expect("a welcome");
            groups.insert(joiner, welcomed(world.device(joiner), welcome));
        }
        Chat {
            state: created.state.clone().unwrap(),
            epoch: created.epoch.unwrap(),
            info: info_bytes(bundle.group_info().unwrap()),
            world,
            groups,
        }
    }

    fn id(&self, user: usize) -> Uuid {
        self.world.id(user)
    }

    fn list(&self) -> MemberList {
        let group = self.groups.values().next().unwrap();
        MemberList::from_group_context(group.public_group().group_context()).unwrap()
    }

    fn leaf(&self, device: (usize, usize)) -> LeafNodeIndex {
        let key = self.world.device(device).signer.public().to_vec();
        self.groups
            .values()
            .next()
            .unwrap()
            .members()
            .find(|member| member.signature_key == key)
            .expect("the device's leaf")
            .index
    }

    /// `device` and the leaf it has.
    fn device_leaf(&self, device: (usize, usize)) -> DeviceLeaf {
        let d = self.world.device(device);
        DeviceLeaf {
            user: d.user,
            device: d.id,
            leaf: self.leaf(device).u32(),
        }
    }

    /// `by` stages `commit`.
    fn stage(&mut self, by: (usize, usize), commit: Commit) -> Staged {
        let removes: Vec<LeafNodeIndex> = commit
            .removes
            .iter()
            .map(|&device| self.leaf(device))
            .collect();
        let Chat { world, groups, .. } = self;
        let device = world.device(by);
        let group = groups.get_mut(&by).unwrap();
        let extensions = commit.members.as_ref().map(|members| {
            let mut extensions = group.public_group().group_context().extensions().clone();
            extensions.add_or_replace(members.to_extension()).unwrap();
            extensions
        });
        group.set_aad(CommitAad::new(Vec::new()).encode());
        let mut builder = group
            .commit_builder()
            .propose_adds(commit.adds.iter().map(|&d| world.device(d).key_package()))
            .propose_removals(removes)
            .force_self_update(true);
        if let Some(extensions) = extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .unwrap();
        }
        let leave_out_pending = commit.leave_out_pending;
        let bundle = builder
            .load_psks(device.provider.storage())
            .unwrap()
            .build(
                device.provider.rand(),
                device.provider.crypto(),
                &device.signer,
                |proposal| !(leave_out_pending && matches!(proposal.sender(), Sender::External(_))),
            )
            .unwrap()
            .stage_commit(&device.provider)
            .unwrap();
        Staged {
            by,
            bundle,
            joined: commit.adds,
            joiner: None,
        }
    }

    /// `joiner` joins by external commit, on the group info the API keeps.
    fn join_external(&mut self, joiner: (usize, usize)) -> Staged {
        let device = self.world.device(joiner);
        let MlsMessageBodyIn::GroupInfo(info) = incoming(&self.info).extract() else {
            panic!("not a group info");
        };
        let (group, bundle) = MlsGroup::external_commit_builder()
            .with_config(join_config())
            .build_group(&device.provider, info, device.credential())
            .unwrap()
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(leaf_capabilities())
                    .build(),
            )
            .load_psks(device.provider.storage())
            .unwrap()
            .build(
                device.provider.rand(),
                device.provider.crypto(),
                &device.signer,
                |_| true,
            )
            .unwrap()
            .finalize(&device.provider)
            .unwrap();
        Staged {
            by: joiner,
            bundle,
            joined: Vec::new(),
            joiner: Some(group),
        }
    }

    /// The API's request to take `staged`.
    fn request(&self, staged: &Staged) -> Request {
        Request {
            state: Some(self.state.clone()),
            message: Some(ByteBuf::from(tls(staged.bundle.commit()))),
            new_group_info: Some(ByteBuf::from(info_bytes(
                staged.bundle.group_info().expect("a group info"),
            ))),
            identities: self.world.identities(),
            device_lists: self.world.device_lists(),
            ..Request::new(Op::Commit, CONVERSATION, GENERATION)
        }
    }

    /// `by` makes `commit`; the validator takes it or refuses it, and the group follows.
    fn submit(&mut self, by: (usize, usize), commit: Commit) -> Response {
        let staged = self.stage(by, commit);
        let response = run(&self.request(&staged));
        if response.ok {
            self.accept(staged, &response);
        } else {
            self.discard(staged);
        }
        response
    }

    /// Every device takes `staged`, which the validator accepted with `response`.
    fn accept(&mut self, staged: Staged, response: &Response) {
        assert!(response.ok, "refused: {:?}", response.error);
        let Chat { world, groups, .. } = self;
        let commit = tls(staged.bundle.commit());
        for (&device, group) in groups.iter_mut() {
            let provider = &world.device(device).provider;
            if device == staged.by {
                group.merge_pending_commit(provider).unwrap();
                continue;
            }
            let message = incoming(&commit).try_into_protocol_message().unwrap();
            let processed = group.process_message(provider, message).unwrap();
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                panic!("not a commit");
            };
            group.merge_staged_commit(provider, *staged).unwrap();
        }
        groups.retain(|_, group| group.is_active());
        for &joiner in &staged.joined {
            let welcome = staged.bundle.welcome().expect("a welcome");
            groups.insert(joiner, welcomed(world.device(joiner), welcome));
        }
        if let Some(group) = staged.joiner {
            groups.insert(staged.by, group);
        }
        self.state = response.state.clone().unwrap();
        self.epoch = response.epoch.unwrap();
        self.info = info_bytes(staged.bundle.group_info().unwrap());
    }

    fn discard(&mut self, staged: Staged) {
        if staged.joiner.is_none() {
            let provider = &self.world.device(staged.by).provider;
            self.groups
                .get_mut(&staged.by)
                .unwrap()
                .clear_pending_commit(provider.storage())
                .unwrap();
        }
    }

    /// The API's request to propose that `device` leaves.
    fn propose_remove_request(&self, device: (usize, usize)) -> Request {
        Request {
            state: Some(self.state.clone()),
            signer_key: Some(ByteBuf::from(self.world.api.to_bytes().to_vec())),
            leaf_index: Some(self.leaf(device).u32()),
            ..Request::new(Op::ProposeRemove, CONVERSATION, GENERATION)
        }
    }

    /// The API keeps the state `response` brings, and every device keeps the proposal.
    fn proposed(&mut self, response: &Response) {
        assert!(response.ok, "refused: {:?}", response.error);
        self.state = response.state.clone().unwrap();
        let message = response.message.clone().expect("the proposal");
        let Chat { world, groups, .. } = self;
        for (&device, group) in groups.iter_mut() {
            let provider = &world.device(device).provider;
            let message = incoming(&message).try_into_protocol_message().unwrap();
            let processed = group.process_message(provider, message).unwrap();
            let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content()
            else {
                panic!("not a proposal");
            };
            group
                .store_pending_proposal(provider.storage(), *proposal)
                .unwrap();
        }
    }

    /// The server proposes that `device` leaves.
    fn server_removes(&mut self, device: (usize, usize)) -> Response {
        let response = run(&self.propose_remove_request(device));
        if response.ok {
            self.proposed(&response);
        }
        response
    }

    /// `from` sends a message to the group, given to the validator as if it were a commit.
    fn private_message(&mut self, from: (usize, usize)) -> Request {
        let device = self.world.device(from);
        let message = self
            .groups
            .get_mut(&from)
            .unwrap()
            .create_message(&device.provider, &device.signer, b"hello")
            .unwrap();
        Request {
            state: Some(self.state.clone()),
            message: Some(ByteBuf::from(tls(&message))),
            new_group_info: Some(ByteBuf::from(self.info.clone())),
            identities: self.world.identities(),
            device_lists: self.world.device_lists(),
            ..Request::new(Op::Commit, CONVERSATION, GENERATION)
        }
    }
}

#[test]
fn create_then_commit_tracks_epochs() {
    let world = World::new(&[1, 1, 1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let first = world.first_commit((O, 0), &members, &[(A, 0), (B, 0)]);
    let created = run(&world.create_request(&first, &members));
    assert_eq!(created.epoch, Some(1), "{:?}", created.error);
    let mut chat = Chat::created(world, first, &created);
    assert_eq!(
        created.change,
        Some(Change {
            users_added: vec![chat.id(O), chat.id(A), chat.id(B)],
            users_removed: Vec::new(),
            devices_added: vec![
                chat.device_leaf((O, 0)),
                chat.device_leaf((A, 0)),
                chat.device_leaf((B, 0)),
            ],
            devices_removed: Vec::new(),
            owner: Some(chat.id(O)),
        })
    );

    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), chat.id(C), chat.epoch + 1)),
        ..Commit::default()
    };
    let added = chat.submit((O, 0), adds_c);
    assert_eq!(added.epoch, Some(2), "{:?}", added.error);
    assert_eq!(
        added.change,
        Some(Change {
            users_added: vec![chat.id(C)],
            users_removed: Vec::new(),
            devices_added: vec![chat.device_leaf((C, 0))],
            devices_removed: Vec::new(),
            owner: Some(chat.id(O)),
        })
    );
}

#[test]
fn commit_breaking_a_rule_is_refused() {
    let mut chat = Chat::group();
    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), chat.id(C), chat.epoch + 1)),
        ..Commit::default()
    };
    let refused = chat.submit((A, 0), adds_c.clone());
    assert_eq!(code(&refused), "members_changed_by_non_owner");
    assert_eq!(refused.state, None);

    // The API keeps the state it had, which takes the owner's commit.
    let added = chat.submit((O, 0), adds_c);
    assert_eq!(added.epoch, Some(2), "{:?}", added.error);
}

#[test]
fn private_message_is_refused() {
    let mut chat = Chat::group();
    let request = chat.private_message((B, 0));
    assert_eq!(code(&run(&request)), "private_message");
}

#[test]
fn group_info_must_match_the_new_epoch() {
    let mut chat = Chat::group();
    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), chat.id(C), chat.epoch + 1)),
        ..Commit::default()
    };
    let staged = chat.stage((O, 0), adds_c);

    // The group info of the epoch the commit starts from.
    let mut request = chat.request(&staged);
    request.new_group_info = Some(ByteBuf::from(chat.info.clone()));
    assert_eq!(
        code(&run(&request)),
        "group_info_mismatch",
        "the epoch before"
    );

    // The new epoch's, its signature broken: the signature is the encoding's last bytes.
    let mut forged = info_bytes(staged.bundle.group_info().unwrap());
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let mut request = chat.request(&staged);
    request.new_group_info = Some(ByteBuf::from(forged));
    assert_eq!(
        code(&run(&request)),
        "group_info_mismatch",
        "not the committer's"
    );

    // Not a group info at all.
    let mut request = chat.request(&staged);
    request.new_group_info = request.message.clone();
    assert_eq!(
        code(&run(&request)),
        "group_info_mismatch",
        "the commit itself"
    );

    let own = run(&chat.request(&staged));
    assert_eq!(own.epoch, Some(2), "its own group info: {:?}", own.error);

    // The committer's, exported once it merged its commit: without the tree a joining device
    // needs, and with it.
    let o = chat.world.device((O, 0));
    chat.groups
        .get_mut(&(O, 0))
        .unwrap()
        .merge_pending_commit(&o.provider)
        .unwrap();
    let exported = |with_tree| {
        let info = chat.groups[&(O, 0)]
            .export_group_info(o.provider.crypto(), &o.signer, with_tree)
            .unwrap();
        let mut request = chat.request(&staged);
        request.new_group_info = Some(ByteBuf::from(tls(&info)));
        run(&request)
    };
    assert_eq!(
        code(&exported(false)),
        "group_info_mismatch",
        "without its tree"
    );
    assert_eq!(exported(true).epoch, Some(2), "with its tree");
}

#[test]
fn propose_remove_then_commit_must_include_it() {
    // A has two devices in the group, and logs one out.
    let world = World::new(&[1, 2, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let mut chat = Chat::start(world, members, (O, 0), &[(A, 0), (A, 1), (B, 0)]);
    let leaving = chat.device_leaf((A, 1));

    let proposed = chat.server_removes((A, 1));
    assert_eq!(proposed.epoch, Some(1), "{:?}", proposed.error);
    assert!(proposed.message.is_some());
    assert_eq!(queued_proposals(&chat.state), 1);

    let dropped = Commit {
        leave_out_pending: true,
        ..Commit::default()
    };
    assert_eq!(
        code(&chat.submit((B, 0), dropped)),
        "pending_removal_dropped"
    );

    let committed = chat.submit((B, 0), Commit::default());
    assert_eq!(committed.epoch, Some(2), "{:?}", committed.error);
    assert_eq!(
        committed.change,
        Some(Change {
            users_added: Vec::new(),
            users_removed: Vec::new(),
            devices_added: Vec::new(),
            devices_removed: vec![leaving],
            owner: Some(chat.id(O)),
        })
    );
    assert_eq!(
        queued_proposals(&chat.state),
        0,
        "the proposal went with its epoch"
    );
}

#[test]
fn stale_never_updated_leaf_does_not_block() {
    // A's device never commits, so its leaf keeps its key package's lifetime, which here ends
    // seconds after A joins: the leaf goes stale as one would 100 days on. OpenMLS reads the
    // system's clock, which a test can't move (the Go test moves wazero's).
    let world = World::new(&[1, 1, 1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let not_after = now() + 5;
    let stale = world
        .device((A, 0))
        .key_package_with(Lifetime::init(now() - 60, not_after));
    let fresh = world.device((B, 0)).key_package();
    let first = world.first_commit_with((O, 0), &members, vec![((A, 0), stale), ((B, 0), fresh)]);
    let created = run(&world.create_request(&first, &members));
    let mut chat = Chat::created(world, first, &created);
    while now() <= not_after {
        std::thread::sleep(Duration::from_millis(200));
    }

    // Built from scratch, as epoch 0 is, the group would now refuse A's leaf.
    let MlsMessageBodyIn::GroupInfo(info) = incoming(&chat.info).extract() else {
        panic!("not a group info");
    };
    let tree = info
        .extensions()
        .ratchet_tree()
        .unwrap()
        .ratchet_tree()
        .clone();
    let rebuilt = PublicGroup::from_external(
        &RustCrypto::default(),
        &MemoryStorage::default(),
        tree,
        info,
        ProposalStore::new(),
    );
    assert!(
        matches!(
            rebuilt,
            Err(CreationFromExternalError::LeafNodeValidation(
                LeafNodeValidationError::Lifetime(LifetimeError::Expired { .. })
            ))
        ),
        "A's leaf is stale"
    );

    // The validator keeps the group's state instead, and the next commits go through.
    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), chat.id(C), chat.epoch + 1)),
        ..Commit::default()
    };
    let added = chat.submit((O, 0), adds_c);
    assert_eq!(added.epoch, Some(2), "{:?}", added.error);
    let renewed = chat.submit((B, 0), Commit::default());
    assert_eq!(renewed.epoch, Some(3), "{:?}", renewed.error);
}

/// The workspace's OpenMLS lets a member apply a commit whose added key package expired after the
/// validator took it (vendor/README.md). The validator, which checks each commit as it comes, still
/// holds that key package to its lifetime, and so does a member making such a commit.
#[test]
fn an_added_key_package_expires_for_the_validator_not_for_a_member_applying_late() {
    let mut chat = Chat::group();
    let not_after = now() + 5;
    let short = chat
        .world
        .device((C, 0))
        .key_package_with(Lifetime::init(now() - 60, not_after));
    let members = adding(&chat.list(), chat.id(C), chat.epoch + 1);
    let Chat { world, groups, .. } = &mut chat;
    let owner = world.device((O, 0));
    let group = groups.get_mut(&(O, 0)).unwrap();
    let mut extensions = group.public_group().group_context().extensions().clone();
    extensions.add_or_replace(members.to_extension()).unwrap();
    group.set_aad(CommitAad::new(Vec::new()).encode());
    let bundle = group
        .commit_builder()
        .propose_adds([short.clone()])
        .force_self_update(true)
        .propose_group_context_extensions(extensions)
        .unwrap()
        .load_psks(owner.provider.storage())
        .unwrap()
        .build(
            owner.provider.rand(),
            owner.provider.crypto(),
            &owner.signer,
            |_| true,
        )
        .unwrap()
        .stage_commit(&owner.provider)
        .unwrap();
    let staged = Staged {
        by: (O, 0),
        bundle,
        joined: vec![(C, 0)],
        joiner: None,
    };
    assert!(run(&chat.request(&staged)).ok, "taken while it holds");
    while now() <= not_after {
        std::thread::sleep(Duration::from_millis(200));
    }

    assert_eq!(code(&run(&chat.request(&staged))), "invalid_commit");
    let Chat { world, groups, .. } = &mut chat;
    let member = world.device((A, 0));
    let commit = incoming(&tls(staged.bundle.commit()))
        .try_into_protocol_message()
        .unwrap();
    let applied = groups
        .get_mut(&(A, 0))
        .unwrap()
        .process_message(&member.provider, commit)
        .expect("a member applying it late takes it");
    assert!(matches!(
        applied.into_content(),
        ProcessedMessageContent::StagedCommitMessage(_)
    ));

    chat.discard(staged);
    let Chat { world, groups, .. } = &mut chat;
    let owner = world.device((O, 0));
    let made = groups
        .get_mut(&(O, 0))
        .unwrap()
        .commit_builder()
        .propose_adds([short])
        .load_psks(owner.provider.storage())
        .unwrap()
        .build(
            owner.provider.rand(),
            owner.provider.crypto(),
            &owner.signer,
            |_| true,
        );
    assert!(made.is_err(), "no member makes it now");
}

#[test]
fn create_holds_epoch_zero_to_the_conversations_members() {
    let world = World::new(&[1, 1, 1]);
    // The verdict on the epoch 0 `creator` makes with `list`, adding `joined`, for a conversation
    // the API has as `api`.
    let verdict = |creator: (usize, usize),
                   list: &MemberList,
                   joined: &[(usize, usize)],
                   api: &MemberList,
                   legacy: bool| {
        let mut first = world.first_commit(creator, list, joined);
        let mut request = world.create_request(&first, api);
        request.legacy = legacy;
        let response = run(&request);
        // The creator makes epoch 0 again in the next case.
        let storage = world.device(creator).provider.storage();
        first.group.delete(storage).unwrap();
        if response.ok {
            Ok(response.epoch)
        } else {
            Err(response.error.unwrap().code)
        }
    };
    let mismatch = || Err("member_list_mismatch".to_string());
    let group = world.list(Kind::Group, Some(O), &[O, A]);

    let with_b = world.list(Kind::Group, Some(O), &[O, A, B]);
    assert_eq!(
        verdict((O, 0), &with_b, &[(A, 0), (B, 0)], &group, false),
        mismatch(),
        "B, whom the conversation doesn't have"
    );
    let reordered = world.list(Kind::Group, Some(O), &[A, O]);
    assert_eq!(
        verdict((O, 0), &reordered, &[(A, 0)], &group, false),
        mismatch(),
        "another order"
    );
    let owned_by_a = world.list(Kind::Group, Some(A), &[O, A]);
    assert_eq!(
        verdict((A, 0), &owned_by_a, &[(O, 0)], &group, false),
        mismatch(),
        "A as its owner"
    );
    assert_eq!(
        verdict((A, 0), &group, &[(O, 0)], &group, false),
        Err("members_changed_by_non_owner".to_string()),
        "made by A"
    );
    assert_eq!(
        verdict((A, 0), &group, &[(O, 0)], &group, true),
        Ok(Some(1)),
        "made by A, from before the cutover"
    );
    assert_eq!(
        verdict((O, 0), &group, &[(A, 0)], &group, false),
        Ok(Some(1)),
        "made by its owner"
    );

    let dm = world.list(Kind::Dm, None, &[O, A]);
    assert_eq!(
        verdict((A, 0), &dm, &[(O, 0)], &dm, false),
        Ok(Some(1)),
        "either side starts a DM"
    );
    assert_eq!(
        verdict((A, 0), &dm, &[(O, 0)], &group, false),
        mismatch(),
        "a DM for a group"
    );
}

#[test]
fn create_names_its_conversation_and_generation() {
    let world = World::new(&[1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A]);
    let first = world.first_commit((O, 0), &members, &[(A, 0)]);

    let mut request = world.create_request(&first, &members);
    request.conversation = new_id();
    assert_eq!(code(&run(&request)), "wrong_group", "another conversation");

    let mut request = world.create_request(&first, &members);
    request.generation = GENERATION + 1;
    assert_eq!(code(&run(&request)), "wrong_group", "another generation");
}

#[test]
fn create_takes_the_api_as_the_external_sender() {
    let world = World::new(&[1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A]);
    let first = world.first_commit((O, 0), &members, &[(A, 0)]);
    let mut request = world.create_request(&first, &members);
    request.external_sender = Some(ByteBuf::from(
        random_key().verifying_key().to_bytes().to_vec(),
    ));
    assert_eq!(code(&run(&request)), "context_changed");
}

#[test]
fn a_member_takes_out_a_device_off_its_users_list() {
    // The owner's two devices are in the group, and the API proposes no removal.
    let world = World::new(&[2, 1, 1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let mut chat = Chat::start(world, members, (O, 0), &[(O, 1), (A, 0), (B, 0)]);
    let second = chat.device_leaf((O, 1));
    let removing_it = || Commit {
        removes: vec![(O, 1)],
        ..Commit::default()
    };

    // While the owner's list has its second device, no member takes that device's leaf out.
    let refused = chat.submit((B, 0), removing_it());
    assert_eq!(code(&refused), "leaf_removed_without_reason");

    // Once the list doesn't, any member does, B here, though its commit brings none of the owner's
    // leaves.
    let owner = &mut chat.world.users[O];
    owner.list = DeviceList::new(
        owner.id,
        public(&owner.identity),
        2,
        vec![owner.devices[0].id],
    )
    .sign(&owner.identity)
    .unwrap();
    let taken = chat.submit((B, 0), removing_it());
    assert!(taken.ok, "refused: {:?}", taken.error);
    assert_eq!(taken.change.unwrap().devices_removed, vec![second]);
}

#[test]
fn missing_identities_are_named() {
    let mut chat = Chat::group();
    let c = chat.id(C);
    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), c, chat.epoch + 1)),
        ..Commit::default()
    };
    let staged = chat.stage((O, 0), adds_c);

    let mut without_identity = chat.request(&staged);
    without_identity.identities.remove(&c);
    let mut without_list = chat.request(&staged);
    without_list.device_lists.remove(&c);
    for (case, request) in [
        ("identity", without_identity),
        ("device list", without_list),
    ] {
        let refused = run(&request);
        assert_eq!(code(&refused), "needs_identities", "{case}");
        assert_eq!(refused.error.unwrap().users, vec![c], "{case}");
    }

    let mut tampered = chat.request(&staged);
    let mut list = tampered.device_lists[&c].clone().into_vec();
    let last = list.len() - 1;
    list[last] ^= 1;
    tampered.device_lists.insert(c, ByteBuf::from(list));
    assert_eq!(code(&run(&tampered)), "invalid_signature");
}

#[test]
fn device_joins_by_external_commit() {
    // A's second device, on A's list, isn't in the group yet.
    let world = World::new(&[1, 2, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let mut chat = Chat::start(world, members, (O, 0), &[(A, 0), (B, 0)]);
    let staged = chat.join_external((A, 1));
    let joined = run(&chat.request(&staged));
    assert_eq!(joined.epoch, Some(2), "{:?}", joined.error);
    chat.accept(staged, &joined);
    assert_eq!(
        joined.change,
        Some(Change {
            users_added: Vec::new(),
            users_removed: Vec::new(),
            devices_added: vec![chat.device_leaf((A, 1))],
            devices_removed: Vec::new(),
            owner: Some(chat.id(O)),
        })
    );

    // And the group goes on from the joiner's state.
    let renewed = chat.submit((A, 1), Commit::default());
    assert_eq!(renewed.epoch, Some(3), "{:?}", renewed.error);
}

#[test]
fn propose_remove_refuses_what_cant_be_committed() {
    let mut chat = Chat::group();

    let mut nowhere = chat.propose_remove_request((B, 0));
    nowhere.leaf_index = Some(99);
    assert_eq!(
        code(&run(&nowhere)),
        "bad_request",
        "a leaf the group doesn't have"
    );

    let mut stranger = chat.propose_remove_request((B, 0));
    stranger.signer_key = Some(ByteBuf::from(random_key().to_bytes().to_vec()));
    assert_eq!(
        code(&run(&stranger)),
        "bad_request",
        "a key that isn't the API's"
    );

    let proposed = chat.server_removes((B, 0));
    assert!(proposed.ok, "{:?}", proposed.error);
    assert_eq!(
        code(&chat.server_removes((B, 0))),
        "already_proposed",
        "the same leaf twice in one epoch"
    );
}

#[test]
fn malformed_requests_are_refused() {
    let mut chat = Chat::group();
    let staged = chat.stage((B, 0), Commit::default());
    let good = chat.request(&staged);
    let raw = |bytes: &[u8]| -> Response {
        ciborium::from_reader(validate_bytes(bytes).as_slice()).unwrap()
    };
    let with = |change: &dyn Fn(&mut Request)| {
        let mut request = good.clone();
        change(&mut request);
        run(&request)
    };

    let mut trailing = encode(&good);
    trailing.push(0);
    let cases = [
        ("nothing", raw(b"")),
        ("not CBOR", raw(&[0xff, 0x00, 0x13])),
        ("a CBOR value after the request", raw(&trailing)),
        ("another version", with(&|r| r.v = 2)),
        ("no state", with(&|r| r.state = None)),
        (
            "a state the validator didn't make",
            with(&|r| r.state = Some(ByteBuf::from(vec![1, 2, 3]))),
        ),
        ("no message", with(&|r| r.message = None)),
        ("no group info", with(&|r| r.new_group_info = None)),
        (
            "a short identity key",
            with(&|r| {
                let user = *r.identities.keys().next().unwrap();
                r.identities.insert(user, ByteBuf::from(vec![1; 31]));
            }),
        ),
        (
            "a group the state doesn't hold",
            with(&|r| r.generation = GENERATION + 1),
        ),
    ];
    let refused = cases.map(|(case, response)| (case, code(&response).to_string()));
    let bad = refused
        .clone()
        .map(|(case, _)| (case, "bad_request".to_string()));
    assert_eq!(refused, bad);

    let garbage = with(&|r| r.message = Some(ByteBuf::from(vec![0, 1, 2, 3])));
    assert_eq!(code(&garbage), "invalid_commit", "a message that isn't MLS");

    let mut create = good.clone();
    create.op = Op::Create;
    assert_eq!(
        code(&run(&create)),
        "bad_request",
        "a create without epoch 0"
    );
}

#[test]
fn wire_format_is_the_contracts() {
    // The request and the response as CBOR with text keys, UUIDs as 16 bytes, and numbers
    // unsigned, built and read without the crate's types.
    let world = World::new(&[1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A]);
    let first = world.first_commit((O, 0), &members, &[(A, 0)]);
    let typed = world.create_request(&first, &members);
    let bytes = |bytes: &[u8]| Value::Bytes(bytes.to_vec());
    let uuid = |id: Uuid| Value::Bytes(id.as_bytes().to_vec());
    let map = |fields: Vec<(&str, Value)>| {
        Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (Value::Text(key.to_string()), value))
                .collect(),
        )
    };
    let by_user = |values: &BTreeMap<Uuid, ByteBuf>| {
        Value::Map(
            values
                .iter()
                .map(|(user, value)| (uuid(*user), bytes(value)))
                .collect(),
        )
    };
    let request = map(vec![
        ("v", Value::Integer(1.into())),
        ("op", Value::Text("create".to_string())),
        ("conversation", uuid(CONVERSATION)),
        ("generation", Value::Integer(GENERATION.into())),
        ("group_info", bytes(typed.group_info.as_ref().unwrap())),
        ("message", bytes(typed.message.as_ref().unwrap())),
        (
            "new_group_info",
            bytes(typed.new_group_info.as_ref().unwrap()),
        ),
        (
            "members",
            map(vec![
                ("kind", Value::Text("group".to_string())),
                ("owner", uuid(world.id(O))),
                (
                    "users",
                    Value::Array(vec![uuid(world.id(O)), uuid(world.id(A))]),
                ),
            ]),
        ),
        ("identities", by_user(&typed.identities)),
        ("device_lists", by_user(&typed.device_lists)),
        (
            "external_sender",
            bytes(typed.external_sender.as_ref().unwrap()),
        ),
    ]);
    let response: Value =
        ciborium::from_reader(validate_bytes(&encode(&request)).as_slice()).unwrap();

    let field = |value: &Value, key: &str| -> Value {
        let Value::Map(fields) = value else {
            panic!("not a map: {value:?}");
        };
        fields
            .iter()
            .find(|(k, _)| k == &Value::Text(key.to_string()))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("no {key} in {value:?}"))
    };
    assert_eq!(field(&response, "ok"), Value::Bool(true));
    assert!(matches!(field(&response, "state"), Value::Bytes(_)));
    assert_eq!(field(&response, "epoch"), Value::Integer(1.into()));
    let change = field(&response, "change");
    assert_eq!(
        field(&change, "users_added"),
        Value::Array(vec![uuid(world.id(O)), uuid(world.id(A))])
    );
    assert_eq!(field(&change, "users_removed"), Value::Array(Vec::new()));
    assert_eq!(field(&change, "devices_removed"), Value::Array(Vec::new()));
    assert_eq!(field(&change, "owner"), uuid(world.id(O)));
    let Value::Array(devices) = field(&change, "devices_added") else {
        panic!("no devices");
    };
    let creator = world.device((O, 0));
    assert_eq!(
        devices[0],
        map(vec![
            ("user", uuid(creator.user)),
            ("device", uuid(creator.id)),
            ("leaf", Value::Integer(0.into())),
        ])
    );

    let Value::Map(mut fields) = request else {
        unreachable!()
    };
    fields.retain(|(key, _)| key != &Value::Text("members".to_string()));
    let refused: Value =
        ciborium::from_reader(validate_bytes(&encode(&Value::Map(fields))).as_slice()).unwrap();
    assert_eq!(field(&refused, "ok"), Value::Bool(false));
    let error = field(&refused, "error");
    assert_eq!(
        field(&error, "code"),
        Value::Text("bad_request".to_string())
    );
    assert!(matches!(field(&error, "message"), Value::Text(_)));
}

/// The vectors the Go test runs the module on: each request, and what the native validator
/// answered it.
#[derive(Default)]
struct Vectors {
    vectors: Vec<Vector>,
    files: Vec<(String, Vec<u8>)>,
}

#[derive(Serialize)]
struct Vector {
    name: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

impl Vectors {
    fn add(&mut self, name: &str, request: &Request) -> Response {
        let input = encode(request);
        let response: Response = ciborium::from_reader(validate_bytes(&input).as_slice()).unwrap();
        self.vectors.push(Vector {
            name: name.to_string(),
            ok: response.ok,
            epoch: response.epoch,
            code: response.error.as_ref().map(|error| error.code.clone()),
        });
        self.files.push((format!("{name}.cbor"), input));
        response
    }

    fn write(self) {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../host-tests/go/testdata");
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in &self.files {
            std::fs::write(dir.join(name), bytes).unwrap();
        }
        let manifest = serde_json::json!({ "vectors": self.vectors });
        std::fs::write(
            dir.join("vectors.json"),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "writes host-tests/go/testdata, the Go test's vectors: run it with --ignored"]
fn write_vectors() {
    let mut vectors = Vectors::default();
    // A's second device stays outside until it joins by external commit.
    let world = World::new(&[1, 2, 1, 1]);
    let members = world.list(Kind::Group, Some(O), &[O, A, B]);
    let first = world.first_commit((O, 0), &members, &[(A, 0), (B, 0)]);
    let created = vectors.add("create", &world.create_request(&first, &members));
    let mut chat = Chat::created(world, first, &created);

    let adds_c = Commit {
        adds: vec![(C, 0)],
        members: Some(adding(&chat.list(), chat.id(C), chat.epoch + 1)),
        ..Commit::default()
    };
    let staged = chat.stage((A, 0), adds_c.clone());
    vectors.add("non_owner_adds", &chat.request(&staged));
    chat.discard(staged);
    let staged = chat.stage((O, 0), adds_c);
    let added = vectors.add("add", &chat.request(&staged));
    chat.accept(staged, &added);

    let message = chat.private_message((B, 0));
    vectors.add("private_message", &message);

    // B renews its leaf: a commit that takes no key package, so no lifetime is checked.
    let staged = chat.stage((B, 0), Commit::default());
    let renewed = vectors.add("renew", &chat.request(&staged));
    chat.accept(staged, &renewed);

    let proposed = vectors.add("propose_remove", &chat.propose_remove_request((A, 0)));
    chat.proposed(&proposed);
    let dropped = Commit {
        leave_out_pending: true,
        ..Commit::default()
    };
    let staged = chat.stage((C, 0), dropped);
    vectors.add("removal_dropped", &chat.request(&staged));
    chat.discard(staged);
    let staged = chat.stage((C, 0), Commit::default());
    let committed = vectors.add("removal_committed", &chat.request(&staged));
    chat.accept(staged, &committed);

    let staged = chat.join_external((A, 1));
    let joined = vectors.add("external_join", &chat.request(&staged));
    chat.accept(staged, &joined);

    let staged = chat.stage((O, 0), Commit::default());
    let mut stale = chat.request(&staged);
    stale.new_group_info = Some(ByteBuf::from(chat.info.clone()));
    vectors.add("stale_group_info", &stale);

    let outcomes: Vec<(&str, bool, Option<u64>, Option<&str>)> = vectors
        .vectors
        .iter()
        .map(|v| (v.name.as_str(), v.ok, v.epoch, v.code.as_deref()))
        .collect();
    assert_eq!(
        outcomes,
        [
            ("create", true, Some(1), None),
            (
                "non_owner_adds",
                false,
                None,
                Some("members_changed_by_non_owner")
            ),
            ("add", true, Some(2), None),
            ("private_message", false, None, Some("private_message")),
            ("renew", true, Some(3), None),
            ("propose_remove", true, Some(3), None),
            (
                "removal_dropped",
                false,
                None,
                Some("pending_removal_dropped")
            ),
            ("removal_committed", true, Some(4), None),
            ("external_join", true, Some(5), None),
            ("stale_group_info", false, None, Some("group_info_mismatch")),
        ]
    );
    vectors.write();
}

/// A request whose state the validator didn't make (found by the `validator_input` fuzz target: one byte
/// of a stored value changed). openmls_memory_storage 0.6.0 unwraps what it stores, so the load
/// panics: natively the panic is caught and answered `internal`; in the wasm32-wasip1 module it aborts
/// the call. The API hands back only states the validator made.
#[test]
fn a_state_the_validator_didnt_make_is_answered() {
    let response = validate_bytes(include_bytes!("corrupted-state.cbor"));
    let response: Response = ciborium::from_reader(response.as_slice()).unwrap();
    assert!(!response.ok);
    assert_eq!(response.error.unwrap().code, "internal");
}
