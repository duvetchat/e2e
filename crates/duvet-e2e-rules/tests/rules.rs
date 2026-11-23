//! Duvet's group rules, on real OpenMLS groups: each rule refuses the commit that breaks it.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use duvet_e2e_rules::{
    CommitAad, DeviceCertificate, DeviceList, Entry, Kind, LeaveStatement, MEMBER_LIST_EXTENSION,
    MemberList, MembershipChange, Removed, RuleContext, RuleViolation, SUITE, check_change,
    check_joined_state, check_state, extract_change, group_config, group_id, join_config,
    keeps_record, leaf_capabilities, leaves,
};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use uuid::Uuid;

const CONVERSATION: Uuid = Uuid::from_u128(0x0193a1b2_c3d4_7e5f_8a6b_7c8d9e0f1a2b);
const GENERATION: u32 = 3;

// The people of most tests: the owner with two devices, A with two (one of them outside the group),
// B with two (one outside), and C, outside the group.
const O: usize = 0;
const A: usize = 1;
const B: usize = 2;
const C: usize = 3;

fn new_id() -> Uuid {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Uuid::from_u64_pair(0x0193_0000_0000_7000, NEXT.fetch_add(1, Ordering::Relaxed))
}

fn signer() -> SignatureKeyPair {
    SignatureKeyPair::new(SignatureScheme::ED25519).unwrap()
}

fn public(signer: &SignatureKeyPair) -> [u8; 32] {
    signer.public().try_into().unwrap()
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
        KeyPackage::builder()
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
    list: DeviceList,
}

impl User {
    /// A user with `devices` devices, all on its list.
    fn new(devices: usize) -> User {
        let id = new_id();
        let identity = signer();
        let devices: Vec<Device> = (0..devices).map(|_| Device::new(id, &identity)).collect();
        let list = DeviceList::new(
            id,
            public(&identity),
            1,
            devices.iter().map(|d| d.id).collect(),
        );
        User {
            id,
            identity,
            devices,
            list,
        }
    }
}

struct World {
    users: Vec<User>,
    server: SignatureKeyPair,
}

impl World {
    fn new(devices: &[usize]) -> World {
        World {
            users: devices.iter().map(|&n| User::new(n)).collect(),
            server: signer(),
        }
    }

    fn device(&self, (user, device): (usize, usize)) -> &Device {
        &self.users[user].devices[device]
    }

    fn id(&self, user: usize) -> Uuid {
        self.users[user].id
    }

    /// Every user's identity and device list, as the core and the validator would have pinned them,
    /// and the server as the groups' external sender.
    fn context(&self) -> RuleContext {
        RuleContext {
            identities: self
                .users
                .iter()
                .map(|u| (u.id, public(&u.identity)))
                .collect(),
            device_lists: self.users.iter().map(|u| (u.id, u.list.clone())).collect(),
            external_sender: Some(self.server.public().to_vec()),
            ..RuleContext::default()
        }
    }

    fn external_sender(&self) -> ExternalSender {
        ExternalSender::new(
            self.server.public().into(),
            BasicCredential::new(b"duvet".to_vec()).into(),
        )
    }

    fn entry(&self, user: usize, epoch: u64) -> Entry {
        Entry {
            user: self.id(user),
            generation: GENERATION,
            epoch,
        }
    }

    /// `creator` makes epoch 0 of the conversation's group at `generation`, under `config`, with
    /// `credential` on its leaf.
    fn create(
        &self,
        creator: (usize, usize),
        credential: CredentialWithKey,
        config: &MlsGroupCreateConfig,
        generation: u32,
    ) -> MlsGroup {
        let device = self.device(creator);
        MlsGroup::new_with_group_id(
            &device.provider,
            &device.signer,
            config,
            group_id(CONVERSATION, generation),
            credential,
        )
        .unwrap()
    }

    /// `creator` makes epoch 0 with `members` as its list, and stages its first commit, adding `joined`.
    fn first_commit(
        &self,
        creator: (usize, usize),
        members: &MemberList,
        joined: &[(usize, usize)],
    ) -> (MlsGroup, CommitMessageBundle) {
        self.first_commit_as(creator, self.device(creator).credential(), members, joined)
    }

    /// As [`World::first_commit`], with `credential` on the creator's leaf: its own, or another
    /// device's certificate on the creator's key, to pose as that device.
    fn first_commit_as(
        &self,
        creator: (usize, usize),
        credential: CredentialWithKey,
        members: &MemberList,
        joined: &[(usize, usize)],
    ) -> (MlsGroup, CommitMessageBundle) {
        let device = self.device(creator);
        let config = group_config(members, self.external_sender());
        let mut group = self.create(creator, credential, &config, GENERATION);
        let key_packages: Vec<KeyPackage> = joined
            .iter()
            .map(|&d| self.device(d).key_package())
            .collect();
        let bundle = group
            .commit_builder()
            .propose_adds(key_packages)
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
        (group, bundle)
    }

    /// The group as `joiner` finds it in the welcome of `bundle`.
    fn welcomed(&self, joiner: (usize, usize), bundle: &CommitMessageBundle) -> StagedWelcome {
        let provider = &self.device(joiner).provider;
        let welcome = bundle.welcome().expect("a welcome").clone();
        StagedWelcome::new_from_welcome(provider, &join_config(), welcome, None).unwrap()
    }
}

/// [`check_state`] on a group as a device finds it.
fn state_of(
    ctx: &RuleContext,
    context: &GroupContext,
    members: impl IntoIterator<Item = Member>,
) -> Result<(), RuleViolation> {
    check_state(ctx, context, &leaves(members)?)
}

/// A config like Duvet's, with another suite, other context extensions or other leaf capabilities.
fn config_with(
    suite: Ciphersuite,
    extensions: Vec<Extension>,
    capabilities: Capabilities,
) -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(suite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities)
        .with_group_context_extensions(Extensions::from_vec(extensions).unwrap())
        .build()
}

/// The commit `group` staged, as the rules see it from its committer.
fn own_change(group: &MlsGroup, aad: &[u8]) -> Result<MembershipChange, RuleViolation> {
    let leaves = leaves(group.members())?;
    let staged = group.pending_commit().expect("a staged commit");
    extract_change(
        group.public_group().group_context(),
        &leaves,
        staged,
        &Sender::Member(group.own_leaf_index()),
        aad,
    )
}

fn incoming(message: &MlsMessageOut) -> MlsMessageIn {
    MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap()).unwrap()
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

fn removing(list: &MemberList, user: Uuid) -> MemberList {
    let mut list = list.clone();
    list.users.retain(|entry| entry.user != user);
    list
}

/// A commit for [`Scene::verdict`].
#[derive(Default)]
struct Commit {
    adds: Vec<KeyPackage>,
    /// Devices whose leaves the commit removes.
    removes: Vec<(usize, usize)>,
    /// The member list after the commit; the context's other extensions stay.
    members: Option<MemberList>,
    /// The context's extensions after the commit, whole.
    extensions: Option<Extensions<GroupContext>>,
    statements: Vec<Vec<u8>>,
    /// Leaves out the proposals the server made.
    leave_out_pending: bool,
}

/// A conversation's group, with each device in it holding its own view.
struct Scene {
    world: World,
    groups: BTreeMap<(usize, usize), MlsGroup>,
}

impl Scene {
    fn new(
        world: World,
        members: MemberList,
        creator: (usize, usize),
        joined: &[(usize, usize)],
    ) -> Scene {
        let (mut group, bundle) = world.first_commit(creator, &members, joined);
        group
            .merge_pending_commit(&world.device(creator).provider)
            .unwrap();
        let mut groups = BTreeMap::from([(creator, group)]);
        for &joiner in joined {
            let provider = &world.device(joiner).provider;
            let group = world
                .welcomed(joiner, &bundle)
                .into_group(provider)
                .unwrap();
            groups.insert(joiner, group);
        }
        Scene { world, groups }
    }

    /// The owner (two devices), A and B; C outside, and A's and B's second devices too.
    fn group() -> Scene {
        let world = World::new(&[2, 2, 2, 1]);
        let members = MemberList::new(
            Kind::Group,
            Some(world.id(O)),
            vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)],
        );
        Scene::new(world, members, (O, 0), &[(O, 1), (A, 0), (B, 0)])
    }

    fn any(&self) -> &MlsGroup {
        self.groups.values().next().unwrap()
    }

    fn list(&self) -> MemberList {
        MemberList::from_group_context(self.any().public_group().group_context()).unwrap()
    }

    fn epoch(&self) -> u64 {
        self.any().epoch().as_u64()
    }

    fn id(&self, user: usize) -> Uuid {
        self.world.id(user)
    }

    fn leaf(&self, device: (usize, usize)) -> LeafNodeIndex {
        let key = self.world.device(device).signer.public().to_vec();
        self.any()
            .members()
            .find(|m| m.signature_key == key)
            .expect("the device's leaf")
            .index
    }

    /// `device`'s leave statement, made at `generation` and `epoch`.
    fn statement(&self, device: (usize, usize), generation: u32, epoch: u64) -> Vec<u8> {
        let device = self.world.device(device);
        LeaveStatement::new(device.user, CONVERSATION, generation, epoch, device.id)
            .sign(&device.signer)
            .unwrap()
    }

    /// The rules' verdict on a commit `by` makes, which is then thrown away.
    fn verdict(
        &mut self,
        by: (usize, usize),
        commit: Commit,
        ctx: &RuleContext,
    ) -> Result<(), RuleViolation> {
        let removes: Vec<LeafNodeIndex> = commit.removes.iter().map(|&d| self.leaf(d)).collect();
        let Scene { world, groups } = self;
        let device = world.device(by);
        let group = groups.get_mut(&by).unwrap();
        let mut extensions = commit.extensions;
        if let Some(members) = &commit.members {
            let mut current = group.public_group().group_context().extensions().clone();
            current.add_or_replace(members.to_extension()).unwrap();
            extensions = Some(current);
        }
        let aad = CommitAad::new(commit.statements).encode();
        group.set_aad(aad.clone());
        let mut builder = group
            .commit_builder()
            .propose_adds(commit.adds)
            .propose_removals(removes);
        if let Some(extensions) = extensions {
            builder = builder
                .propose_group_context_extensions(extensions)
                .unwrap();
        }
        let leave_out_pending = commit.leave_out_pending;
        builder
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
        let verdict = own_change(group, &aad).and_then(|change| check_change(ctx, &change));
        group
            .clear_pending_commit(device.provider.storage())
            .unwrap();
        verdict
    }

    /// The server proposes `message`, and every device in the group keeps it for the next commit.
    fn server_proposes(&mut self, message: MlsMessageOut) {
        let Scene { world, groups } = self;
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

    fn server_removes(&mut self, device: (usize, usize)) {
        let removed = self.leaf(device);
        let group = self.any();
        let message = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
            removed,
            group.group_id().clone(),
            group.epoch(),
            &self.world.server,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        self.server_proposes(message);
    }

    fn server_adds(&mut self, key_package: KeyPackage) {
        let group = self.any();
        let message = ExternalProposal::new_add::<OpenMlsRustCrypto>(
            key_package,
            group.group_id().clone(),
            group.epoch(),
            &self.world.server,
            SenderExtensionIndex::new(0),
        )
        .unwrap();
        self.server_proposes(message);
    }

    /// `joiner` joins by an external commit on the group info `observer` exports, and the rules
    /// read it as `observer` receives it.
    fn external_change(
        &mut self,
        joiner: (usize, usize),
        observer: (usize, usize),
    ) -> MembershipChange {
        let Scene { world, groups } = self;
        let exporter = world.device(observer);
        let group = groups.get_mut(&observer).unwrap();
        let info = group
            .export_group_info(exporter.provider.crypto(), &exporter.signer, true)
            .unwrap();
        let MlsMessageBodyIn::GroupInfo(info) = incoming(&info).extract() else {
            panic!("not a group info");
        };
        let device = world.device(joiner);
        let (_joined, bundle) = MlsGroup::external_commit_builder()
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
        let leaves = leaves(group.members()).unwrap();
        let context = group.public_group().group_context().clone();
        let message = incoming(bundle.commit())
            .try_into_protocol_message()
            .unwrap();
        let processed = group.process_message(&exporter.provider, message).unwrap();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.content() else {
            panic!("not a commit");
        };
        extract_change(
            &context,
            &leaves,
            staged,
            processed.sender(),
            processed.aad(),
        )
        .unwrap()
    }
}

#[test]
fn members_changed_by_non_owner_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let commit = Commit {
        adds: vec![s.world.device((C, 0)).key_package()],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), commit, &ctx),
        Err(RuleViolation::MembersChangedByNonOwner)
    );
}

#[test]
fn leave_without_statement_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let commit = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), s.id(B))),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), commit, &ctx),
        Err(RuleViolation::LeaveWithoutStatement)
    );
}

#[test]
fn leave_with_old_statement_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    // From the group's previous generation: before B's latest entry.
    let old = s.statement((B, 0), GENERATION - 1, 9);
    let commit = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), s.id(B))),
        statements: vec![old],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), commit, &ctx),
        Err(RuleViolation::LeaveWithoutStatement)
    );

    // Signed by a device of B's that its latest list no longer has.
    let mut ctx = s.world.context();
    let b = s.id(B);
    let newer = DeviceList::new(
        b,
        public(&s.world.users[B].identity),
        2,
        vec![s.world.device((B, 1)).id],
    );
    ctx.device_lists.insert(b, newer);
    let commit = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), b)),
        statements: vec![s.statement((B, 0), GENERATION, s.epoch())],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), commit, &ctx),
        Err(RuleViolation::LeaveWithoutStatement)
    );
}

#[test]
fn owner_not_successor_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let mut members = removing(&s.list(), s.id(O));
    members.owner = Some(s.id(B)); // A joined before B
    let commit = Commit {
        removes: vec![(O, 0), (O, 1)],
        members: Some(members),
        statements: vec![s.statement((O, 0), GENERATION, s.epoch())],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), commit, &ctx),
        Err(RuleViolation::OwnerNotSuccessor)
    );
}

#[test]
fn owner_leaving_hands_over_to_first_joined() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let mut members = removing(&s.list(), s.id(O));
    members.owner = Some(s.id(A));
    let commit = Commit {
        removes: vec![(O, 0), (O, 1)],
        members: Some(members),
        statements: vec![s.statement((O, 0), GENERATION, s.epoch())],
        ..Commit::default()
    };
    assert_eq!(s.verdict((B, 0), commit, &ctx), Ok(()));
}

#[test]
fn leaf_not_signed_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    // C's device, its certificate signed by A's identity.
    let forged = Device::new(s.id(C), &s.world.users[A].identity);
    let commit = Commit {
        adds: vec![forged.key_package()],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::LeafNotSigned)
    );
}

#[test]
fn leaf_key_mismatch_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    // C's real certificate, on a leaf whose signature key is another.
    let c = s.world.device((C, 0));
    let other = signer();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(c.certificate.clone()).into(),
        signature_key: other.public().into(),
    };
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities())
        .build(SUITE, &c.provider, &other, credential)
        .unwrap()
        .key_package()
        .clone();
    let commit = Commit {
        adds: vec![key_package],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::LeafNotSigned)
    );
}

#[test]
fn device_not_listed_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let unlisted = Device::new(s.id(C), &s.world.users[C].identity);
    let commit = Commit {
        adds: vec![unlisted.key_package()],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::DeviceNotListed)
    );
}

#[test]
fn user_not_member_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let commit = Commit {
        adds: vec![s.world.device((C, 0)).key_package()],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::UserNotMember)
    );
}

#[test]
fn external_join_changes_members_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let b_leaf = s.leaf((B, 0)).u32();
    let change = s.external_change((A, 1), (O, 0));
    assert_eq!(check_change(&ctx, &change), Ok(()));

    let mut taking_b = change.clone();
    taking_b.removed.push(Removed {
        index: b_leaf,
        by_server: false,
    });
    assert_eq!(
        check_change(&ctx, &taking_b),
        Err(RuleViolation::ExternalJoinChangesMembers)
    );

    let mut adding_c = change.clone();
    adding_c.after = adding(&adding_c.after, s.id(C), change.epoch + 1);
    assert_eq!(
        check_change(&ctx, &adding_c),
        Err(RuleViolation::ExternalJoinChangesMembers)
    );
}

#[test]
fn server_proposal_not_remove_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let key_package = s.world.device((C, 0)).key_package();
    s.server_adds(key_package);
    let commit = Commit {
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::ServerProposalNotRemove)
    );
}

#[test]
fn too_many_members_is_rejected() {
    let world = World::new(&[1, 1, 1, 1]);
    let mut users = vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)];
    // 20 people in all, most of them without a device yet.
    users.extend((0..17).map(|_| Entry {
        user: new_id(),
        generation: GENERATION,
        epoch: 0,
    }));
    let members = MemberList::new(Kind::Group, Some(world.id(O)), users);
    let mut s = Scene::new(world, members, (O, 0), &[(A, 0)]);
    let ctx = s.world.context();
    let commit = Commit {
        adds: vec![s.world.device((C, 0)).key_package()],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::TooManyMembers)
    );
}

#[test]
fn context_changed_is_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let mut extensions = s.any().public_group().group_context().extensions().clone();
    extensions.remove(ExtensionType::ExternalSenders);
    let commit = Commit {
        extensions: Some(extensions),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::ContextChanged)
    );
}

#[test]
fn pending_removal_dropped_is_rejected() {
    let mut s = Scene::group();
    s.server_removes((A, 0));
    let mut ctx = s.world.context();
    ctx.enforce_pending = true;
    ctx.pending_server_removals = vec![s.leaf((A, 0)).u32()];
    let dropped = Commit {
        leave_out_pending: true,
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((B, 0), dropped, &ctx),
        Err(RuleViolation::PendingRemovalDropped)
    );
    assert_eq!(s.verdict((B, 0), Commit::default(), &ctx), Ok(()));
}

#[test]
fn dm_members_never_change() {
    let world = World::new(&[1, 1, 1]);
    let members = MemberList::new(Kind::Dm, None, vec![world.entry(0, 0), world.entry(1, 0)]);
    let mut s = Scene::new(world, members, (0, 0), &[(1, 0)]);
    let ctx = s.world.context();

    let adding_third = Commit {
        adds: vec![s.world.device((2, 0)).key_package()],
        members: Some(adding(&s.list(), s.id(2), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((0, 0), adding_third, &ctx),
        Err(RuleViolation::MembersChangedByNonOwner)
    );

    let leaving = Commit {
        removes: vec![(1, 0)],
        members: Some(removing(&s.list(), s.id(1))),
        statements: vec![s.statement((1, 0), GENERATION, s.epoch())],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((0, 0), leaving, &ctx),
        Err(RuleViolation::MembersChangedByNonOwner)
    );
}

#[test]
fn legacy_initial_list_must_match() {
    // A conversation from before the cutover: any member makes epoch 0, with the list the API expects.
    let world = World::new(&[1, 1, 1]);
    let expected = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)],
    );
    let mut ctx = world.context();
    ctx.expected_initial = Some(expected.clone());

    let short = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    );
    let (group, _) = world.first_commit((A, 0), &short, &[(O, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::MemberListMismatch)
    );

    let (group, _) = world.first_commit((B, 0), &expected, &[(O, 0), (A, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Ok(()),
        "B isn't the owner, and it's fine"
    );
}

#[test]
fn owner_creates_epoch_zero() {
    let world = World::new(&[1, 1]);
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    );
    let ctx = world.context();

    let (group, _) = world.first_commit((A, 0), &members, &[(O, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::MembersChangedByNonOwner)
    );

    let (group, _) = world.first_commit((O, 0), &members, &[(A, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Ok(())
    );
}

#[test]
fn valid_changes_pass() {
    let mut s = Scene::group();
    let ctx = s.world.context();

    let owner_adds_c = Commit {
        adds: vec![s.world.device((C, 0)).key_package()],
        members: Some(adding(&s.list(), s.id(C), s.epoch() + 1)),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 1), owner_adds_c, &ctx),
        Ok(()),
        "the owner adds C"
    );

    let owner_removes_b = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), s.id(B))),
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), owner_removes_b, &ctx),
        Ok(()),
        "the owner removes B"
    );

    let b_leaves = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), s.id(B))),
        statements: vec![s.statement((B, 0), GENERATION, s.epoch())],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((A, 0), b_leaves, &ctx),
        Ok(()),
        "B leaves, A commits it"
    );

    assert_eq!(
        s.verdict((B, 0), Commit::default(), &ctx),
        Ok(()),
        "B renews its leaf"
    );

    s.server_removes((O, 1));
    assert_eq!(
        s.verdict((A, 0), Commit::default(), &ctx),
        Ok(()),
        "the server removes a device, A commits it"
    );

    let joins = s.external_change((A, 1), (O, 0));
    assert_eq!(
        check_change(&ctx, &joins),
        Ok(()),
        "A's second device, on its list, joins by external commit"
    );
}

#[test]
fn updated_leaf_keeps_its_device() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let Scene { world, groups } = &mut s;
    let b = world.device((B, 0));
    let other = world.device((B, 1)); // on B's list, not in the group
    let group = groups.get_mut(&(B, 0)).unwrap();
    group
        .self_update_with_new_signer(
            &b.provider,
            &b.signer,
            NewSignerBundle {
                signer: &other.signer,
                credential_with_key: other.credential(),
            },
            LeafNodeParameters::default(),
        )
        .unwrap();
    let change = own_change(group, &[]).unwrap();
    assert_eq!(
        check_change(&ctx, &change),
        Err(RuleViolation::LeafNotSigned)
    );
}

/// The certificate of `device`, public as every leaf's, on the key of `signer`: a credential that
/// poses as `device`.
fn posing_as(world: &World, device: (usize, usize), signer: (usize, usize)) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(world.device(device).certificate.clone()).into(),
        signature_key: world.device(signer).signer.public().into(),
    }
}

#[test]
fn forged_creator_is_rejected() {
    // A makes epoch 0 posing as the owner's device, so the first commit looks like the owner's.
    let world = World::new(&[1, 1, 1]);
    let ctx = world.context();
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)],
    );
    let posing = posing_as(&world, (O, 0), (A, 0));
    let (group, bundle) = world.first_commit_as((A, 0), posing, &members, &[(O, 0), (B, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::LeafNotSigned),
        "the first commit"
    );
    let welcome = world.welcomed((B, 0), &bundle);
    assert_eq!(
        state_of(&ctx, welcome.group_context(), welcome.members()),
        Err(RuleViolation::LeafNotSigned),
        "B's welcome"
    );
}

#[test]
fn forged_creator_of_a_dm_is_rejected() {
    // C, outside the DM of O and A, makes its epoch 0 posing as O's device.
    let world = World::new(&[1, 1, 1, 1]);
    let ctx = world.context();
    let members = MemberList::new(Kind::Dm, None, vec![world.entry(O, 0), world.entry(A, 0)]);
    let posing = posing_as(&world, (O, 0), (C, 0));
    let (group, bundle) = world.first_commit_as((C, 0), posing, &members, &[(A, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::LeafNotSigned),
        "the first commit"
    );
    let welcome = world.welcomed((A, 0), &bundle);
    assert_eq!(
        state_of(&ctx, welcome.group_context(), welcome.members()),
        Err(RuleViolation::LeafNotSigned),
        "A's welcome"
    );
}

#[test]
fn starting_leaves_are_members_listed_devices() {
    let world = World::new(&[1, 1, 1]);
    let ctx = world.context();

    // O makes epoch 0 of a group it isn't in.
    let others = MemberList::new(
        Kind::Group,
        Some(world.id(A)),
        vec![world.entry(A, 0), world.entry(B, 0)],
    );
    let (group, _) = world.first_commit((O, 0), &others, &[(A, 0)]);
    let state = state_of(&ctx, group.public_group().group_context(), group.members());
    assert_eq!(
        state,
        Err(RuleViolation::UserNotMember),
        "a creator outside"
    );
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::UserNotMember),
        "a creator outside, by its first commit"
    );

    // A makes epoch 0 from a device its latest list no longer has.
    let members = MemberList::new(Kind::Dm, None, vec![world.entry(A, 0), world.entry(B, 0)]);
    let (group, _) = world.first_commit((A, 0), &members, &[(B, 0)]);
    let mut ctx = world.context();
    let a = world.id(A);
    let without = DeviceList::new(a, public(&world.users[A].identity), 2, vec![]);
    ctx.device_lists.insert(a, without);
    let state = state_of(&ctx, group.public_group().group_context(), group.members());
    assert_eq!(
        state,
        Err(RuleViolation::DeviceNotListed),
        "an unlisted creator"
    );
}

#[test]
fn joined_state_takes_unlisted_devices_not_other_identities() {
    // O adds A and B; A joins by the welcome.
    let world = World::new(&[1, 1, 1]);
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)],
    );
    let (_, bundle) = world.first_commit((O, 0), &members, &[(A, 0), (B, 0)]);
    let joined = world.welcomed((A, 0), &bundle);
    let leaves = leaves(joined.members()).unwrap();
    let context = joined.group_context();
    assert_eq!(
        check_joined_state(&world.context(), context, &leaves),
        Ok(())
    );

    // B's latest list, as A has it, no longer has the device B is in the group with: its removal
    // is on its way, as it is for the members.
    let b = world.id(B);
    let mut ctx = world.context();
    let without = DeviceList::new(b, public(&world.users[B].identity), 2, vec![]);
    ctx.device_lists.insert(b, without);
    assert_eq!(
        check_state(&ctx, context, &leaves),
        Err(RuleViolation::DeviceNotListed)
    );
    assert_eq!(
        check_joined_state(&ctx, context, &leaves),
        Ok(()),
        "a device on its way out"
    );

    // A pinned another identity for B than the one that certified B's leaf.
    let mut ctx = world.context();
    ctx.identities.insert(b, public(&signer()));
    assert_eq!(
        check_joined_state(&ctx, context, &leaves),
        Err(RuleViolation::LeafNotSigned),
        "another identity"
    );

    // And the rest of check_state holds: the list it must be.
    let mut ctx = world.context();
    ctx.expected_initial = Some(MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    ));
    assert_eq!(
        check_joined_state(&ctx, context, &leaves),
        Err(RuleViolation::MemberListMismatch),
        "another list"
    );
}

/// `check_state` on the epoch 0 O makes in a world of O and A, under Duvet's config but for `suite`,
/// the context's extensions `extensions` gives (from the member list's and the API's sender), and
/// leaves that also support `more` extension types.
fn starting_context(
    suite: Ciphersuite,
    more: &[ExtensionType],
    extensions: impl FnOnce(Extension, ExternalSender) -> Vec<Extension>,
) -> Result<(), RuleViolation> {
    let world = World::new(&[1, 1]);
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    );
    let mut types = vec![
        ExtensionType::Unknown(MEMBER_LIST_EXTENSION),
        ExtensionType::LastResort,
    ];
    types.extend_from_slice(more);
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![suite])
        .extensions(types)
        .build();
    let extensions = extensions(members.to_extension(), world.external_sender());
    let config = config_with(suite, extensions, capabilities);
    let credential = world.device((O, 0)).credential();
    let group = world.create((O, 0), credential, &config, GENERATION);
    state_of(
        &world.context(),
        group.public_group().group_context(),
        group.members(),
    )
}

#[test]
fn starting_context_must_be_duvets() {
    // The API's key against the one sender the group names.
    let world = World::new(&[1, 1]);
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    );
    let (group, _) = world.first_commit((O, 0), &members, &[(A, 0)]);
    let change = own_change(&group, &[]).unwrap();
    let with_key = |key: Option<Vec<u8>>| RuleContext {
        external_sender: key,
        ..world.context()
    };
    let stranger_key = Some(signer().public().to_vec());
    let context = group.public_group().group_context();
    let verdicts = [
        ("the API's key", check_change(&world.context(), &change)),
        ("no key to compare", check_change(&with_key(None), &change)),
        (
            "another key",
            check_change(&with_key(stranger_key.clone()), &change),
        ),
        (
            "another key, on the state",
            state_of(&with_key(stranger_key), context, group.members()),
        ),
    ];
    let expected = [
        ("the API's key", Ok(())),
        ("no key to compare", Ok(())),
        ("another key", Err(RuleViolation::ContextChanged)),
        (
            "another key, on the state",
            Err(RuleViolation::ContextChanged),
        ),
    ];
    assert_eq!(verdicts, expected);

    // Contexts Duvet's clients never make.
    let list = ExtensionType::Unknown(MEMBER_LIST_EXTENSION);
    let other = ExtensionType::Unknown(0xF0D2);
    let required = |types: &[ExtensionType]| {
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(types, &[], &[]))
    };
    let stranger = || {
        ExternalSender::new(
            signer().public().into(),
            BasicCredential::new(b"stranger".to_vec()).into(),
        )
    };
    let chacha = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;
    let duvets = |list_ext, api| {
        vec![
            list_ext,
            required(&[list]),
            Extension::ExternalSenders(vec![api]),
        ]
    };
    assert_eq!(starting_context(SUITE, &[], duvets), Ok(()), "Duvet's");
    let verdicts = [
        ("another suite", starting_context(chacha, &[], duvets)),
        (
            "no external sender",
            starting_context(SUITE, &[], |list_ext, _| vec![list_ext, required(&[list])]),
        ),
        (
            "two external senders",
            starting_context(SUITE, &[], |list_ext, api| {
                vec![
                    list_ext,
                    required(&[list]),
                    Extension::ExternalSenders(vec![api, stranger()]),
                ]
            }),
        ),
        (
            "the member list not required",
            starting_context(SUITE, &[], |list_ext, api| {
                vec![
                    list_ext,
                    required(&[]),
                    Extension::ExternalSenders(vec![api]),
                ]
            }),
        ),
        (
            "more required",
            starting_context(SUITE, &[other], |list_ext, api| {
                vec![
                    list_ext,
                    required(&[list, other]),
                    Extension::ExternalSenders(vec![api]),
                ]
            }),
        ),
        (
            "another extension",
            starting_context(SUITE, &[other], |list_ext, api| {
                let mut extensions = duvets(list_ext, api);
                extensions.push(Extension::Unknown(0xF0D2, UnknownExtension(vec![1])));
                extensions
            }),
        ),
    ];
    let refused = verdicts.map(|(case, _)| (case, Err(RuleViolation::ContextChanged)));
    assert_eq!(verdicts, refused);
}

/// A member list made of a world's users.
type ListOf = fn(&World) -> MemberList;

/// The verdicts on the epoch 0 `creator` makes, in a world of O, A, B and C with a device each,
/// with the list `members` gives: `check_state` on it, as the validator's `create` finds it, and
/// `check_change` on its first commit, which adds `joined`.
fn starting(
    creator: (usize, usize),
    joined: &[(usize, usize)],
    members: impl FnOnce(&World) -> MemberList,
) -> (Result<(), RuleViolation>, Result<(), RuleViolation>) {
    let world = World::new(&[1, 1, 1, 1]);
    let ctx = world.context();
    let (group, _) = world.first_commit(creator, &members(&world), joined);
    (
        state_of(&ctx, group.public_group().group_context(), group.members()),
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
    )
}

#[test]
fn starting_list_must_be_well_formed() {
    let mismatch = (
        Err(RuleViolation::MemberListMismatch),
        Err(RuleViolation::MemberListMismatch),
    );
    let lists: [(&str, ListOf); 7] = [
        ("an entry from a later epoch", |w| {
            let a = Entry {
                epoch: 5,
                ..w.entry(A, 0)
            };
            MemberList::new(Kind::Group, Some(w.id(O)), vec![w.entry(O, 0), a])
        }),
        ("an entry from an earlier generation", |w| {
            let a = Entry {
                generation: GENERATION - 1,
                ..w.entry(A, 0)
            };
            MemberList::new(Kind::Group, Some(w.id(O)), vec![w.entry(O, 0), a])
        }),
        ("a user twice", |w| {
            let users = vec![w.entry(O, 0), w.entry(A, 0), w.entry(A, 0)];
            MemberList::new(Kind::Group, Some(w.id(O)), users)
        }),
        ("an owner outside the list", |w| {
            MemberList::new(
                Kind::Group,
                Some(w.id(C)),
                vec![w.entry(O, 0), w.entry(A, 0)],
            )
        }),
        ("a group without an owner", |w| {
            MemberList::new(Kind::Group, None, vec![w.entry(O, 0), w.entry(A, 0)])
        }),
        ("a DM with a third user", |w| {
            let users = vec![w.entry(O, 0), w.entry(A, 0), w.entry(B, 0)];
            MemberList::new(Kind::Dm, None, users)
        }),
        ("a DM with an owner", |w| {
            MemberList::new(Kind::Dm, Some(w.id(O)), vec![w.entry(O, 0), w.entry(A, 0)])
        }),
    ];
    let verdicts = lists.map(|(case, members)| (case, starting((O, 0), &[(A, 0)], members)));
    let refused = verdicts.map(|(case, _)| (case, mismatch));
    assert_eq!(verdicts, refused);

    let crowded = starting((O, 0), &[(A, 0)], |w| {
        let mut users = vec![w.entry(O, 0), w.entry(A, 0)];
        users.extend((0..19).map(|_| Entry {
            user: new_id(),
            generation: GENERATION,
            epoch: 0,
        }));
        MemberList::new(Kind::Group, Some(w.id(O)), users)
    });
    assert_eq!(
        crowded,
        (
            Err(RuleViolation::TooManyMembers),
            Err(RuleViolation::TooManyMembers)
        ),
        "21 users"
    );

    // A welcome brings its list as it is at its epoch: B's entry from later on traps B as well.
    let world = World::new(&[1, 1, 1]);
    let b = Entry {
        epoch: 5,
        ..world.entry(B, 0)
    };
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0), b],
    );
    let (_, bundle) = world.first_commit((O, 0), &members, &[(A, 0), (B, 0)]);
    let welcome = world.welcomed((B, 0), &bundle);
    assert_eq!(
        state_of(&world.context(), welcome.group_context(), welcome.members()),
        Err(RuleViolation::MemberListMismatch),
        "B's welcome"
    );
}

#[test]
fn legacy_creator_moving_itself_first_is_rejected() {
    // B would own the conversation once O left: the owner's successor is the list's first user.
    let world = World::new(&[1, 1, 1]);
    let expected = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0), world.entry(B, 0)],
    );
    let mut ctx = world.context();
    ctx.expected_initial = Some(expected);
    let reordered = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(B, 0), world.entry(O, 0), world.entry(A, 0)],
    );
    let (group, _) = world.first_commit((B, 0), &reordered, &[(O, 0), (A, 0)]);
    assert_eq!(
        check_change(&ctx, &own_change(&group, &[]).unwrap()),
        Err(RuleViolation::MemberListMismatch)
    );
}

#[test]
fn joined_list_keeps_to_the_record() {
    // A device's record of a group from before the cutover, O its owner, and the lists of groups
    // it joins past the founding: every user listed must be the record's, in any order and whatever
    // their entries say, and O, while listed, the owner.
    let (o, a, b, x) = (new_id(), new_id(), new_id(), new_id());
    let list = |kind, owner, users: &[(Uuid, u64)]| {
        let users = users
            .iter()
            .map(|&(user, epoch)| Entry {
                user,
                generation: 0,
                epoch,
            })
            .collect();
        MemberList::new(kind, owner, users)
    };
    let record = list(Kind::Group, Some(o), &[(o, 0), (a, 0), (b, 0)]);
    let keeps = |owner, users: &[(Uuid, u64)]| {
        keeps_record(&list(Kind::Group, Some(owner), users), &record)
    };
    assert!(keeps(o, &[(o, 0), (a, 0), (b, 0)]), "the record");
    assert!(keeps(o, &[(o, 0), (b, 0), (a, 4)]), "A added back");
    assert!(keeps(o, &[(o, 0), (b, 0), (a, 0)]), "in another order");
    assert!(keeps(a, &[(a, 0), (b, 0)]), "O gone, A its successor");
    assert!(
        !keeps(o, &[(o, 0), (a, 0), (b, 0), (x, 2)]),
        "X added later"
    );
    assert!(
        !keeps(o, &[(o, 0), (a, 0), (b, 0), (x, 0)]),
        "X entered first"
    );
    assert!(
        !keeps(a, &[(o, 0), (a, 0), (b, 0)]),
        "A the owner, O listed"
    );
    assert!(
        !keeps(a, &[(a, 0), (b, 0), (o, 5)]),
        "O added back, A still the owner"
    );
    let dm = list(Kind::Dm, None, &[(o, 0), (a, 0)]);
    assert!(!keeps_record(&dm, &record), "a DM");
}

#[test]
fn member_list_rewrites_are_rejected() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let list = s.list();

    let mut reordered = list.clone();
    reordered.users.swap(0, 1);
    let mut moved = list.clone();
    moved.users[2].epoch = u64::MAX;
    let commits = [
        (
            "A puts itself first",
            (A, 0),
            Commit {
                members: Some(reordered),
                ..Commit::default()
            },
        ),
        (
            "A moves B's entry out of any statement's reach",
            (A, 0),
            Commit {
                members: Some(moved),
                ..Commit::default()
            },
        ),
        (
            // C enters at the epoch the commit makes, not the one it starts from.
            "the owner adds C at the wrong epoch",
            (O, 0),
            Commit {
                adds: vec![s.world.device((C, 0)).key_package()],
                members: Some(adding(&list, s.id(C), s.epoch())),
                ..Commit::default()
            },
        ),
    ];
    let verdicts = commits.map(|(case, by, commit)| (case, s.verdict(by, commit, &ctx)));
    let refused = verdicts.map(|(case, _)| (case, Err(RuleViolation::MemberListMismatch)));
    assert_eq!(verdicts, refused);
}

#[test]
fn leaf_removed_without_reason_is_rejected() {
    // A stays in the list, and the server proposed nothing.
    let mut s = Scene::group();
    let ctx = s.world.context();
    let commit = Commit {
        removes: vec![(A, 0)],
        ..Commit::default()
    };
    assert_eq!(
        s.verdict((O, 0), commit, &ctx),
        Err(RuleViolation::LeafRemovedWithoutReason)
    );
}

#[test]
fn a_device_off_its_list_goes_by_any_members_commit() {
    // The owner takes its second device off its list, and the server proposes nothing.
    let mut s = Scene::group();
    let stale = s.world.context();
    let mut ctx = s.world.context();
    let owner = &s.world.users[O];
    let list = DeviceList::new(
        owner.id,
        public(&owner.identity),
        2,
        vec![owner.devices[0].id],
    );
    ctx.device_lists.insert(owner.id, list);
    let removing_it = || Commit {
        removes: vec![(O, 1)],
        ..Commit::default()
    };

    // Any member's commit takes that device's leaf out, another user's as well as its own user's.
    assert_eq!(s.verdict((B, 0), removing_it(), &ctx), Ok(()));
    assert_eq!(s.verdict((O, 0), removing_it(), &ctx), Ok(()));
    // Not while the list the checker holds still has the device.
    assert_eq!(
        s.verdict((B, 0), removing_it(), &stale),
        Err(RuleViolation::LeafRemovedWithoutReason)
    );
}

#[test]
fn leave_with_statement_at_entry_epoch_passes() {
    let mut s = Scene::group();
    let ctx = s.world.context();
    let entry = *s.list().entry(s.id(B)).unwrap();
    let commit = Commit {
        removes: vec![(B, 0)],
        members: Some(removing(&s.list(), s.id(B))),
        statements: vec![s.statement((B, 0), entry.generation, entry.epoch)],
        ..Commit::default()
    };
    assert_eq!(s.verdict((A, 0), commit, &ctx), Ok(()));
}

#[test]
fn extract_change_needs_the_context_the_commit_starts_from() {
    let world = World::new(&[1, 1]);
    let members = MemberList::new(
        Kind::Group,
        Some(world.id(O)),
        vec![world.entry(O, 0), world.entry(A, 0)],
    );
    let (group, _) = world.first_commit((O, 0), &members, &[(A, 0)]);
    let staged = group.pending_commit().unwrap();
    let leaves = leaves(group.members()).unwrap();
    let sender = Sender::Member(group.own_leaf_index());
    let read =
        |before: &GroupContext| extract_change(before, &leaves, staged, &sender, &[]).map(|_| ());
    assert_eq!(read(group.public_group().group_context()), Ok(()));
    assert_eq!(
        read(staged.group_context()),
        Err(RuleViolation::Malformed),
        "the context once the commit is merged"
    );
    let config = group_config(&members, world.external_sender());
    let credential = world.device((O, 0)).credential();
    let other = world.create((O, 0), credential, &config, GENERATION + 1);
    assert_eq!(
        read(other.public_group().group_context()),
        Err(RuleViolation::Malformed),
        "another generation's group at the same epoch"
    );
}

#[test]
fn signed_objects_reject_tampering() {
    let user = User::new(1);
    let identity = public(&user.identity);
    let certificate = user.devices[0].certificate.clone();
    assert_eq!(
        DeviceCertificate::verify(&certificate, &identity).map(|c| c.user),
        Ok(user.id)
    );

    for index in 0..certificate.len() {
        let mut tampered = certificate.clone();
        tampered[index] ^= 0x01;
        assert!(
            DeviceCertificate::verify(&tampered, &identity).is_err(),
            "byte {index} changed"
        );
    }
    // The signature's last byte, and the body's: the signature is the encoding's last 64 bytes,
    // after its key ("sig") and its header.
    for index in [certificate.len() - 1, certificate.len() - 64 - 2 - 4 - 1] {
        let mut tampered = certificate.clone();
        tampered[index] ^= 0x01;
        assert_eq!(
            DeviceCertificate::verify(&tampered, &identity),
            Err(RuleViolation::InvalidSignature)
        );
    }

    let stranger = User::new(0);
    assert_eq!(
        DeviceCertificate::verify(&certificate, &public(&stranger.identity)),
        Err(RuleViolation::InvalidSignature)
    );

    let list = user.list.sign(&user.identity).unwrap();
    assert_eq!(DeviceList::verify(&list, &identity), Ok(user.list.clone()));
    assert_eq!(
        DeviceList::verify(&list, &public(&stranger.identity)),
        Err(RuleViolation::InvalidSignature)
    );
}

#[test]
fn device_list_rollback_is_rejected() {
    let user = User::new(2);
    let identity = public(&user.identity);
    let (first, second) = (user.devices[0].id, user.devices[1].id);
    let v1 = DeviceList::new(user.id, identity, 1, vec![first]);
    let v2 = DeviceList::new(user.id, identity, 2, vec![first, second]);

    assert!(v1.accepts_after(None));
    assert!(v2.accepts_after(Some(&v1)));
    assert!(v2.accepts_after(Some(&v2)), "the same list again");
    assert!(!v1.accepts_after(Some(&v2)), "a lower version");
    let other_v2 = DeviceList::new(user.id, identity, 2, vec![second]);
    assert!(
        !other_v2.accepts_after(Some(&v2)),
        "the same version with other devices"
    );
}
