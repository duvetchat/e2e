//! The API's commit validator: a `wasm32-wasip1` module the API runs under wazero.
//!
//! It keeps each conversation's group as the API sees it, the public part of MLS, and refuses the
//! commits that break Duvet's group rules before the API takes them. A [`Request`] goes in and a
//! [`Response`] comes out, both in CBOR: natively through [`validate_bytes`], and in the module
//! through its `alloc`, `dealloc` and `validate` exports.
//!
//! Only epoch 0 builds a group from scratch, which checks every leaf's lifetime. Later requests load
//! the state the previous one left, so a leaf an inactive device never renewed doesn't block them.

mod state;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display};
use std::panic::{AssertUnwindSafe, catch_unwind};

use duvet_e2e_rules::{
    DeviceCertificate, DeviceList, Entry, Kind, LeaveStatement, MemberList, MembershipChange,
    RuleContext, RuleViolation, SUITE, check_change, extract_change, group_id, leaves,
    unlisted_candidates,
};
use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    ExternalProposal, GroupId, LeafNodeIndex, MlsMessageBodyIn, MlsMessageIn,
    OpenMlsSignaturePublicKey, ProcessedMessageContent, Proposal, ProposalStore, ProtocolMessage,
    PublicGroup, Sender, SenderExtensionIndex, SignatureScheme, Verifiable,
};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::{OpenMlsRustCrypto, RustCrypto};
use openmls_traits::signatures::{Signer, SignerError};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

// The codes of the refusals that aren't a rule's: a rule's refusal has the rule's name.
const BAD_REQUEST: &str = "bad_request";
const WRONG_GROUP: &str = "wrong_group";
const INVALID_GROUP_INFO: &str = "invalid_group_info";
const PRIVATE_MESSAGE: &str = "private_message";
const INVALID_COMMIT: &str = "invalid_commit";
const NEEDS_IDENTITIES: &str = "needs_identities";
const GROUP_INFO_MISMATCH: &str = "group_info_mismatch";
const ALREADY_PROPOSED: &str = "already_proposed";
const INTERNAL: &str = "internal";
const TOO_LARGE: &str = "too_large";

/// What the API asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    /// Take a group's epoch 0, from its group info and tree, and its first commit.
    Create,
    /// Take a commit, a member's or an external one, on the state the previous request left.
    Commit,
    /// Sign, as the API, a proposal that removes a leaf, and keep it for the next commit.
    ProposeRemove,
}

/// A request, in CBOR. Each operation reads the fields it names, and nothing else.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub v: u32,
    pub op: Op,
    /// The conversation and the generation whose group the request is about: together, its ID.
    pub conversation: Uuid,
    pub generation: u32,
    /// The state the previous request left: `commit` and `propose_remove`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ByteBuf>,
    /// Epoch 0's group info, with its ratchet tree, as an MLS message: `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_info: Option<ByteBuf>,
    /// The commit, as an MLS message: `create` and `commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<ByteBuf>,
    /// The group info the committer made for the new epoch, as an MLS message, which the API
    /// serves to devices joining by external commit: `create` and `commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_group_info: Option<ByteBuf>,
    /// The conversation's members as the API has them, which epoch 0's list must be: `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub members: Option<Members>,
    /// Identity keys (32 bytes) by user: at least those of the users whose leaves or leave
    /// statements a commit carries, and at epoch 0 of every user with a leaf.
    #[serde(default)]
    pub identities: BTreeMap<Uuid, ByteBuf>,
    /// Each of those users' latest device list, signed.
    #[serde(default)]
    pub device_lists: BTreeMap<Uuid, ByteBuf>,
    /// The API's Ed25519 private key (32 bytes), the group's external sender: `propose_remove`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<ByteBuf>,
    /// The leaf to remove: `propose_remove`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<u32>,
    /// The API's public key (32 bytes), the one external sender epoch 0 may name: `create`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_sender: Option<ByteBuf>,
    /// A conversation from before the cutover, whose epoch 0 any member may make: `create`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub legacy: bool,
}

impl Request {
    /// A request for `op` on the group of `conversation` at `generation`, with no other field.
    pub fn new(op: Op, conversation: Uuid, generation: u32) -> Self {
        Self {
            v: 1,
            op,
            conversation,
            generation,
            state: None,
            group_info: None,
            message: None,
            new_group_info: None,
            members: None,
            identities: BTreeMap::new(),
            device_lists: BTreeMap::new(),
            signer_key: None,
            leaf_index: None,
            external_sender: None,
            legacy: false,
        }
    }
}

/// A conversation's members as the API has them, in the order they entered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Members {
    pub kind: Kind,
    /// A group's owner; a DM has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Uuid>,
    pub users: Vec<Uuid>,
}

/// The answer to a request, in CBOR.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    /// The group's state after the request, for the API to keep and pass with the next one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<ByteBuf>,
    /// The group's epoch after the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    /// The proposal `propose_remove` signed, as an MLS message, for the group's queue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<ByteBuf>,
    /// What the commit changed: `create` and `commit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<Change>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Failure>,
}

/// What a commit changed: the users and devices that entered and left, and the owner after it.
/// For `create`, everyone and everything in the group entered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub users_added: Vec<Uuid>,
    pub users_removed: Vec<Uuid>,
    pub devices_added: Vec<DeviceLeaf>,
    pub devices_removed: Vec<DeviceLeaf>,
    /// The owner after the commit; a DM has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Uuid>,
}

/// A device and its leaf, by whose index the API proposes the device's removal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLeaf {
    pub user: Uuid,
    pub device: Uuid,
    pub leaf: u32,
}

/// Every field but the API's private key, `signer_key`.
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("v", &self.v)
            .field("op", &self.op)
            .field("conversation", &self.conversation)
            .field("generation", &self.generation)
            .field("state", &self.state)
            .field("group_info", &self.group_info)
            .field("message", &self.message)
            .field("new_group_info", &self.new_group_info)
            .field("members", &self.members)
            .field("identities", &self.identities)
            .field("device_lists", &self.device_lists)
            .field("leaf_index", &self.leaf_index)
            .field("external_sender", &self.external_sender)
            .field("legacy", &self.legacy)
            .finish_non_exhaustive()
    }
}

/// Why a request was refused: a code the API decides by, and a message for people.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub code: String,
    pub message: String,
    /// The users `needs_identities` names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<Uuid>,
}

/// The largest request the validator reads, in bytes: 4 MiB. A group of 20 people with 10 devices
/// each starts with a request of about 190 KB, and a commit in it takes one of about 450 KB, its
/// state about 340 KB. The API sizes the module's memory by it.
pub const MAX_REQUEST: usize = 4 << 20;

/// Answers a CBOR request with a CBOR response, a refusal included: nothing fails through it. A
/// request over [`MAX_REQUEST`] is refused before it's read.
pub fn validate_bytes(input: &[u8]) -> Vec<u8> {
    if input.len() > MAX_REQUEST {
        return refused(TOO_LARGE, "the request is over 4 MiB");
    }
    // A panic is caught natively; the module aborts on one, as wasm32 can't unwind.
    let response = match catch_unwind(AssertUnwindSafe(|| handle(input))) {
        Ok(Ok(response)) => response,
        Ok(Err(refusal)) => refusal.into_response(),
        Err(_) => Refusal::new(INTERNAL, "the validator failed").into_response(),
    };
    encode(&response)
        .or_else(|| encode(&Refusal::new(INTERNAL, "the response doesn't encode").into_response()))
        .unwrap_or_default()
}

fn handle(input: &[u8]) -> Result<Response, Refusal> {
    let mut request: Request = decode(input).ok_or_else(|| {
        Refusal::new(
            BAD_REQUEST,
            "the request isn't one CBOR map of the validator's fields",
        )
    })?;
    if request.v != 1 {
        return Err(Refusal::new(BAD_REQUEST, "the request's version isn't 1"));
    }
    let group = group_id(request.conversation, request.generation);
    let response = match request.op {
        Op::Create => create(&request, &group),
        Op::Commit => commit(&request, &group),
        Op::ProposeRemove => propose_remove(&request, &group),
    };
    if let Some(key) = request.signer_key.as_mut() {
        key.zeroize();
    }
    response
}

/// A refusal on its way out.
#[derive(Debug)]
struct Refusal {
    code: &'static str,
    message: String,
    users: Vec<Uuid>,
}

impl Refusal {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            users: Vec::new(),
        }
    }

    fn missing(field: &str) -> Self {
        Self::new(BAD_REQUEST, format!("the request has no {field}"))
    }

    fn internal(error: impl Display) -> Self {
        Self::new(INTERNAL, error.to_string())
    }

    fn into_response(self) -> Response {
        Response {
            ok: false,
            error: Some(Failure {
                code: self.code.to_string(),
                message: self.message,
                users: self.users,
            }),
            ..Response::default()
        }
    }
}

impl From<RuleViolation> for Refusal {
    fn from(violation: RuleViolation) -> Self {
        Self::new(violation.name(), violation.to_string())
    }
}

/// Takes epoch 0, from its group info and tree, and the first commit on it.
fn create(request: &Request, group_id: &GroupId) -> Result<Response, Refusal> {
    let members = request
        .members
        .as_ref()
        .ok_or_else(|| Refusal::missing("members"))?;
    let external_sender = key32(
        field(&request.external_sender, "external_sender")?,
        "external_sender",
    )?;
    let info = group_info(field(&request.group_info, "group_info")?).ok_or_else(|| {
        Refusal::new(
            INVALID_GROUP_INFO,
            "the group info isn't an MLS message with a group info",
        )
    })?;
    if info.group_id() != group_id {
        return Err(Refusal::new(
            WRONG_GROUP,
            "the group info is another conversation's or generation's",
        ));
    }
    if info.epoch().as_u64() != 0 {
        return Err(Refusal::new(
            INVALID_GROUP_INFO,
            "the group info isn't epoch 0's",
        ));
    }
    let tree = info
        .extensions()
        .ratchet_tree()
        .ok_or_else(|| Refusal::new(INVALID_GROUP_INFO, "the group info has no ratchet tree"))?
        .ratchet_tree()
        .clone();
    let crypto = RustCrypto::default();
    let storage = MemoryStorage::default();
    // The one group built from scratch, which checks every leaf, its lifetime included.
    let (group, _) =
        PublicGroup::from_external(&crypto, &storage, tree, info, ProposalStore::new())
            .map_err(|error| Refusal::new(INVALID_GROUP_INFO, error.to_string()))?;

    // Epoch 0's list is the conversation's as the API has it: its kind, its owner, and its users
    // in the order they entered.
    let list = MemberList::from_group_context(group.group_context())?;
    let users: Vec<Uuid> = list.users.iter().map(|entry| entry.user).collect();
    if (list.kind, list.owner, &users) != (members.kind, members.owner, &members.users) {
        return Err(Refusal::new(
            RuleViolation::MemberListMismatch.name(),
            "epoch 0's member list isn't the conversation's",
        ));
    }
    // The rules let any member make a conversation's epoch 0 only when it's from before the cutover.
    let expected_initial = request.legacy.then(|| {
        let entries = members
            .users
            .iter()
            .map(|&user| Entry {
                user,
                generation: request.generation,
                epoch: 0,
            })
            .collect();
        MemberList::new(members.kind, members.owner, entries)
    });
    let rules = Rules {
        expected_initial,
        external_sender: Some(external_sender.to_vec()),
    };
    apply(request, group, storage, &crypto, rules, Snapshot::default())
}

/// Takes a commit on the state the previous request left.
fn commit(request: &Request, group_id: &GroupId) -> Result<Response, Refusal> {
    let storage = state::import(field(&request.state, "state")?)?;
    let group = load(&storage, group_id)?;
    let before = Snapshot::of(&group)?;
    let rules = Rules {
        expected_initial: None,
        external_sender: request.external_sender.as_ref().map(|key| key.to_vec()),
    };
    apply(
        request,
        group,
        storage,
        &RustCrypto::default(),
        rules,
        before,
    )
}

/// Signs, as the API, the proposal that removes a leaf, and keeps it in the group for the next
/// member's commit, which must carry it.
fn propose_remove(request: &Request, group_id: &GroupId) -> Result<Response, Refusal> {
    let storage = state::import(field(&request.state, "state")?)?;
    let mut group = load(&storage, group_id)?;
    let index = request
        .leaf_index
        .ok_or_else(|| Refusal::missing("leaf_index"))?;
    let signer = ApiSigner::new(field(&request.signer_key, "signer_key")?)?;
    let leaf = LeafNodeIndex::new(index);
    if group.leaf(leaf).is_none() {
        return Err(Refusal::new(
            BAD_REQUEST,
            "the group has no leaf at that index",
        ));
    }
    // A commit can't carry two removals of one leaf.
    if server_removals(&group, &storage)?.contains(&index) {
        return Err(Refusal::new(
            ALREADY_PROPOSED,
            "that leaf's removal is already proposed in this epoch",
        ));
    }
    let proposal = ExternalProposal::new_remove::<OpenMlsRustCrypto>(
        leaf,
        group.group_id().clone(),
        group.group_context().epoch(),
        &signer,
        SenderExtensionIndex::new(0),
    )
    .map_err(Refusal::internal)?;
    let message = proposal
        .tls_serialize_detached()
        .map_err(Refusal::internal)?;
    // The group takes it as every member will: signed by its one external sender.
    let incoming = MlsMessageIn::tls_deserialize_exact(&message)
        .map_err(Refusal::internal)?
        .try_into_protocol_message()
        .map_err(Refusal::internal)?;
    let processed = group
        .process_message(&RustCrypto::default(), incoming)
        .map_err(|_| {
            Refusal::new(
                BAD_REQUEST,
                "signer_key doesn't sign as the group's external sender",
            )
        })?;
    let ProcessedMessageContent::ProposalMessage(queued) = processed.into_content() else {
        return Err(Refusal::internal("the proposal didn't read back as one"));
    };
    group
        .add_proposal(&storage, *queued)
        .map_err(Refusal::internal)?;
    Ok(Response {
        ok: true,
        state: Some(ByteBuf::from(state::export(&storage)?)),
        epoch: Some(group.group_context().epoch().as_u64()),
        message: Some(ByteBuf::from(message)),
        ..Response::default()
    })
}

/// What the rules go by for an operation, beyond the commit and the request's users.
struct Rules {
    expected_initial: Option<MemberList>,
    external_sender: Option<Vec<u8>>,
}

/// Processes the request's commit on `group`, holds it to the rules, merges it, and checks the
/// group info its committer made for the new epoch.
fn apply(
    request: &Request,
    mut group: PublicGroup,
    storage: MemoryStorage,
    crypto: &RustCrypto,
    rules: Rules,
    before: Snapshot,
) -> Result<Response, Refusal> {
    let message = commit_message(field(&request.message, "message")?, group.group_id())?;
    let new_group_info = field(&request.new_group_info, "new_group_info")?;
    let pending = server_removals(&group, &storage)?;
    let context = group.group_context().clone();
    let leaves_before = leaves(group.members())?;
    let processed = group
        .process_message(crypto, message)
        .map_err(|error| Refusal::new(INVALID_COMMIT, error.to_string()))?;
    let sender = processed.sender().clone();
    let aad = processed.aad().to_vec();
    let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
        return Err(Refusal::new(INVALID_COMMIT, "the message isn't a commit"));
    };
    let change = extract_change(&context, &leaves_before, &staged, &sender, &aad)?;
    let ctx = rule_context(request, &change, pending, rules)?;
    check_change(&ctx, &change)?;

    // The committer's leaf after the commit, which signs the new group info.
    let committer = match sender {
        Sender::Member(index) => index,
        _ => group
            .ext_commit_sender_index(&staged)
            .map_err(Refusal::internal)?,
    };
    group
        .merge_commit(&storage, *staged)
        .map_err(Refusal::internal)?;
    state::drop_used_proposals(&storage)?;
    check_group_info(new_group_info, &group, committer, crypto)?;
    let after = Snapshot::of(&group)?;
    Ok(Response {
        ok: true,
        state: Some(ByteBuf::from(state::export(&storage)?)),
        epoch: Some(group.group_context().epoch().as_u64()),
        change: Some(before.change_to(&after)),
        ..Response::default()
    })
}

/// The commit as OpenMLS takes it: a public message of this group. Commits travel in the clear so
/// the API can check them.
fn commit_message(bytes: &[u8], group_id: &GroupId) -> Result<ProtocolMessage, Refusal> {
    let invalid = |what: &str| Refusal::new(INVALID_COMMIT, what);
    let message = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| invalid("the message isn't an MLS message"))?
        .try_into_protocol_message()
        .map_err(|_| invalid("the message isn't a group's message"))?;
    if matches!(message, ProtocolMessage::PrivateMessage(_)) {
        return Err(Refusal::new(
            PRIVATE_MESSAGE,
            "the message is a private message; commits go as public messages",
        ));
    }
    if message.group_id() != group_id {
        return Err(Refusal::new(
            WRONG_GROUP,
            "the commit is another conversation's or generation's",
        ));
    }
    Ok(message)
}

/// The group the state holds under `group_id`.
fn load(storage: &MemoryStorage, group_id: &GroupId) -> Result<PublicGroup, Refusal> {
    PublicGroup::load(storage, group_id)
        .map_err(|_| Refusal::new(BAD_REQUEST, "the state isn't one the validator made"))?
        .ok_or_else(|| {
            Refusal::new(
                BAD_REQUEST,
                "the state doesn't hold this conversation's group at this generation",
            )
        })
}

/// The leaves the API proposed to remove in the group's epoch.
fn server_removals(group: &PublicGroup, storage: &MemoryStorage) -> Result<Vec<u32>, Refusal> {
    let queued = group.queued_proposals(storage).map_err(Refusal::internal)?;
    Ok(queued
        .iter()
        .filter(|(_, proposal)| matches!(proposal.sender(), Sender::External(_)))
        .filter_map(|(_, proposal)| match proposal.proposal() {
            Proposal::Remove(remove) => Some(remove.removed().u32()),
            _ => None,
        })
        .collect())
}

/// What the rules go by for `change`: the request's identities, the device lists of the users the
/// change needs (verified), and the API's pending removals, which a member's commit must carry.
fn rule_context(
    request: &Request,
    change: &MembershipChange,
    pending: Vec<u32>,
    rules: Rules,
) -> Result<RuleContext, Refusal> {
    let identities = request
        .identities
        .iter()
        .map(|(user, key)| Ok((*user, key32(key, "an identity key")?)))
        .collect::<Result<BTreeMap<_, _>, Refusal>>()?;
    let needed = needed_users(change);
    let missing: Vec<Uuid> = needed
        .iter()
        .filter(|user| !identities.contains_key(user) || !request.device_lists.contains_key(user))
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(Refusal {
            users: missing,
            ..Refusal::new(
                NEEDS_IDENTITIES,
                "the commit needs these users' identity keys and device lists",
            )
        });
    }
    let mut device_lists = BTreeMap::new();
    for user in needed {
        let (Some(identity), Some(signed)) =
            (identities.get(&user), request.device_lists.get(&user))
        else {
            continue;
        };
        let list = DeviceList::verify(signed, identity)?;
        if list.user != user {
            return Err(Refusal::new(
                BAD_REQUEST,
                format!("the device list given for {user} is another user's"),
            ));
        }
        device_lists.insert(user, list);
    }
    Ok(RuleContext {
        identities,
        // Every leaf goes by the identity the server serves now: earlier ones are a device's
        // knowledge, for the commits it applies late.
        earlier_identities: BTreeMap::new(),
        device_lists,
        pending_server_removals: pending,
        enforce_pending: true,
        expected_initial: rules.expected_initial,
        // A record is a client's, of what its person saw before the cutover.
        record: None,
        external_sender: rules.external_sender,
    })
}

/// The users whose identity and device list the rules read for `change`: those of the leaves it
/// brings, of its members' leave statements and of the leaves a member removes from users who stay
/// ([`unlisted_candidates`]), and at epoch 0 those of every leaf it starts from.
fn needed_users(change: &MembershipChange) -> BTreeSet<Uuid> {
    let brought = change
        .added
        .iter()
        .chain(change.updated.iter().map(|(_, leaf)| leaf));
    // Read without verifying, only to learn whose identity verifies them: the rules refuse one
    // that can't be read.
    let mut users: BTreeSet<Uuid> = brought
        .filter_map(|leaf| DeviceCertificate::read_unverified(&leaf.credential).ok())
        .map(|certificate| certificate.user)
        .collect();
    users.extend(
        change
            .statements
            .iter()
            .filter_map(|statement| LeaveStatement::read_unverified(statement).ok())
            .map(|statement| statement.user)
            .filter(|user| change.before.contains(*user)),
    );
    users.extend(unlisted_candidates(change));
    if change.epoch == 0 {
        users.extend(change.leaves.values().map(|leaf| leaf.user));
    }
    users
}

/// The new group info must be the group's after the commit, as its committer made it: devices
/// joining by external commit build the group from it.
fn check_group_info(
    bytes: &[u8],
    group: &PublicGroup,
    committer: LeafNodeIndex,
    crypto: &RustCrypto,
) -> Result<(), Refusal> {
    let mismatch = |what: &str| Refusal::new(GROUP_INFO_MISMATCH, what);
    let info = group_info(bytes)
        .ok_or_else(|| mismatch("the new group info isn't an MLS message with a group info"))?;

    // What a group info signs is its context, its extensions, its confirmation tag and its signer,
    // in that order (RFC 9420, 12.4.3): the first, third and fourth must be the group's and the
    // committer's.
    let mut expected = group
        .group_context()
        .tls_serialize_detached()
        .map_err(Refusal::internal)?;
    expected.extend(
        info.extensions()
            .tls_serialize_detached()
            .map_err(Refusal::internal)?,
    );
    expected.extend(
        group
            .confirmation_tag()
            .tls_serialize_detached()
            .map_err(Refusal::internal)?,
    );
    expected.extend(committer.u32().to_be_bytes());
    if info.unsigned_payload().map_err(Refusal::internal)? != expected {
        return Err(mismatch(
            "the new group info isn't the group's after the commit, from its committer",
        ));
    }

    // The tree a joining device builds the group from, and the epoch's key for its external commit.
    let tree = info
        .extensions()
        .ratchet_tree()
        .ok_or_else(|| mismatch("the new group info has no ratchet tree"))?
        .ratchet_tree()
        .tls_serialize_detached()
        .map_err(Refusal::internal)?;
    let own_tree = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(Refusal::internal)?;
    if tree != own_tree {
        return Err(mismatch("the new group info's tree isn't the group's"));
    }
    if info.extensions().external_pub().is_none() {
        return Err(mismatch("the new group info has no external public key"));
    }

    let leaf = group
        .leaf(committer)
        .ok_or_else(|| Refusal::internal("the committer has no leaf"))?;
    let key = OpenMlsSignaturePublicKey::from_signature_key(
        leaf.signature_key().clone(),
        SUITE.signature_algorithm(),
    );
    info.verify(crypto, &key)
        .map_err(|_| mismatch("the new group info isn't signed by the committer"))?;
    Ok(())
}

fn group_info(bytes: &[u8]) -> Option<VerifiableGroupInfo> {
    match MlsMessageIn::tls_deserialize_exact(bytes).ok()?.extract() {
        MlsMessageBodyIn::GroupInfo(info) => Some(info),
        _ => None,
    }
}

/// Who's in a group: its users and owner, by its member list, and its devices, by their leaves.
#[derive(Default)]
struct Snapshot {
    users: Vec<Uuid>,
    owner: Option<Uuid>,
    devices: Vec<DeviceLeaf>,
}

impl Snapshot {
    fn of(group: &PublicGroup) -> Result<Self, Refusal> {
        let list = MemberList::from_group_context(group.group_context())?;
        let devices = leaves(group.members())?
            .into_iter()
            .map(|(leaf, device)| DeviceLeaf {
                user: device.user,
                device: device.device,
                leaf,
            })
            .collect();
        Ok(Self {
            users: list.users.iter().map(|entry| entry.user).collect(),
            owner: list.owner,
            devices,
        })
    }

    fn change_to(&self, after: &Snapshot) -> Change {
        Change {
            users_added: after
                .users
                .iter()
                .filter(|user| !self.users.contains(user))
                .copied()
                .collect(),
            users_removed: self
                .users
                .iter()
                .filter(|user| !after.users.contains(user))
                .copied()
                .collect(),
            devices_added: after
                .devices
                .iter()
                .filter(|leaf| !self.devices.contains(leaf))
                .copied()
                .collect(),
            devices_removed: self
                .devices
                .iter()
                .filter(|leaf| !after.devices.contains(leaf))
                .copied()
                .collect(),
            owner: after.owner,
        }
    }
}

/// The API's key, signing as the group's external sender.
struct ApiSigner(ed25519_dalek::SigningKey);

impl ApiSigner {
    fn new(key: &[u8]) -> Result<Self, Refusal> {
        let seed = Zeroizing::new(key32(key, "signer_key")?);
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&seed)))
    }
}

impl Signer for ApiSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(ed25519_dalek::Signer::sign(&self.0, payload)
            .to_bytes()
            .to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn field<'a>(value: &'a Option<ByteBuf>, name: &str) -> Result<&'a [u8], Refusal> {
    value
        .as_deref()
        .map(Vec::as_slice)
        .ok_or_else(|| Refusal::missing(name))
}

fn key32(bytes: &[u8], what: &str) -> Result<[u8; 32], Refusal> {
    bytes
        .try_into()
        .map_err(|_| Refusal::new(BAD_REQUEST, format!("{what} isn't 32 bytes")))
}

/// Exactly one CBOR value, nested `CBOR_DEPTH` levels at most: anything after it, like anything
/// that isn't one, is `None`.
fn decode<T: DeserializeOwned>(mut bytes: &[u8]) -> Option<T> {
    let value =
        ciborium::de::from_reader_with_recursion_limit(&mut bytes, duvet_e2e_rules::CBOR_DEPTH)
            .ok()?;
    bytes.is_empty().then_some(value)
}

/// A refusal, as `validate_bytes` answers one.
fn refused(code: &'static str, message: &str) -> Vec<u8> {
    encode(&Refusal::new(code, message).into_response()).unwrap_or_default()
}

fn encode(value: &impl Serialize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).ok()?;
    Some(out)
}

/// The module's exports, which the API calls through wazero. Addresses are wasm32's, 32 bits.
#[cfg(target_arch = "wasm32")]
mod exports {
    use std::alloc::{Layout, alloc as allocate, dealloc as deallocate};

    /// Allocates `len` bytes for the host to write a request into: their address, or 0 when
    /// there's no room, as for a request over `MAX_REQUEST`, which `validate` would refuse.
    #[unsafe(no_mangle)]
    pub extern "C" fn alloc(len: u32) -> u32 {
        if len == 0 {
            // An empty buffer takes no memory, only an address that isn't 0.
            return 1;
        }
        if len as usize > super::MAX_REQUEST {
            return 0;
        }
        match Layout::array::<u8>(len as usize) {
            // SAFETY: the layout isn't empty.
            Ok(layout) => unsafe { allocate(layout) as usize as u32 },
            Err(_) => 0,
        }
    }

    /// Frees a buffer `alloc` or `validate` handed out.
    ///
    /// # Safety
    ///
    /// `ptr` and `len` are such a buffer's, not freed yet.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn dealloc(ptr: u32, len: u32) {
        if ptr == 0 || len == 0 {
            return;
        }
        if let Ok(layout) = Layout::array::<u8>(len as usize) {
            // SAFETY: the caller hands back a buffer of this layout, from `alloc` or `validate`.
            unsafe { deallocate(ptr as usize as *mut u8, layout) }
        }
    }

    /// Answers the request the host wrote at `ptr`. The response is at `(ptr << 32) | len`, for
    /// the host to free with `dealloc`; the request stays the host's to free.
    ///
    /// # Safety
    ///
    /// `ptr` and `len` are a buffer from `alloc` holding the request.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn validate(ptr: u32, len: u32) -> u64 {
        let response = if len as usize > super::MAX_REQUEST {
            // Refused unread, as `validate_bytes` refuses it.
            super::refused(super::TOO_LARGE, "the request is over 4 MiB")
        } else if len == 0 {
            super::validate_bytes(&[])
        } else if ptr == 0 {
            // No buffer is at address 0: a slice from it would be undefined behaviour.
            super::refused(super::BAD_REQUEST, "the request is at address 0")
        } else {
            // SAFETY: the caller hands a buffer of `len` bytes at `ptr`, which isn't 0.
            let request =
                unsafe { std::slice::from_raw_parts(ptr as usize as *const u8, len as usize) };
            super::validate_bytes(request)
        }
        .into_boxed_slice();
        let len = response.len() as u64;
        let ptr = Box::into_raw(response) as *mut u8 as usize as u64;
        (ptr << 32) | len
    }
}
