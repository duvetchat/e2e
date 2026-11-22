//! A commit, read as the rules need it: who made it, the member list before and after, and the
//! leaves it adds, updates and removes.

use std::collections::BTreeMap;

use openmls::prelude::{
    BasicCredential, Credential, Extension, ExtensionType, GroupContext, LeafNode, Member,
    Proposal, ProposalType, Sender, StagedCommit,
};
use uuid::Uuid;

use crate::{
    CommitAad, DeviceCertificate, MEMBER_LIST_EXTENSION, MemberList, RuleViolation, group_id_parts,
};

/// A leaf of the group before a commit: its device, as its certificate names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub user: Uuid,
    pub device: Uuid,
    /// The leaf's credential: its device's certificate, signed.
    pub certificate: Vec<u8>,
    pub signature_key: Vec<u8>,
}

/// A group's leaves, by index.
pub type Leaves = BTreeMap<u32, Leaf>;

/// The leaves of a group's members, read from their certificates without verifying them again:
/// each was verified as its leaf entered.
pub fn leaves(members: impl IntoIterator<Item = Member>) -> Result<Leaves, RuleViolation> {
    members
        .into_iter()
        .map(|member| {
            let certificate = basic_identity(&member.credential).ok_or(RuleViolation::Malformed)?;
            let device = DeviceCertificate::read_unverified(&certificate)?;
            let leaf = Leaf {
                user: device.user,
                device: device.device,
                certificate,
                signature_key: member.signature_key,
            };
            Ok((member.index.u32(), leaf))
        })
        .collect()
}

/// Who made a commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Committer {
    /// A member, with the leaf it had before the commit.
    Member { index: u32, leaf: Leaf },
    /// A device joining by external commit; its leaf is the change's one added leaf.
    NewMember,
}

/// A leaf as a commit brings it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewLeaf {
    /// The leaf's basic credential, which should be a signed device certificate; empty for another kind.
    pub credential: Vec<u8>,
    pub signature_key: Vec<u8>,
}

/// A leaf a commit removes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Removed {
    pub index: u32,
    /// The server (the group's external sender) proposed it.
    pub by_server: bool,
}

/// A commit, as the rules read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipChange {
    pub conversation: Uuid,
    pub generation: u32,
    /// The epoch the commit starts from.
    pub epoch: u64,
    pub committer: Committer,
    pub before: MemberList,
    pub after: MemberList,
    /// The group's leaves before the commit.
    pub leaves: Leaves,
    pub added: Vec<NewLeaf>,
    /// Leaves that change in place, by index: the committer's own through its path, and Update proposals.
    pub updated: Vec<(u32, NewLeaf)>,
    pub removed: Vec<Removed>,
    /// The leave statements in the commit's authenticated data, signed.
    pub statements: Vec<Vec<u8>>,
    /// The kinds of the proposals the server made.
    pub server_proposals: Vec<ProposalType>,
    /// The commit changes the context beyond the member list: another extension, or a proposal that
    /// isn't an add, an update, a removal or an external join's own.
    pub context_changed: bool,
}

/// Reads a commit: `before` and `leaves` are the group's as the commit finds it, and `sender` and
/// `aad` the commit message's.
pub fn extract_change(
    before: &GroupContext,
    leaves: &Leaves,
    staged: &StagedCommit,
    sender: &Sender,
    aad: &[u8],
) -> Result<MembershipChange, RuleViolation> {
    let (conversation, generation) = group_id_parts(before.group_id())?;
    let committer = match sender {
        Sender::Member(index) => {
            let leaf = leaves
                .get(&index.u32())
                .cloned()
                .ok_or(RuleViolation::Malformed)?;
            Committer::Member {
                index: index.u32(),
                leaf,
            }
        }
        Sender::NewMemberCommit => Committer::NewMember,
        Sender::External(_) | Sender::NewMemberProposal => return Err(RuleViolation::Malformed),
    };
    let mut change = MembershipChange {
        conversation,
        generation,
        epoch: before.epoch().as_u64(),
        committer,
        before: MemberList::from_group_context(before)?,
        after: MemberList::from_group_context(staged.group_context())?,
        leaves: leaves.clone(),
        added: Vec::new(),
        updated: Vec::new(),
        removed: Vec::new(),
        statements: CommitAad::statements(aad)?,
        server_proposals: Vec::new(),
        context_changed: other_extensions(before) != other_extensions(staged.group_context()),
    };
    for queued in staged.queued_proposals() {
        let by_server = matches!(queued.sender(), Sender::External(_));
        if by_server {
            change
                .server_proposals
                .push(queued.proposal().proposal_type());
        }
        match queued.proposal() {
            Proposal::Add(add) => change.added.push(new_leaf(add.key_package().leaf_node())),
            Proposal::Update(update) => change
                .updated
                .push((member_index(queued.sender())?, new_leaf(update.leaf_node()))),
            Proposal::Remove(remove) => change.removed.push(Removed {
                index: remove.removed().u32(),
                by_server,
            }),
            Proposal::SelfRemove => change.removed.push(Removed {
                index: member_index(queued.sender())?,
                by_server,
            }),
            Proposal::GroupContextExtensions(_) | Proposal::ExternalInit(_) => {}
            _ => change.context_changed = true,
        }
    }
    if let Some(leaf) = staged.update_path_leaf_node() {
        match &change.committer {
            Committer::Member { index, .. } => change.updated.push((*index, new_leaf(leaf))),
            Committer::NewMember => change.added.push(new_leaf(leaf)),
        }
    }
    Ok(change)
}

fn member_index(sender: &Sender) -> Result<u32, RuleViolation> {
    match sender {
        Sender::Member(index) => Ok(index.u32()),
        _ => Err(RuleViolation::Malformed),
    }
}

fn new_leaf(leaf: &LeafNode) -> NewLeaf {
    NewLeaf {
        credential: basic_identity(leaf.credential()).unwrap_or_default(),
        signature_key: leaf.signature_key().as_slice().to_vec(),
    }
}

fn basic_identity(credential: &Credential) -> Option<Vec<u8>> {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|basic| basic.identity().to_vec())
}

/// The context's extensions but the member list.
fn other_extensions(context: &GroupContext) -> Vec<Extension> {
    let members = ExtensionType::Unknown(MEMBER_LIST_EXTENSION);
    context
        .extensions()
        .iter()
        .filter(|extension| extension.extension_type() != members)
        .cloned()
        .collect()
}
