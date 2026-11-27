//! The rules every commit must keep, checked by the core as it applies a commit and by the API's
//! validator as it accepts one, and those a group's state must keep where it enters through no
//! commit: its epoch 0, and the group a device joins by a welcome or an external commit.

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _, VLBytes};
use openmls::prelude::{ExtensionType, ExternalSender, GroupContext, ProposalType};
use uuid::Uuid;

use crate::{
    Committer, DeviceCertificate, DeviceList, Kind, LeaveStatement, Leaves, MAX_MEMBERS,
    MEMBER_LIST_EXTENSION, MemberList, MembershipChange, SUITE, group_id_parts,
    required_capabilities,
};

/// Why a commit is refused: the rule it breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuleViolation {
    #[error("only the owner's devices add or remove other users, and a DM's members never change")]
    MembersChangedByNonOwner,
    #[error("a user is taken out without a valid statement of their leaving")]
    LeaveWithoutStatement,
    #[error("the new owner isn't the first-joined of the users left")]
    OwnerNotSuccessor,
    #[error("a leaf's certificate isn't signed by its user's identity for that leaf's key")]
    LeafNotSigned,
    #[error("a leaf's device isn't on its user's latest device list")]
    DeviceNotListed,
    #[error("a leaf's user isn't a member")]
    UserNotMember,
    #[error("an external commit changes the members")]
    ExternalJoinChangesMembers,
    #[error("the server proposed something other than removing a leaf")]
    ServerProposalNotRemove,
    #[error("a new group of more than 20 members, or someone added past 20")]
    TooManyMembers,
    #[error("the group's context isn't Duvet's, or the commit changes it beyond its members")]
    ContextChanged,
    #[error("a member's commit leaves out a removal the server proposed")]
    PendingRemovalDropped,
    #[error(
        "the member list isn't well formed or the expected one, or isn't the previous one without the users who left and with the new ones at its end"
    )]
    MemberListMismatch,
    #[error(
        "a leaf goes without its user leaving or being removed, the server removing it, or its device leaving its user's list"
    )]
    LeafRemovedWithoutReason,
    #[error("a signature doesn't verify")]
    InvalidSignature,
    #[error("malformed")]
    Malformed,
}

impl RuleViolation {
    /// The rule's name, for the core's `rule_violation` and the validator's errors.
    pub fn name(&self) -> &'static str {
        match self {
            RuleViolation::MembersChangedByNonOwner => "members_changed_by_non_owner",
            RuleViolation::LeaveWithoutStatement => "leave_without_statement",
            RuleViolation::OwnerNotSuccessor => "owner_not_successor",
            RuleViolation::LeafNotSigned => "leaf_not_signed",
            RuleViolation::DeviceNotListed => "device_not_listed",
            RuleViolation::UserNotMember => "user_not_member",
            RuleViolation::ExternalJoinChangesMembers => "external_join_changes_members",
            RuleViolation::ServerProposalNotRemove => "server_proposal_not_remove",
            RuleViolation::TooManyMembers => "too_many_members",
            RuleViolation::ContextChanged => "context_changed",
            RuleViolation::PendingRemovalDropped => "pending_removal_dropped",
            RuleViolation::MemberListMismatch => "member_list_mismatch",
            RuleViolation::LeafRemovedWithoutReason => "leaf_removed_without_reason",
            RuleViolation::InvalidSignature => "invalid_signature",
            RuleViolation::Malformed => "malformed",
        }
    }
}

/// What the rules go by besides the commit.
#[derive(Clone, Debug, Default)]
pub struct RuleContext {
    /// Each user's pinned identity key.
    pub identities: BTreeMap<Uuid, [u8; 32]>,
    /// The identities each user had before the pinned one, as the checker knows them: in
    /// [`check_applied_change`] they certify a leaf whose device is off its user's latest list.
    pub earlier_identities: BTreeMap<Uuid, Vec<[u8; 32]>>,
    /// Each user's latest device list, verified.
    pub device_lists: BTreeMap<Uuid, DeviceList>,
    /// The leaves the server proposed to remove in this epoch.
    pub pending_server_removals: Vec<u32>,
    /// A member's commit must carry each of them (the validator's rule).
    pub enforce_pending: bool,
    /// The list epoch 0 must have, when any member may make it: a conversation from before the cutover.
    pub expected_initial: Option<MemberList>,
    /// A device's record of a conversation from before the cutover, and how the group it joins is
    /// held to it.
    pub record: Option<Record>,
    /// The API's signature key, the group's one external sender; not compared when unknown.
    pub external_sender: Option<Vec<u8>>,
}

/// A device's record of a conversation from before the cutover, as a group it joins is held to it.
#[derive(Clone, Debug)]
pub enum Record {
    /// The group's founding welcome, or any join back to a group the device forgot, which must have
    /// the record's members and owner ([`is_record`]).
    Founding(MemberList),
    /// Any other join, which must keep to the record ([`keeps_record`]).
    Joined(MemberList),
}

/// Whether a commit keeps every rule. Checked in this order, so a commit breaking several gets the
/// first; from epoch 0, the state it starts from comes first, with [`check_state`].
pub fn check_change(ctx: &RuleContext, change: &MembershipChange) -> Result<(), RuleViolation> {
    change_rules(ctx, change, Listing::Required)
}

/// Whether another device's commit, as a member applies it, keeps every rule: what
/// [`check_change`] checks, but a leaf the commit brings, and the device that signed one of its
/// leave statements, needn't be on its user's latest list. Such a leaf passes certified by its
/// user's pinned identity for its own key, or, its device off that list, by an identity the user
/// had before (`earlier_identities`); a listed device's leaf goes by the pinned identity alone, as
/// an earlier one, which a lost device may hold, could vouch for its own key under a listed name.
///
/// The server took the commit against the lists it had then, and the validator holds every leaf to
/// them ([`check_change`]); a member applying it later may hold a newer list, from which the device
/// was taken since, or a new identity of its user. Refusing it then would block the group. The leaf
/// is on its way out: no member that holds the newer list sends while it's in, and its next commit
/// takes it out (the core's `ready_to_send` and `commit_pending`).
///
/// It doesn't tell a commit the server took while the device was listed from one it let in past
/// its validator after. So the core narrows `earlier_identities` to what the group shows (its
/// `check_applied`): an identity the user had before certifies a leaf only while the group still
/// lives in it, that is, it certifies a leaf of theirs there, none of theirs carries the pinned
/// identity's certificate, and the group took out no device of theirs under it. And it asks this
/// only of a commit that brings back no device the group took out (`brings_back_removed`).
/// Whoever holds a device lost to a rotation keeps the identity from before, and gets no device in
/// under it, a new device ID included, where the group shows the rotation. What's left is a group
/// that shows the member nothing of it yet: no leaf of that user renewed under the new identity,
/// and none of theirs taken out under the old one since the member pinned the new one (one taken
/// out before, as a device taken off its list first and the keys changed later, is noted without
/// its identity). An honest late join looks the same there, so it comes in. The server holds that
/// open, not the member: as long as it keeps the user's renewal out of the queue, once per
/// conversation (taking out what came in notes the identity), and until a commit that takes it out
/// enters. Till then that device is its user: its commits count as its user's (an owner's add and
/// remove members, and stay), its edits and deletions of its user's messages apply, what it sends
/// shows as its user's, and a leave statement it signs takes its user out. A device only taken off
/// its list holds the identity its user still has, which signs lists: only a rotation takes that
/// from it.
pub fn check_applied_change(
    ctx: &RuleContext,
    change: &MembershipChange,
) -> Result<(), RuleViolation> {
    change_rules(ctx, change, Listing::NotRequired)
}

fn change_rules(
    ctx: &RuleContext,
    change: &MembershipChange,
    listing: Listing,
) -> Result<(), RuleViolation> {
    use RuleViolation::*;
    let (before, after) = (&change.before, &change.after);

    // Epoch 0 entered through no commit: nothing has checked its context, its list or its leaves,
    // the committer's among them.
    if change.epoch == 0 {
        check_state(ctx, &change.context, &change.leaves)?;
    }

    if change.context_changed || after.kind != before.kind {
        return Err(ContextChanged);
    }
    // No one comes in past 20 people. A conversation from before the cutover may start with more
    // (`check_state`): it keeps them, and takes no one in while it would stay past 20.
    let brings_someone = after.users.iter().any(|entry| !before.contains(entry.user));
    if brings_someone && after.users.len() > MAX_MEMBERS {
        return Err(TooManyMembers);
    }
    if change
        .server_proposals
        .iter()
        .any(|kind| *kind != ProposalType::Remove)
    {
        return Err(ServerProposalNotRemove);
    }

    // Each leaf the commit brings carries its device's certificate, signed by its user's identity
    // for the leaf's own key; a leaf updated in place stays the same device.
    let added = change
        .added
        .iter()
        .map(|leaf| brought(ctx, &leaf.credential, &leaf.signature_key, listing))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, leaf) in &change.updated {
        let certificate = brought(ctx, &leaf.credential, &leaf.signature_key, listing)?;
        let old = change.leaves.get(index).ok_or(Malformed)?;
        if (certificate.user, certificate.device) != (old.user, old.device) {
            return Err(LeafNotSigned);
        }
    }

    check_list(change)?;

    let committer = match &change.committer {
        Committer::Member { leaf, .. } => leaf.user,
        Committer::NewMember => {
            // An external commit brings its joiner's leaf alone, and takes out that device's old leaf at most.
            let [joiner] = added.as_slice() else {
                return Err(ExternalJoinChangesMembers);
            };
            let own_old_leaf = |index: u32| {
                change
                    .leaves
                    .get(&index)
                    .is_some_and(|old| (old.user, old.device) == (joiner.user, joiner.device))
            };
            let same_members = before.users == after.users && before.owner == after.owner;
            if !same_members
                || !change
                    .removed
                    .iter()
                    .all(|removal| own_old_leaf(removal.index))
            {
                return Err(ExternalJoinChangesMembers);
            }
            joiner.user
        }
    };

    // Epoch 0 is the owner's to make, but in a DM or a conversation from before the cutover, whose
    // list `check_state` held to the expected one.
    if change.epoch == 0
        && ctx.expected_initial.is_none()
        && before.kind == Kind::Group
        && before.owner != Some(committer)
    {
        return Err(MembersChangedByNonOwner);
    }

    if ctx.enforce_pending
        && matches!(change.committer, Committer::Member { .. })
        && ctx
            .pending_server_removals
            .iter()
            .any(|index| !change.removed.iter().any(|removal| removal.index == *index))
    {
        return Err(PendingRemovalDropped);
    }

    let removed_users: BTreeSet<Uuid> = before
        .users
        .iter()
        .map(|e| e.user)
        .filter(|u| !after.contains(*u))
        .collect();
    let added_users: BTreeSet<Uuid> = after
        .users
        .iter()
        .map(|e| e.user)
        .filter(|u| !before.contains(*u))
        .collect();

    if before.kind == Kind::Dm
        && (!added_users.is_empty() || !removed_users.is_empty() || after.owner != before.owner)
    {
        return Err(MembersChangedByNonOwner);
    }
    if !added_users.is_empty() && before.owner != Some(committer) {
        return Err(MembersChangedByNonOwner);
    }

    // A user goes with their own statement, or because the owner removes them.
    let left = left_users(ctx, change, listing)?;
    for user in &removed_users {
        let removed_by_owner = before.owner == Some(committer) && before.owner != Some(*user);
        if !left.contains(user) && !removed_by_owner {
            return Err(LeaveWithoutStatement);
        }
    }

    let successor = match before.owner {
        Some(owner) if removed_users.contains(&owner) => {
            after.users.first().map(|entry| entry.user)
        }
        owner => owner,
    };
    if after.owner != successor {
        return Err(OwnerNotSuccessor);
    }

    // Every leaf after the commit is a member's.
    let removed: BTreeSet<u32> = change.removed.iter().map(|removal| removal.index).collect();
    let staying = change
        .leaves
        .iter()
        .filter(|(index, _)| !removed.contains(index))
        .map(|(_, leaf)| leaf.user);
    if staying
        .chain(added.iter().map(|certificate| certificate.user))
        .any(|user| !after.contains(user))
    {
        return Err(UserNotMember);
    }

    // A leaf goes when its user does, when the server proposes it, when its own device rejoins
    // (checked above for external commits), or when its device is off its user's latest list as
    // the checker holds it, by any member's commit: a device taken off its list stops reading what
    // comes next, whether or not the server proposes its removal.
    for removal in &change.removed {
        let leaf = change.leaves.get(&removal.index).ok_or(Malformed)?;
        let unlisted = ctx
            .device_lists
            .get(&leaf.user)
            .is_some_and(|list| !list.contains(leaf.device));
        let cause = removal.by_server
            || removed_users.contains(&leaf.user)
            || matches!(change.committer, Committer::NewMember)
            || unlisted;
        if !cause {
            return Err(LeafRemovedWithoutReason);
        }
    }
    Ok(())
}

/// The users whose latest lists say whether `change` may take out the leaves it removes: those of
/// the leaves a member removes, without the server proposing it, from users who stay. The rules
/// read their lists only for that.
pub fn unlisted_candidates(change: &MembershipChange) -> impl Iterator<Item = Uuid> + '_ {
    change
        .removed
        .iter()
        .filter(|removal| !removal.by_server)
        .filter_map(|removal| change.leaves.get(&removal.index))
        .map(|leaf| leaf.user)
        .filter(|user| change.after.contains(*user))
}

/// Whether a group's state, as a device finds it, is one Duvet makes: Duvet's context, a
/// well-formed member list (exactly `expected_initial`, and held to `record`, when given), and
/// every leaf certified for its own key, its device on its user's latest list, its user a member.
/// Checked in this order. Where a state enters through no commit, this is what checks it:
/// `check_change` from epoch 0 and the validator's `create`.
pub fn check_state(
    ctx: &RuleContext,
    context: &GroupContext,
    leaves: &Leaves,
) -> Result<(), RuleViolation> {
    state(ctx, context, leaves, Listing::Required)
}

/// Whether a group a device enters, by a welcome or by its own external commit, is one Duvet
/// makes: what [`check_state`] checks, but a leaf whose device has left its user's latest list
/// still passes, certified by its user's pinned identity. The members already in the group keep
/// such a leaf too ([`check_change`] certifies only the leaves a commit brings), until the commit
/// of the server's removal proposal, which a device sends no message before. A leaf certified by
/// another identity than its user's pinned one is refused all the same.
pub fn check_joined_state(
    ctx: &RuleContext,
    context: &GroupContext,
    leaves: &Leaves,
) -> Result<(), RuleViolation> {
    state(ctx, context, leaves, Listing::NotRequired)
}

/// Whether a leaf's device must be on its user's latest device list.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Listing {
    Required,
    NotRequired,
}

fn state(
    ctx: &RuleContext,
    context: &GroupContext,
    leaves: &Leaves,
    listing: Listing,
) -> Result<(), RuleViolation> {
    use RuleViolation::*;
    check_context(ctx, context)?;

    let list = MemberList::from_group_context(context)?;
    let (_, generation) = group_id_parts(context.group_id())?;
    // More than 20 people only in a conversation from before the cutover that the expected list or
    // the device's record describes (ruling 38): the list is then that one, or keeps to that
    // record, which holds no one the conversation didn't have.
    let described = ctx.expected_initial.is_some() || ctx.record.is_some();
    if list.users.len() > MAX_MEMBERS && !described {
        return Err(TooManyMembers);
    }
    well_formed(&list, generation, context.epoch().as_u64())?;
    if let Some(expected) = &ctx.expected_initial {
        let users = |list: &MemberList| {
            list.users
                .iter()
                .map(|entry| entry.user)
                .collect::<Vec<_>>()
        };
        if (list.kind, list.owner, users(&list)) != (expected.kind, expected.owner, users(expected))
        {
            return Err(MemberListMismatch);
        }
    }
    let kept = match &ctx.record {
        Some(Record::Founding(record)) => is_record(&list, record),
        Some(Record::Joined(record)) => keeps_record(&list, record),
        None => true,
    };
    if !kept {
        return Err(MemberListMismatch);
    }

    for leaf in leaves.values() {
        let certificate = match listing {
            Listing::Required => certified(ctx, &leaf.certificate, &leaf.signature_key)?,
            Listing::NotRequired => signed_for(ctx, &leaf.certificate, &leaf.signature_key)?,
        };
        // The rules know a leaf by these: they must be its certificate's.
        if (certificate.user, certificate.device) != (leaf.user, leaf.device) {
            return Err(LeafNotSigned);
        }
        if !list.contains(certificate.user) {
            return Err(UserNotMember);
        }
    }
    Ok(())
}

/// The context Duvet's groups have: Duvet's suite, and beside the member list only its
/// requirement of every leaf and the API as the one external sender.
fn check_context(ctx: &RuleContext, context: &GroupContext) -> Result<(), RuleViolation> {
    let extensions = context.extensions();
    let ours = |kind: ExtensionType| {
        matches!(
            kind,
            ExtensionType::RequiredCapabilities | ExtensionType::ExternalSenders
        ) || kind == ExtensionType::Unknown(MEMBER_LIST_EXTENSION)
    };
    let api = match (
        extensions.external_senders().map(Vec::as_slice),
        &ctx.external_sender,
    ) {
        (Some([sender]), Some(key)) => sender_key(sender)? == *key,
        (Some([_]), None) => true,
        _ => false,
    };
    let duvets = context.ciphersuite() == SUITE
        && extensions.required_capabilities() == Some(&required_capabilities())
        && api
        && extensions
            .iter()
            .all(|extension| ours(extension.extension_type()));
    if duvets {
        Ok(())
    } else {
        Err(RuleViolation::ContextChanged)
    }
}

/// Whether `context`'s group has `key` as its one external sender: what a client holds a group it
/// joins to, with the API's key as it was given it. The API is known by its key alone.
pub fn external_sender_is(context: &GroupContext, key: &[u8]) -> bool {
    match context.extensions().external_senders().map(Vec::as_slice) {
        Some([sender]) => sender_key(sender).is_ok_and(|named| named == key),
        _ => false,
    }
}

/// An external sender's signature key: the first field of its encoding, as OpenMLS keeps the
/// accessor to itself.
fn sender_key(sender: &ExternalSender) -> Result<Vec<u8>, RuleViolation> {
    let encoded = sender
        .tls_serialize_detached()
        .map_err(|_| RuleViolation::Malformed)?;
    let key =
        VLBytes::tls_deserialize(&mut encoded.as_slice()).map_err(|_| RuleViolation::Malformed)?;
    Ok(key.as_slice().to_vec())
}

/// Whether `list` is `record`, a device's record of a conversation from before the cutover, as a
/// group the device founds, and a founding welcome it takes, must be: the same kind and owner, and
/// the same users, in any order, as a record keeps none.
pub fn is_record(list: &MemberList, record: &MemberList) -> bool {
    let users = |list: &MemberList| {
        list.users
            .iter()
            .map(|entry| entry.user)
            .collect::<BTreeSet<_>>()
    };
    (list.kind, list.owner) == (record.kind, record.owner) && users(list) == users(record)
}

/// Whether `list`, the member list of a group a device joins past the founding, keeps to `record`,
/// the device's record of the conversation from before the cutover. The list's entries are
/// whatever the last commit's maker wrote, so only its kind and who it lists count. A DM's two
/// users never change: the list is the record ([`is_record`]). In a group, every user listed is the
/// record's, in any order, and the record's owner, while listed, is the owner: a user the owner
/// added since the cutover is refused too, as nothing in the list tells that addition from a
/// planted one.
pub fn keeps_record(list: &MemberList, record: &MemberList) -> bool {
    if record.kind == Kind::Dm {
        return is_record(list, record);
    }
    let owner_kept = record
        .owner
        .filter(|&owner| list.contains(owner))
        .is_none_or(|owner| list.owner == Some(owner));
    list.kind == record.kind
        && list.users.iter().all(|entry| record.contains(entry.user))
        && owner_kept
}

/// A member list as Duvet keeps it: each user once, entered in this generation and by `epoch`; a
/// group's owner among them, and a DM's two users without one.
fn well_formed(list: &MemberList, generation: u32, epoch: u64) -> Result<(), RuleViolation> {
    let users: BTreeSet<Uuid> = list.users.iter().map(|entry| entry.user).collect();
    let entered = list
        .users
        .iter()
        .all(|entry| entry.generation == generation && entry.epoch <= epoch);
    let owned = match list.kind {
        Kind::Group => list.owner.is_some_and(|owner| users.contains(&owner)),
        Kind::Dm => list.owner.is_none() && list.users.len() == 2,
    };
    if users.len() == list.users.len() && entered && owned {
        Ok(())
    } else {
        Err(RuleViolation::MemberListMismatch)
    }
}

/// A leaf's certificate, verified: signed by its user's pinned identity, for the leaf's own
/// signature key, and its device on its user's latest list. What [`check_change`] holds every leaf
/// a commit brings to.
pub fn certified(
    ctx: &RuleContext,
    credential: &[u8],
    signature_key: &[u8],
) -> Result<DeviceCertificate, RuleViolation> {
    let certificate = signed_for(ctx, credential, signature_key)?;
    if !ctx
        .device_lists
        .get(&certificate.user)
        .is_some_and(|list| list.contains(certificate.device))
    {
        return Err(RuleViolation::DeviceNotListed);
    }
    Ok(certificate)
}

/// A leaf a commit brings, verified as `listing` holds it: [`certified`], or [`vouched_for`] when its
/// device needn't be listed.
fn brought(
    ctx: &RuleContext,
    credential: &[u8],
    signature_key: &[u8],
    listing: Listing,
) -> Result<DeviceCertificate, RuleViolation> {
    match listing {
        Listing::Required => certified(ctx, credential, signature_key),
        Listing::NotRequired => vouched_for(ctx, credential, signature_key),
    }
}

/// A leaf's certificate, verified for the leaf's own signature key: signed by its user's pinned
/// identity, or, for a device off its user's latest list, by an identity the user had before.
fn vouched_for(
    ctx: &RuleContext,
    credential: &[u8],
    signature_key: &[u8],
) -> Result<DeviceCertificate, RuleViolation> {
    let pinned = signed_for(ctx, credential, signature_key);
    let Ok(claimed) = DeviceCertificate::read_unverified(credential) else {
        return pinned;
    };
    let listed = ctx
        .device_lists
        .get(&claimed.user)
        .is_some_and(|list| list.contains(claimed.device));
    if pinned.is_ok() || listed {
        return pinned;
    }
    ctx.earlier_identities
        .get(&claimed.user)
        .into_iter()
        .flatten()
        .filter_map(|identity| DeviceCertificate::verify(credential, identity).ok())
        .find(|certificate| certificate.signature_key == signature_key)
        .ok_or(RuleViolation::LeafNotSigned)
}

/// A leaf's certificate, verified: signed by its user's pinned identity, for the leaf's own
/// signature key. What [`check_joined_state`] holds every leaf to.
pub fn signed_for(
    ctx: &RuleContext,
    credential: &[u8],
    signature_key: &[u8],
) -> Result<DeviceCertificate, RuleViolation> {
    let claimed =
        DeviceCertificate::read_unverified(credential).map_err(|_| RuleViolation::LeafNotSigned)?;
    let identity = ctx
        .identities
        .get(&claimed.user)
        .ok_or(RuleViolation::LeafNotSigned)?;
    let certificate = DeviceCertificate::verify(credential, identity)
        .map_err(|_| RuleViolation::LeafNotSigned)?;
    if certificate.signature_key != signature_key {
        return Err(RuleViolation::LeafNotSigned);
    }
    Ok(certificate)
}

/// The list after the commit is the one before without the users taken out, in the same order and
/// with the same entries, and then the users added, entering at the commit's new epoch.
fn check_list(change: &MembershipChange) -> Result<(), RuleViolation> {
    let (before, after) = (&change.before, &change.after);
    let kept: Vec<_> = before
        .users
        .iter()
        .filter(|entry| after.contains(entry.user))
        .collect();
    let (prefix, added) = after.users.split_at(kept.len().min(after.users.len()));
    let unique = after
        .users
        .iter()
        .map(|entry| entry.user)
        .collect::<BTreeSet<_>>()
        .len()
        == after.users.len();
    let kept_in_place = prefix.iter().eq(kept.iter().copied());
    let added_now = added.iter().all(|entry| {
        !before.contains(entry.user)
            && entry.generation == change.generation
            && entry.epoch == change.epoch + 1
    });
    if unique && kept_in_place && added_now {
        Ok(())
    } else {
        Err(RuleViolation::MemberListMismatch)
    }
}

/// The users the commit's leave statements take out. Any statement that doesn't hold refuses the commit.
fn left_users(
    ctx: &RuleContext,
    change: &MembershipChange,
    listing: Listing,
) -> Result<BTreeSet<Uuid>, RuleViolation> {
    let group = Place {
        conversation: change.conversation,
        generation: change.generation,
        epoch: change.epoch,
    };
    change
        .statements
        .iter()
        .map(|signed| {
            statement_holds(ctx, &change.before, &change.leaves, group, signed, listing)
                .ok_or(RuleViolation::LeaveWithoutStatement)
        })
        .collect()
}

/// A group at one of its epochs: the conversation, the generation and the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Place {
    pub conversation: Uuid,
    pub generation: u32,
    pub epoch: u64,
}

/// The user a leave statement takes out of a group at `place`, whose members are `list` and
/// leaves `leaves`, when it holds: signed by a device of theirs that has a leaf in the group and is
/// on their latest list, for this conversation, and made at their latest entry or after it (before
/// it, it would come from an earlier membership), and not after now. A commit's statements are
/// held to it, and the core to keep only the statements a commit can carry.
pub fn statement_user(
    ctx: &RuleContext,
    list: &MemberList,
    leaves: &Leaves,
    place: Place,
    signed: &[u8],
) -> Option<Uuid> {
    statement_holds(ctx, list, leaves, place, signed, Listing::Required)
}

/// [`statement_user`], its signer's device held to its user's latest list as `listing` says: when
/// it needn't be listed, its leaf's certificate holds as [`check_applied_change`] holds a new leaf.
fn statement_holds(
    ctx: &RuleContext,
    list: &MemberList,
    leaves: &Leaves,
    place: Place,
    signed: &[u8],
    listing: Listing,
) -> Option<Uuid> {
    let claimed = LeaveStatement::read_unverified(signed).ok()?;
    let leaf = leaves
        .values()
        .find(|leaf| leaf.user == claimed.user && leaf.device == claimed.device)?;
    let certificate = match listing {
        Listing::Required => {
            DeviceCertificate::verify(&leaf.certificate, ctx.identities.get(&claimed.user)?).ok()?
        }
        Listing::NotRequired => vouched_for(ctx, &leaf.certificate, &leaf.signature_key).ok()?,
    };
    let statement = LeaveStatement::verify(signed, &certificate).ok()?;
    let listed = listing == Listing::NotRequired
        || ctx
            .device_lists
            .get(&statement.user)
            .is_some_and(|list| list.contains(statement.device));
    let entry = list.entry(statement.user)?;
    let made = (statement.generation, statement.epoch);
    let in_time =
        made >= (entry.generation, entry.epoch) && made <= (place.generation, place.epoch);
    (listed && statement.conversation == place.conversation && in_time).then_some(statement.user)
}
