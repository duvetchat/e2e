//! The rules every commit must keep, checked by the core as it applies a commit and by the API's
//! validator as it accepts one.

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::ProposalType;
use uuid::Uuid;

use crate::{
    Committer, DeviceCertificate, DeviceList, Kind, LeaveStatement, MAX_MEMBERS, MemberList,
    MembershipChange, NewLeaf,
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
    #[error("more than 20 members")]
    TooManyMembers,
    #[error("the commit changes the group's context beyond its members")]
    ContextChanged,
    #[error("a member's commit leaves out a removal the server proposed")]
    PendingRemovalDropped,
    #[error(
        "the new member list isn't the previous one without the users who left and with the new ones at its end"
    )]
    MemberListMismatch,
    #[error("a leaf goes without its user leaving or being removed, or the server removing it")]
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
    /// Each user's latest device list, verified.
    pub device_lists: BTreeMap<Uuid, DeviceList>,
    /// The leaves the server proposed to remove in this epoch.
    pub pending_server_removals: Vec<u32>,
    /// A member's commit must carry each of them (the validator's rule).
    pub enforce_pending: bool,
    /// The list epoch 0 must have, when any member may make it: a conversation from before the cutover.
    pub expected_initial: Option<MemberList>,
}

/// Whether a commit keeps every rule. Checked in this order, so a commit breaking several gets the first.
pub fn check_change(ctx: &RuleContext, change: &MembershipChange) -> Result<(), RuleViolation> {
    use RuleViolation::*;
    let (before, after) = (&change.before, &change.after);

    if change.context_changed || after.kind != before.kind {
        return Err(ContextChanged);
    }
    if after.users.len() > MAX_MEMBERS {
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
        .map(|leaf| certified(ctx, leaf))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, leaf) in &change.updated {
        let certificate = certified(ctx, leaf)?;
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

    if change.epoch == 0 {
        match &ctx.expected_initial {
            Some(expected) if !same_members(before, expected) => return Err(MemberListMismatch),
            Some(_) => {}
            None if before.kind == Kind::Group && before.owner != Some(committer) => {
                return Err(MembersChangedByNonOwner);
            }
            None => {}
        }
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
    let left = left_users(ctx, change)?;
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

    // A leaf goes when its user does, when the server proposes it, or when its own device rejoins
    // (checked above for external commits).
    for removal in &change.removed {
        let leaf = change.leaves.get(&removal.index).ok_or(Malformed)?;
        let cause = removal.by_server
            || removed_users.contains(&leaf.user)
            || matches!(change.committer, Committer::NewMember);
        if !cause {
            return Err(LeafRemovedWithoutReason);
        }
    }
    Ok(())
}

/// A new leaf's certificate, verified: signed by its user's pinned identity, for the leaf's own
/// signature key, and its device on its user's latest list.
fn certified(ctx: &RuleContext, leaf: &NewLeaf) -> Result<DeviceCertificate, RuleViolation> {
    let claimed = DeviceCertificate::read_unverified(&leaf.credential)
        .map_err(|_| RuleViolation::LeafNotSigned)?;
    let identity = ctx
        .identities
        .get(&claimed.user)
        .ok_or(RuleViolation::LeafNotSigned)?;
    let certificate = DeviceCertificate::verify(&leaf.credential, identity)
        .map_err(|_| RuleViolation::LeafNotSigned)?;
    if certificate.signature_key != leaf.signature_key {
        return Err(RuleViolation::LeafNotSigned);
    }
    if !ctx
        .device_lists
        .get(&certificate.user)
        .is_some_and(|list| list.contains(certificate.device))
    {
        return Err(RuleViolation::DeviceNotListed);
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

fn same_members(list: &MemberList, expected: &MemberList) -> bool {
    let users = |list: &MemberList| {
        list.users
            .iter()
            .map(|entry| entry.user)
            .collect::<BTreeSet<_>>()
    };
    list.kind == expected.kind
        && list.owner == expected.owner
        && list.users.len() == expected.users.len()
        && users(list) == users(expected)
}

/// The users the commit's leave statements take out. Any statement that doesn't hold refuses the commit.
fn left_users(
    ctx: &RuleContext,
    change: &MembershipChange,
) -> Result<BTreeSet<Uuid>, RuleViolation> {
    change
        .statements
        .iter()
        .map(|signed| leaving_user(ctx, change, signed).ok_or(RuleViolation::LeaveWithoutStatement))
        .collect()
}

/// The user a statement takes out, when it holds: signed by a device of theirs that has a leaf in
/// the group and is on their latest list, for this conversation, and made at their latest entry or
/// after it (before it, it would come from an earlier membership), and not after now.
fn leaving_user(ctx: &RuleContext, change: &MembershipChange, signed: &[u8]) -> Option<Uuid> {
    let claimed = LeaveStatement::read_unverified(signed).ok()?;
    let leaf = change
        .leaves
        .values()
        .find(|leaf| leaf.user == claimed.user && leaf.device == claimed.device)?;
    let certificate =
        DeviceCertificate::verify(&leaf.certificate, ctx.identities.get(&claimed.user)?).ok()?;
    let statement = LeaveStatement::verify(signed, &certificate).ok()?;
    let listed = ctx
        .device_lists
        .get(&statement.user)
        .is_some_and(|list| list.contains(statement.device));
    let entry = change.before.entry(statement.user)?;
    let made = (statement.generation, statement.epoch);
    let in_time =
        made >= (entry.generation, entry.epoch) && made <= (change.generation, change.epoch);
    (listed && statement.conversation == change.conversation && in_time).then_some(statement.user)
}
