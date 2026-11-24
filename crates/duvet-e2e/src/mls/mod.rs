//! Conversations' MLS groups: the commands that make and change them, and `apply`, which takes
//! each conversation's queue from the server in order.
//!
//! No group stays in memory between commands: each command loads the one it needs, and what it
//! changes goes into its transaction. A commit this device makes waits for `commit_result`, the
//! server's word on it: taken, it's merged; refused, a new group's goes, and a member's commit
//! waits for the queue to say which commit took its epoch. Every commit, this device's and the
//! others', is held to the group rules before it's merged.

pub(crate) mod apply;
mod commits;
mod create;
mod members;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;

use duvet_e2e_rules::{
    CommitAad, Committer, DeviceCertificate, Entry, Kind, LeaveStatement, Leaves,
    MEMBER_LIST_EXTENSION, MemberList, MembershipChange, Place, RuleContext, RuleViolation, SUITE,
    certified, check_applied_change, check_change, extract_change, group_id, leaves, signed_for,
    statement_user, unlisted_candidates,
};
use openmls::prelude::tls_codec::{DeserializeBytes as _, Serialize as _};
use openmls::prelude::{
    BasicCredential, ExtensionType, KeyPackage, KeyPackageIn, LeafNodeIndex, LeafNodeParameters,
    Lifetime, MlsGroup, MlsMessageOut, OpenMlsProvider, Proposal, ProtocolVersion, Sender,
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::identity::{from_cbor, not_found, renewed_at, to_cbor};
use crate::protocol::b64;
use crate::{Error, OwnDevice, SqlStorageError, Tx};

pub(crate) use apply::{ApplyRequest, apply};
pub(crate) use commits::{
    CommitResult, JoinExternal, commit_pending, commit_result, group, join_external, refresh,
    refresh_due,
};
pub(crate) use create::{CreateGroup, ResetGroup, create_group, reset_group};
pub(crate) use members::{AddMembers, RemoveMembers, add_members, leave, remove_members};

/// A leaf is renewed by a commit with a path once this long passed since it was last new.
const REFRESH_AFTER_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// What a blocked group answers to the commands that would commit in it: only a reset, the
/// owner's, takes it on.
const GROUP_BLOCKED: &str = "group_blocked";

/// A command about one conversation, and nothing else.
#[derive(Debug, Deserialize)]
pub(crate) struct ConversationId {
    pub(crate) conversation_id: Uuid,
}

/// This device's commit waiting for `commit_result`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pending {
    /// Epoch 0 of a new conversation's group, and its first commit.
    Create,
    /// Epoch 0 of the conversation's next generation, and its first commit: the current
    /// generation's group stays until the server takes it.
    Reset,
    /// A commit in the current group.
    Commit,
    /// The external commit this device joined the current group with, merged already.
    External,
}

impl Pending {
    fn name(self) -> &'static str {
        match self {
            Pending::Create => "create",
            Pending::Reset => "reset",
            Pending::Commit => "commit",
            Pending::External => "external",
        }
    }

    fn from_name(name: &str) -> Result<Pending, Error> {
        match name {
            "create" => Ok(Pending::Create),
            "reset" => Ok(Pending::Reset),
            "commit" => Ok(Pending::Commit),
            "external" => Ok(Pending::External),
            _ => Err(malformed_row()),
        }
    }
}

/// A conversation as this device keeps it: the generation it's at, the last entry of the queue it
/// applied, the members as its group last had them, and whether a commit that broke the rules
/// blocked it.
#[derive(Clone, Debug)]
pub struct GroupRow {
    pub conversation: Uuid,
    pub generation: u32,
    /// The last entry of the queue applied; none until one took effect.
    pub last_seq: Option<u64>,
    /// The latest epoch of `generation` this device held, or saw a commit take the group to: a
    /// welcome to it or an earlier one is an old one, again.
    pub epoch: u64,
    pub members: MemberList,
    pub blocked: bool,
    /// When this device's leaf in the group was last new, in Unix milliseconds.
    pub leaf_updated_at: i64,
    pub(crate) pending: Option<Pending>,
    /// The SHA-256 of this device's last commit, to know it when the queue brings it back.
    pub(crate) echo: Option<Vec<u8>>,
    /// The leave statements this epoch's removal proposals brought, for the commit that takes
    /// their users out.
    pub(crate) statements: Vec<Vec<u8>>,
}

impl GroupRow {
    pub(crate) fn read(tx: &Tx<'_>, conversation: Uuid) -> Result<Option<GroupRow>, Error> {
        type Columns = (
            i64,
            Option<i64>,
            i64,
            Vec<u8>,
            bool,
            i64,
            Option<String>,
            Option<Vec<u8>>,
            Option<Vec<u8>>,
        );
        let columns: Option<Columns> = tx
            .conn()
            .query_row(
                "SELECT generation, last_seq, epoch, members, blocked, leaf_updated_at, pending, \
                 echo, statements FROM groups WHERE conversation_id = ?1",
                [conversation.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            generation,
            last_seq,
            epoch,
            members,
            blocked,
            leaf_updated_at,
            pending,
            echo,
            statements,
        )) = columns
        else {
            return Ok(None);
        };
        let statements = match statements {
            Some(bytes) => from_cbor::<Vec<ByteBuf>>(&bytes)
                .ok_or_else(malformed_row)?
                .into_iter()
                .map(ByteBuf::into_vec)
                .collect(),
            None => Vec::new(),
        };
        Ok(Some(GroupRow {
            conversation,
            generation: u32::try_from(generation).map_err(|_| malformed_row())?,
            last_seq: last_seq
                .map(|seq| u64::try_from(seq).map_err(|_| malformed_row()))
                .transpose()?,
            epoch: u64::try_from(epoch).map_err(|_| malformed_row())?,
            members: from_cbor(&members).ok_or_else(malformed_row)?,
            blocked,
            leaf_updated_at,
            pending: pending.as_deref().map(Pending::from_name).transpose()?,
            echo,
            statements,
        }))
    }

    pub(crate) fn write(&self, tx: &Tx<'_>) -> Result<(), Error> {
        let kind = match self.members.kind {
            Kind::Dm => "dm",
            Kind::Group => "group",
        };
        let last_seq = self
            .last_seq
            .map(|seq| i64::try_from(seq).map_err(|_| malformed_row()))
            .transpose()?;
        let epoch = i64::try_from(self.epoch).map_err(|_| malformed_row())?;
        let statements = if self.statements.is_empty() {
            None
        } else {
            let statements: Vec<ByteBuf> = self
                .statements
                .iter()
                .map(|statement| ByteBuf::from(statement.clone()))
                .collect();
            Some(to_cbor(&statements)?)
        };
        tx.conn().execute(
            "INSERT INTO groups (conversation_id, generation, last_seq, epoch, members, owner, \
             kind, blocked, leaf_updated_at, pending, echo, statements) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
             ON CONFLICT (conversation_id) DO UPDATE SET generation = excluded.generation, \
             last_seq = excluded.last_seq, epoch = excluded.epoch, members = excluded.members, \
             owner = excluded.owner, kind = excluded.kind, blocked = excluded.blocked, \
             leaf_updated_at = excluded.leaf_updated_at, pending = excluded.pending, \
             echo = excluded.echo, statements = excluded.statements",
            params![
                self.conversation.as_bytes().as_slice(),
                self.generation,
                last_seq,
                epoch,
                to_cbor(&self.members)?,
                self.members.owner.map(|owner| owner.as_bytes().to_vec()),
                kind,
                self.blocked,
                self.leaf_updated_at,
                self.pending.map(Pending::name),
                self.echo,
                statements,
            ],
        )?;
        Ok(())
    }

    pub(crate) fn delete(tx: &Tx<'_>, conversation: Uuid) -> Result<(), Error> {
        tx.conn().execute(
            "DELETE FROM groups WHERE conversation_id = ?1",
            [conversation.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// This device's commit, staged: it waits for `commit_result`, and the queue may bring it back.
    fn staged(&mut self, pending: Pending, staged: &Staged) {
        self.pending = Some(pending);
        self.echo = Some(digest(&staged.commit));
    }
}

/// The group this device holds of `conversation`, at the generation its row names, with that
/// row. `not_found` names a `group` when the device knows nothing of the conversation, and its
/// `membership` when the device isn't in its group (it left, it was removed, it hasn't joined).
pub fn load_group(tx: &Tx<'_>, conversation: Uuid) -> Result<(MlsGroup, GroupRow), Error> {
    let row = GroupRow::read(tx, conversation)?.ok_or_else(|| not_found("group"))?;
    let group =
        stored_group(tx, conversation, row.generation)?.ok_or_else(|| not_found("membership"))?;
    Ok((group, row))
}

/// Whether this device may send a message in `conversation` now, which `encrypt` asks before it
/// encrypts. What stops it from committing stops it from sending: its own commit waiting for
/// `commit_result` or the queue (`pending_commit`), a blocked group (`rule_violation`,
/// `group_blocked`), and its own removal proposed (`not_found`, `membership`). Beyond those, a
/// removal the server proposed waits for its commit first, `pending_proposals`, and so does any
/// member's leaf whose device is off its user's latest list as this device knows it, whose removal
/// the server may never propose: then `commit_pending` makes them, so no message reaches a device
/// on its way out.
pub fn ready_to_send(tx: &Tx<'_>, conversation: Uuid) -> Result<(), Error> {
    let (group, row) = load_group(tx, conversation)?;
    can_commit(&group, &row)?;
    if group.has_pending_proposals() {
        return Err(Error::PendingProposals);
    }
    let unlisted = unlisted_leaves(tx, &group)?;
    if !unlisted.is_empty() {
        ask_about_lists(tx, &unlisted)?;
        return Err(Error::PendingProposals);
    }
    Ok(())
}

/// The ask's key before this device takes out leaves whose devices are off their users' lists: one
/// for every group, as what it checks, each user's latest list, is the same everywhere.
const LISTS_ASK: &[u8] = b"devices off their users' lists";

/// Before this device takes out the `unlisted` leaves: `needs_identities` for their users, once per
/// state of what this device knows of each, as a device of theirs may have been set up since this
/// device last saw their list. `Ok` once the client observed each of them at what it knows now.
fn ask_about_lists(tx: &Tx<'_>, unlisted: &[(LeafNodeIndex, Uuid)]) -> Result<(), Error> {
    ask_first(
        tx,
        LISTS_ASK,
        unlisted.iter().map(|(_, user)| *user).collect(),
    )
}

/// The leaves in `group` whose devices are off their users' latest lists as this device holds them
/// (removed from them, or left out of a rotation or a reset), this device's own aside, each with
/// its user. A user whose list this device doesn't hold has none here. A leaf is off a list
/// this device holds because its user took its device off, or because this device holds a list older
/// than the leaf: a welcome holds leaves to their user's identity alone, so a device that joined by
/// one may never have seen the list that brought a leaf. So `pending_proposals` asks first
/// (`ask_about_lists`): once the client observes the user, a leaf on their newer list stays.
fn unlisted_leaves(tx: &Tx<'_>, group: &MlsGroup) -> Result<Vec<(LeafNodeIndex, Uuid)>, Error> {
    let own = group.own_leaf_index().u32();
    let mut lists = BTreeMap::new();
    let mut unlisted = Vec::new();
    for (index, leaf) in leaves(group.members()).map_err(|_| stored_state())? {
        if index == own {
            continue;
        }
        let list = match lists.entry(leaf.user) {
            std::collections::btree_map::Entry::Occupied(known) => known.into_mut(),
            std::collections::btree_map::Entry::Vacant(unknown) => {
                unknown.insert(tx.device_list_of(leaf.user)?)
            }
        };
        let off = list
            .as_ref()
            .is_some_and(|list| !list.contains(leaf.device));
        if off {
            unlisted.push((LeafNodeIndex::new(index), leaf.user));
        }
    }
    Ok(unlisted)
}

/// Whether this device can commit in its group now: not while its own commit waits for
/// `commit_result`, or for the queue once the server answered it as refused (`pending_commit`), nor
/// in a blocked group (`rule_violation`, `group_blocked`), nor once the server proposed removing
/// this device's own leaf (`not_found`, `membership`). That device is on its way out: OpenMLS
/// refuses a commit that removes its own committer, and the validator a member's commit that leaves
/// a pending removal out, so it waits for another member's.
pub(crate) fn can_commit(group: &MlsGroup, row: &GroupRow) -> Result<(), Error> {
    if row.pending.is_some() || group.pending_commit().is_some() {
        return Err(Error::PendingCommit);
    }
    if row.blocked {
        return Err(Error::RuleViolation {
            rule: GROUP_BLOCKED.into(),
        });
    }
    let own = group.own_leaf_index();
    let leaving = group.pending_proposals().any(
        |queued| matches!(queued.proposal(), Proposal::Remove(remove) if remove.removed() == own),
    );
    if leaving {
        return Err(not_found("membership"));
    }
    Ok(())
}

/// The row once this device's own commit is merged: the members and epoch its group has now, no
/// statement left to carry, and its leaf new, as every commit of this device's renews it (but one
/// made before the identity changed, whose leaf is due at once: `renewed_at`).
pub(crate) fn own_merged(tx: &Tx<'_>, row: &mut GroupRow, group: &MlsGroup) -> Result<(), Error> {
    row.members = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    row.epoch = group.epoch().as_u64();
    row.statements.clear();
    row.leaf_updated_at = renewed_at(tx, group)?;
    Ok(())
}

/// Merges this device's waiting commit in `group`: what it took out is noted ([`note_removed`]),
/// and the row follows ([`own_merged`]).
pub(crate) fn merge_own(
    tx: &Tx<'_>,
    row: &mut GroupRow,
    group: &mut MlsGroup,
) -> Result<(), Error> {
    let before = leaves(group.members()).map_err(|_| stored_state())?;
    group
        .merge_pending_commit(tx.provider())
        .map_err(openmls_error)?;
    note_removed(tx, row.conversation, &before, group)?;
    own_merged(tx, row, group)
}

/// Notes the devices of `before`'s leaves that `group` no longer holds: a commit this device
/// applied or made took them out of `conversation`'s group, or a reset left them out of its next
/// generation. They stay out ([`brings_back_removed`]). So does the identity that certified such a
/// leaf, when it isn't the one this device pins for its user now: one the user had before, which
/// certifies nothing more in the conversation ([`check_applied`]). A device whose user the same
/// commit takes off the member list left with them, not as a device, and isn't noted.
pub(crate) fn note_removed(
    tx: &Tx<'_>,
    conversation: Uuid,
    before: &Leaves,
    group: &MlsGroup,
) -> Result<(), Error> {
    let staying: BTreeSet<Uuid> = leaves(group.members())
        .map_err(|_| stored_state())?
        .values()
        .map(|leaf| leaf.device)
        .collect();
    let listed = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    for leaf in before.values() {
        if staying.contains(&leaf.device) || !listed.contains(leaf.user) {
            continue;
        }
        tx.conn().execute(
            "INSERT OR IGNORE INTO removed_devices (conversation_id, user_id, device_id) \
             VALUES (?1, ?2, ?3)",
            params![
                conversation.as_bytes().as_slice(),
                leaf.user.as_bytes().as_slice(),
                leaf.device.as_bytes().as_slice()
            ],
        )?;
        let pinned = tx
            .identity_of(leaf.user)?
            .is_some_and(|key| DeviceCertificate::verify(&leaf.certificate, &key).is_ok());
        if pinned {
            continue;
        }
        let earlier = tx
            .earlier_identities_of(leaf.user)?
            .into_iter()
            .find(|key| DeviceCertificate::verify(&leaf.certificate, key).is_ok());
        if let Some(key) = earlier {
            tx.conn().execute(
                "INSERT OR IGNORE INTO removed_identities (conversation_id, user_id, identity_key) \
                 VALUES (?1, ?2, ?3)",
                params![
                    conversation.as_bytes().as_slice(),
                    leaf.user.as_bytes().as_slice(),
                    key.as_slice()
                ],
            )?;
        }
    }
    Ok(())
}

/// The identities `user` had before that certified a leaf the group of `conversation` took out
/// ([`note_removed`]): they certify nothing more there.
fn removed_identities(tx: &Tx<'_>, conversation: Uuid, user: Uuid) -> Result<Vec<Vec<u8>>, Error> {
    let mut statement = tx.conn().prepare(
        "SELECT identity_key FROM removed_identities WHERE conversation_id = ?1 AND user_id = ?2",
    )?;
    let keys = statement.query_map(
        params![
            conversation.as_bytes().as_slice(),
            user.as_bytes().as_slice()
        ],
        |row| row.get(0),
    )?;
    Ok(keys.collect::<Result<_, _>>()?)
}

/// Whether another device's commit brings back a device this device saw leave the conversation's
/// group ([`note_removed`]), its device off its user's latest list as this device holds it. Such a
/// commit is refused as [`check`] refuses it, whatever identity certified the leaf: a device the
/// group took out (lost, then left out of a rotation or a list) doesn't come back by the server's
/// leave. The record knows that device alone, by its user and its ID: a new device ID its holder
/// makes under the identity from before a rotation is refused by what [`check_applied`] hands the
/// rules. The cost: a device added again after its removal, and taken off its list since, blocks a
/// member that applies its return late, as any such leaf did before `check_applied`.
pub(crate) fn brings_back_removed(tx: &Tx<'_>, change: &MembershipChange) -> Result<bool, Error> {
    let brought = change
        .added
        .iter()
        .chain(change.updated.iter().map(|(_, leaf)| leaf));
    for leaf in brought {
        let Ok(claimed) = DeviceCertificate::read_unverified(&leaf.credential) else {
            continue;
        };
        let listed = tx
            .device_list_of(claimed.user)?
            .is_some_and(|list| list.contains(claimed.device));
        let removed: bool = tx.conn().query_row(
            "SELECT EXISTS (SELECT 1 FROM removed_devices WHERE conversation_id = ?1 \
             AND user_id = ?2 AND device_id = ?3)",
            params![
                change.conversation.as_bytes().as_slice(),
                claimed.user.as_bytes().as_slice(),
                claimed.device.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )?;
        if removed && !listed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The group stored for `conversation` at `generation`, while this device is in it.
pub(crate) fn stored_group(
    tx: &Tx<'_>,
    conversation: Uuid,
    generation: u32,
) -> Result<Option<MlsGroup>, Error> {
    let group = MlsGroup::load(tx.provider().storage(), &group_id(conversation, generation))
        .map_err(storage_error)?;
    Ok(group.filter(MlsGroup::is_active))
}

/// Deletes what's stored of `conversation`'s group at `generation`, if anything is.
pub(crate) fn delete_group(tx: &Tx<'_>, conversation: Uuid, generation: u32) -> Result<(), Error> {
    let storage = tx.provider().storage();
    if let Some(mut group) =
        MlsGroup::load(storage, &group_id(conversation, generation)).map_err(storage_error)?
    {
        group.delete(storage).map_err(storage_error)?;
    }
    Ok(())
}

/// What the rules go by for `users`: their pinned identities and latest device lists. The users
/// this device has neither for are named, for `observe_user`.
pub(crate) fn rule_context(
    tx: &Tx<'_>,
    users: impl IntoIterator<Item = Uuid>,
) -> Result<RuleContext, Error> {
    let mut ctx = RuleContext::default();
    let mut missing = Vec::new();
    for user in users {
        if ctx.identities.contains_key(&user) || missing.contains(&user) {
            continue;
        }
        match (tx.identity_of(user)?, tx.device_list_of(user)?) {
            (Some(identity), Some(list)) => {
                ctx.identities.insert(user, identity);
                ctx.device_lists.insert(user, list);
            }
            _ => missing.push(user),
        }
    }
    if missing.is_empty() {
        Ok(ctx)
    } else {
        Err(Error::NeedsIdentities {
            users: missing.iter().map(Uuid::to_string).collect(),
        })
    }
}

/// The users whose identities and lists the rules read for `change`: those of the leaves it brings,
/// of its members' leave statements and of the leaves a member removes from users who stay
/// ([`unlisted_candidates`]), and at epoch 0 those of every leaf it starts from.
fn needed_users(change: &MembershipChange) -> BTreeSet<Uuid> {
    let brought = change
        .added
        .iter()
        .chain(change.updated.iter().map(|(_, leaf)| leaf));
    // Read without verifying, only to learn whose identity verifies them: the rules refuse what
    // doesn't verify.
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

/// Before another device's commit refused for `violation` counts as refused: when this device's
/// own knowledge may be what refuses it, the users it refuses for are to be observed anew first,
/// `needs_identities` ([`ask_first`]). Those are the users of the leaves the commit brings that
/// this device can't certify (`device_not_listed`, `leaf_not_signed`: a member that hasn't seen a
/// user's newest list or identity refuses their new device), the users whose leave statement is
/// missing or doesn't verify (`leave_without_statement`: a statement signed by a device this
/// device doesn't know as listed), and the users of the leaves a member removes
/// (`leaf_removed_without_reason`: a member that hasn't seen a user's newest list doesn't know the
/// device is off it).
pub(crate) fn commit_asks_first(
    tx: &Tx<'_>,
    entry: &[u8],
    change: &MembershipChange,
    violation: RuleViolation,
) -> Result<(), Error> {
    let users = match violation {
        RuleViolation::DeviceNotListed | RuleViolation::LeafNotSigned => {
            let brought: Vec<(&[u8], &[u8])> = change
                .added
                .iter()
                .chain(change.updated.iter().map(|(_, leaf)| leaf))
                .map(|leaf| (leaf.credential.as_slice(), leaf.signature_key.as_slice()))
                .collect();
            let ctx = rule_context(tx, claimed_users(&brought))?;
            uncertified(&ctx, &brought, true)
        }
        RuleViolation::LeaveWithoutStatement => unconfirmed_leavers(tx, change)?,
        RuleViolation::LeafRemovedWithoutReason => unlisted_candidates(change).collect(),
        _ => return Ok(()),
    };
    ask_first(tx, entry, users)
}

/// Before a welcome refused for `violation` counts as refused: the users of its leaves this device
/// can't certify by their pinned identity (`leaf_not_signed`: a welcome holds a leaf to that
/// identity alone, or to the certificate it signed for the same device) are to be observed anew
/// first, as for a commit.
pub(crate) fn welcome_asks_first(
    tx: &Tx<'_>,
    entry: &[u8],
    ctx: &RuleContext,
    leaves: &Leaves,
    violation: RuleViolation,
) -> Result<(), Error> {
    if !matches!(
        violation,
        RuleViolation::DeviceNotListed | RuleViolation::LeafNotSigned
    ) {
        return Ok(());
    }
    let all: Vec<(&[u8], &[u8])> = leaves
        .values()
        .map(|leaf| (leaf.certificate.as_slice(), leaf.signature_key.as_slice()))
        .collect();
    ask_first(tx, entry, uncertified(ctx, &all, false))
}

/// The users `leaves` (credential, signature key) name.
fn claimed_users(leaves: &[(&[u8], &[u8])]) -> BTreeSet<Uuid> {
    leaves
        .iter()
        .filter_map(|(credential, _)| DeviceCertificate::read_unverified(credential).ok())
        .map(|certificate| certificate.user)
        .collect()
}

/// The users among `leaves` whose certificate this device's knowledge refuses: not signed by
/// their pinned identity for the leaf's key, or, when `listed`, for a device off their list.
fn uncertified(ctx: &RuleContext, leaves: &[(&[u8], &[u8])], listed: bool) -> BTreeSet<Uuid> {
    let refused: Vec<(&[u8], &[u8])> = leaves
        .iter()
        .copied()
        .filter(|&(credential, key)| {
            if listed {
                certified(ctx, credential, key).is_err()
            } else {
                signed_for(ctx, credential, key).is_err()
            }
        })
        .collect();
    claimed_users(&refused)
}

/// The users `change` takes off the list without a leave statement this device can verify: each
/// statement's user when it doesn't hold, and each user removed with none (but by the owner).
fn unconfirmed_leavers(tx: &Tx<'_>, change: &MembershipChange) -> Result<BTreeSet<Uuid>, Error> {
    let claimed: Vec<Uuid> = change
        .statements
        .iter()
        .filter_map(|signed| LeaveStatement::read_unverified(signed).ok())
        .map(|statement| statement.user)
        .filter(|user| change.before.contains(*user))
        .collect();
    let ctx = rule_context(tx, claimed)?;
    let place = Place {
        conversation: change.conversation,
        generation: change.generation,
        epoch: change.epoch,
    };
    let mut users = BTreeSet::new();
    let mut left = BTreeSet::new();
    for signed in &change.statements {
        match statement_user(&ctx, &change.before, &change.leaves, place, signed) {
            Some(user) => {
                left.insert(user);
            }
            None => users.extend(
                LeaveStatement::read_unverified(signed)
                    .ok()
                    .map(|statement| statement.user),
            ),
        }
    }
    let committer = match &change.committer {
        Committer::Member { leaf, .. } => Some(leaf.user),
        Committer::NewMember => None,
    };
    let owner = change.before.owner;
    for entry in &change.before.users {
        let by_owner = owner.is_some() && owner == committer && owner != Some(entry.user);
        if !change.after.contains(entry.user) && !left.contains(&entry.user) && !by_owner {
            users.insert(entry.user);
        }
    }
    Ok(users)
}

/// `needs_identities` for the users of `users` the client hasn't observed since `entry` (the
/// refused commit's or welcome's SHA-256) asked about them at what this device knows of them now.
/// Once it observed each of them since, the same knowledge refusing the same entry again is the
/// refusal (`Ok`). What it asks is noted, whatever becomes of the command.
pub(crate) fn ask_first(tx: &Tx<'_>, entry: &[u8], users: BTreeSet<Uuid>) -> Result<(), Error> {
    let mut ask = Vec::new();
    for user in users {
        let (Some(identity), Some(list)) = (tx.identity_of(user)?, tx.device_list_of(user)?) else {
            continue;
        };
        let version = i64::try_from(list.version)
            .map_err(|_| Error::Internal("a device list's version is out of range".into()))?;
        let noted: Option<(Vec<u8>, i64, bool)> = tx
            .conn()
            .query_row(
                "SELECT identity_key, list_version, observed FROM observe_asks \
                 WHERE entry = ?1 AND user_id = ?2",
                params![entry, user.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if noted != Some((identity.to_vec(), version, true)) {
            ask.push((user, identity, version));
        }
    }
    if ask.is_empty() {
        return Ok(());
    }
    let users = ask.iter().map(|(user, _, _)| user.to_string()).collect();
    let entry = entry.to_vec();
    tx.keep(move |conn| {
        let mut written = 0;
        for (user, identity, version) in &ask {
            written += conn.execute(
                "INSERT INTO observe_asks (entry, user_id, identity_key, list_version, observed) \
                 VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT (entry, user_id) DO UPDATE SET \
                 identity_key = excluded.identity_key, list_version = excluded.list_version, \
                 observed = 0",
                params![
                    entry,
                    user.as_bytes().as_slice(),
                    identity.as_slice(),
                    version
                ],
            )?;
        }
        Ok(written)
    });
    Err(Error::NeedsIdentities { users })
}

/// Drops from another device's commit the leaves it renews with the credential and signature key
/// they had. Such a leaf asserts nothing new: it was certified as it entered, and only its own key
/// signs it. So it isn't certified again under its user's identity as this device pins it now,
/// which may have changed since the server took the commit (a rotation, a reset): that commit broke
/// no rule then, and refusing it would block the group. The validator, which checks each commit as
/// it comes, still certifies every leaf a commit brings.
pub(crate) fn skip_unchanged_leaves(change: &mut MembershipChange) {
    change.updated.retain(|(index, leaf)| {
        change.leaves.get(index).is_none_or(|before| {
            before.certificate != leaf.credential || before.signature_key != leaf.signature_key
        })
    });
}

/// For each leaf another device's commit brings, added or updated, whose certificate an identity its
/// user had before signed, not the one this device pins now: the certificate the identity pinned
/// signed for the same device, in its place for the rules, when this device keeps one. Such a leaf
/// was made before the change (a device set up then, joining its groups), and the identity pinned
/// now vouches for the same device; the rules then hold the leaf's signature key to that
/// certificate's. A leaf that identity hasn't certified, or certified with other keys, is refused,
/// and so is one of an identity this device hasn't seen yet, which it asks about first. The
/// validator, which checks each commit as it comes, holds every leaf to its own certificate.
pub(crate) fn certify_by_pinned(tx: &Tx<'_>, change: &mut MembershipChange) -> Result<(), Error> {
    let updated = change.updated.iter_mut().map(|(_, leaf)| leaf);
    for leaf in change.added.iter_mut().chain(updated) {
        if let Some(current) = pinned_in_place_of(tx, &leaf.credential, true)? {
            leaf.credential = current;
        }
    }
    Ok(())
}

/// As [`certify_by_pinned`], for each leaf of a group this device enters, by a welcome or its own
/// external commit. A new member may never have seen the identity a leaf's user had before, so a
/// leaf's certificate needn't be one this device knows: the identity pinned now vouching for the
/// same device, with the leaf's own key, is what lets it in.
pub(crate) fn certify_leaves_by_pinned(tx: &Tx<'_>, leaves: &mut Leaves) -> Result<(), Error> {
    for leaf in leaves.values_mut() {
        if let Some(current) = pinned_in_place_of(tx, &leaf.certificate, false)? {
            leaf.certificate = current;
        }
    }
    Ok(())
}

/// The certificate the identity pinned for `credential`'s user signed for the same device, when
/// this device keeps one and that identity didn't sign `credential`: when `earlier`, only if an
/// identity this device knows the user had before did.
fn pinned_in_place_of(
    tx: &Tx<'_>,
    credential: &[u8],
    earlier: bool,
) -> Result<Option<Vec<u8>>, Error> {
    let Ok(claimed) = DeviceCertificate::read_unverified(credential) else {
        return Ok(None);
    };
    let Some(pinned) = tx.identity_of(claimed.user)? else {
        return Ok(None);
    };
    if DeviceCertificate::verify(credential, &pinned).is_ok() {
        return Ok(None);
    }
    if earlier
        && !tx
            .earlier_identities_of(claimed.user)?
            .iter()
            .any(|key| DeviceCertificate::verify(credential, key).is_ok())
    {
        return Ok(None);
    }
    tx.certificate_of(claimed.user, claimed.device)
}

/// What the rules go by for a commit beyond its users' identities and lists.
#[derive(Default)]
pub(crate) struct Extra {
    /// Epoch 0's list, when any member may make it: a conversation from before the cutover.
    pub(crate) expected_initial: Option<MemberList>,
    /// The API's key, which epoch 0 must name as the one external sender.
    pub(crate) external_sender: Option<Vec<u8>>,
}

/// Holds a commit to the rules, as every member and the validator do: `Ok(Err(..))` names the
/// rule it breaks, `Err` is a failure to check it (`needs_identities` among them).
pub(crate) fn check(
    tx: &Tx<'_>,
    change: &MembershipChange,
    extra: Extra,
) -> Result<Result<(), RuleViolation>, Error> {
    let mut ctx = rule_context(tx, needed_users(change))?;
    ctx.expected_initial = extra.expected_initial;
    ctx.external_sender = extra.external_sender;
    Ok(check_change(&ctx, change))
}

/// Holds another device's commit, as `apply` takes it late, to the rules ([`check_applied_change`]):
/// a leaf it brings, or a leave statement's signer, may be off its user's latest list, certified by
/// the identity pinned for its user or, off that list, by one this device knows the user had before
/// while the group still lives in it: that identity certifies a leaf of theirs there, none of theirs
/// carries the pinned identity's certificate, and the group took out no device of theirs under it
/// ([`note_removed`]). `apply` asks it only of a commit that brings back no device the group took
/// out ([`brings_back_removed`]).
pub(crate) fn check_applied(
    tx: &Tx<'_>,
    change: &MembershipChange,
) -> Result<Result<(), RuleViolation>, Error> {
    let users = needed_users(change);
    let mut ctx = rule_context(tx, users.iter().copied())?;
    for user in users {
        // An identity the user had before certifies a leaf only while the group still lives in
        // it: it certifies a leaf of theirs there, and none carries the pinned one's certificate.
        let theirs: Vec<_> = change
            .leaves
            .values()
            .filter(|leaf| leaf.user == user)
            .collect();
        let certifies = |identity: &[u8; 32]| {
            theirs
                .iter()
                .any(|leaf| DeviceCertificate::verify(&leaf.certificate, identity).is_ok())
        };
        if !ctx.identities.get(&user).is_some_and(certifies) {
            // Nor one that certified a leaf the group took out: the group moved past it.
            let removed = removed_identities(tx, change.conversation, user)?;
            let shown = tx
                .earlier_identities_of(user)?
                .into_iter()
                .filter(|identity| {
                    certifies(identity) && !removed.iter().any(|key| key.as_slice() == identity)
                })
                .collect();
            ctx.earlier_identities.insert(user, shown);
        }
    }
    Ok(check_applied_change(&ctx, change))
}

/// A commit this device makes, before it's built.
#[derive(Default)]
pub(crate) struct Draft {
    pub(crate) adds: Vec<KeyPackage>,
    pub(crate) removes: Vec<LeafNodeIndex>,
    /// The member list after it, when it changes.
    pub(crate) list: Option<MemberList>,
    /// The leave statements it carries.
    pub(crate) statements: Vec<Vec<u8>>,
}

/// This device's next commit in `group`: the key packages it adds and the users it adds and
/// removes, and what goes with any commit of this epoch. The removals the server proposed go in
/// (OpenMLS takes them from the proposal store), and so do every member's leaves whose devices are
/// off their users' latest lists as this device knows them, those the server proposed by reference
/// alone; with them, the leave statements
/// of the users whose leaves all go, who leave the list, a leaving owner handing over to the first
/// user to have entered of those who stay.
pub(crate) fn draft(
    tx: &Tx<'_>,
    group: &MlsGroup,
    row: &GroupRow,
    adds: Vec<KeyPackage>,
    users_added: &[Uuid],
    users_removed: &[Uuid],
) -> Result<Draft, Error> {
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    let leaves = leaves(group.members()).map_err(|_| stored_state())?;
    let mut removes: Vec<LeafNodeIndex> = leaves
        .iter()
        .filter(|(_, leaf)| users_removed.contains(&leaf.user))
        .map(|(&index, _)| LeafNodeIndex::new(index))
        .collect();
    let mut going: BTreeSet<u32> = group
        .pending_proposals()
        .filter(|queued| matches!(queued.sender(), Sender::External(_)))
        .filter_map(|queued| match queued.proposal() {
            Proposal::Remove(remove) => Some(remove.removed().u32()),
            _ => None,
        })
        .collect();
    let unlisted: Vec<(LeafNodeIndex, Uuid)> = unlisted_leaves(tx, group)?
        .into_iter()
        .filter(|(leaf, _)| !going.contains(&leaf.u32()) && !removes.contains(leaf))
        .collect();
    if !unlisted.is_empty() {
        ask_about_lists(tx, &unlisted)?;
        removes.extend(unlisted.into_iter().map(|(leaf, _)| leaf));
    }
    going.extend(removes.iter().map(|leaf| leaf.u32()));

    let place = Place {
        conversation: row.conversation,
        generation: row.generation,
        epoch: group.epoch().as_u64(),
    };
    let mut statements = Vec::new();
    let mut leaving = Vec::new();
    if !row.statements.is_empty() {
        let users = row
            .statements
            .iter()
            .filter_map(|statement| LeaveStatement::read_unverified(statement).ok())
            .map(|statement| statement.user)
            .filter(|user| list.contains(*user));
        let ctx = rule_context(tx, users)?;
        for signed in &row.statements {
            let Some(user) = statement_user(&ctx, &list, &leaves, place, signed) else {
                continue;
            };
            let all_go = leaves
                .iter()
                .filter(|(_, leaf)| leaf.user == user)
                .all(|(index, _)| going.contains(index));
            if all_go && !leaving.contains(&user) {
                statements.push(signed.clone());
                leaving.push(user);
            }
        }
    }

    let mut users: Vec<Entry> = list
        .users
        .iter()
        .filter(|entry| !leaving.contains(&entry.user) && !users_removed.contains(&entry.user))
        .copied()
        .collect();
    let owner = match list.owner {
        Some(owner) if leaving.contains(&owner) => users.first().map(|entry| entry.user),
        owner => owner,
    };
    users.extend(users_added.iter().map(|&user| Entry {
        user,
        generation: row.generation,
        epoch: place.epoch + 1,
    }));
    let after = MemberList::new(list.kind, owner, users);
    Ok(Draft {
        adds,
        removes,
        list: (after != list).then_some(after),
        statements,
    })
}

/// A commit of this device's, staged in its group, as the server takes it: the commit, the welcome
/// for the devices it adds, and the group info of the epoch it makes.
pub(crate) struct Staged {
    pub(crate) commit: Vec<u8>,
    pub(crate) welcome: Option<Vec<u8>>,
    pub(crate) group_info: Vec<u8>,
}

/// Builds `draft` in `group` and stages it: with every removal the server proposed, the member
/// list's change, the leave statements in its authenticated data, and a path whose new leaf carries
/// this device's current certificate. Before anything goes out, the commit is held to the rules, as
/// every member and the validator will hold it.
pub(crate) fn stage(
    tx: &Tx<'_>,
    group: &mut MlsGroup,
    own: &OwnDevice,
    draft: Draft,
    extra: Extra,
) -> Result<Staged, Error> {
    let provider = tx.provider();
    let credential = own.credential()?;
    let context = group.public_group().group_context().clone();
    let leaves = leaves(group.members()).map_err(|_| stored_state())?;
    let extensions = match &draft.list {
        Some(list) => {
            let mut extensions = context.extensions().clone();
            extensions
                .add_or_replace(list.to_extension())
                .map_err(openmls_error)?;
            Some(extensions)
        }
        None => None,
    };
    let aad = CommitAad::new(draft.statements).encode();
    group.set_aad(aad.clone());
    let mut builder = group
        .commit_builder()
        .propose_adds(draft.adds)
        .propose_removals(draft.removes)
        .force_self_update(true)
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_credential_with_key(credential)
                .build(),
        );
    if let Some(extensions) = extensions {
        builder = builder
            .propose_group_context_extensions(extensions)
            .map_err(openmls_error)?;
    }
    let bundle = builder
        .load_psks(provider.storage())
        .map_err(openmls_error)?
        .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
        .map_err(openmls_error)?
        .stage_commit(provider)
        .map_err(openmls_error)?;

    let staged = group
        .pending_commit()
        .ok_or_else(|| Error::Internal("the commit wasn't staged".into()))?;
    let sender = Sender::Member(group.own_leaf_index());
    let change = extract_change(&context, &leaves, staged, &sender, &aad).map_err(violation)?;
    check(tx, &change, extra)?.map_err(violation)?;

    let group_info = bundle
        .group_info()
        .ok_or_else(|| Error::Internal("the commit came without its group info".into()))?;
    Ok(Staged {
        commit: tls(bundle.commit())?,
        welcome: bundle.to_welcome_msg().as_ref().map(tls).transpose()?,
        group_info: tls(&MlsMessageOut::from(group_info.clone()))?,
    })
}

/// A device that a commit would add but can't: it has no valid key package.
#[derive(Debug, Serialize)]
pub(crate) struct Skipped {
    user_id: Uuid,
    device_id: Uuid,
}

/// The key packages that bring `users`' devices in: for each device on a user's latest signed
/// list but this one, the first of those `offered` for it that's valid, its lifetime by the core's
/// clock among the rest. A device with none is skipped. A user with key packages offered needs an
/// identity and a list (`needs_identities`); a user with none and no identity known has no devices
/// this device can add.
pub(crate) fn choose(
    tx: &Tx<'_>,
    own_device: Uuid,
    users: &[Uuid],
    offered: &BTreeMap<Uuid, Vec<b64::Bytes>>,
) -> Result<(Vec<KeyPackage>, Vec<Skipped>), Error> {
    let crypto = tx.provider().crypto();
    // OpenMLS's validation reads the system's clock for the lifetime; the core's decides as well.
    let now = u64::try_from(tx.now() / 1000).unwrap_or(0);
    let live = |lifetime: &Lifetime| lifetime.not_before() <= now && now < lifetime.not_after();
    let mut chosen = Vec::new();
    let mut skipped = Vec::new();
    let mut missing = Vec::new();
    for &user in users {
        let offers = offered.get(&user).map(Vec::as_slice).unwrap_or_default();
        let (identity, list) = match (tx.identity_of(user)?, tx.device_list_of(user)?) {
            (Some(identity), Some(list)) => (identity, list),
            _ => {
                if !offers.is_empty() {
                    missing.push(user.to_string());
                }
                continue;
            }
        };
        let mut valid = BTreeMap::new();
        for offer in offers {
            let Some(key_package) = KeyPackageIn::tls_deserialize_exact_bytes(&offer.0)
                .ok()
                .and_then(|key_package| key_package.validate(crypto, ProtocolVersion::Mls10).ok())
                .filter(|key_package| live(key_package.life_time()))
            else {
                continue;
            };
            let leaf = key_package.leaf_node();
            let supported = key_package.ciphersuite() == SUITE
                && leaf
                    .capabilities()
                    .extensions()
                    .contains(&ExtensionType::Unknown(MEMBER_LIST_EXTENSION));
            let certificate = BasicCredential::try_from(leaf.credential().clone())
                .ok()
                .and_then(|basic| DeviceCertificate::verify(basic.identity(), &identity).ok());
            if let Some(certificate) = certificate.filter(|certificate| {
                supported
                    && certificate.user == user
                    && certificate.signature_key == leaf.signature_key().as_slice()
                    && list.contains(certificate.device)
            }) {
                valid.entry(certificate.device).or_insert(key_package);
            }
        }
        for &device in &list.devices {
            if device == own_device {
                continue;
            }
            match valid.remove(&device) {
                Some(key_package) => chosen.push(key_package),
                None => skipped.push(Skipped {
                    user_id: user,
                    device_id: device,
                }),
            }
        }
    }
    if missing.is_empty() {
        Ok((chosen, skipped))
    } else {
        Err(Error::NeedsIdentities { users: missing })
    }
}

fn tls(message: &MlsMessageOut) -> Result<Vec<u8>, Error> {
    message
        .tls_serialize_detached()
        .map_err(|_| Error::Internal("an MLS message couldn't be encoded".into()))
}

/// SHA-256, to know a commit by.
fn digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn violation(violation: RuleViolation) -> Error {
    Error::RuleViolation {
        rule: violation.name().into(),
    }
}

/// OpenMLS refusing what the core asked of it. Its messages name the check, never a key.
fn openmls_error(error: impl Display) -> Error {
    Error::Internal(format!("MLS: {error}"))
}

fn storage_error(error: SqlStorageError) -> Error {
    Error::Storage(error.to_string())
}

fn stored_state() -> Error {
    Error::Internal("a stored group isn't one of Duvet's".into())
}

fn malformed_row() -> Error {
    Error::Internal("a stored conversation is malformed".into())
}
