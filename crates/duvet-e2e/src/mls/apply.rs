//! A conversation's queue, as the server keeps it: one sequence of entries (commits, welcomes,
//! proposals, messages, edits, deletes), which the core applies in strict order of their numbers.
//! An entry applied already is skipped, without an error or an effect; a missing one is a `gap`.
//! Each kind of entry has its handler ([`EntryHandler`]); the order is this module's alone.

use duvet_e2e_rules::{
    Entry as ListEntry, Kind, LeaveStatement, MemberList, Place, Record, RuleContext,
    RuleViolation, check_joined_state, external_sender_is, extract_change, group_id_parts,
    join_config, leaves, statement_user,
};
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{
    MlsGroup, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProcessMessageError,
    ProcessedMessageContent, Proposal, ProtocolMessage, Sender, StagedWelcome, Welcome,
    WelcomeError,
};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    EXTERNAL_SENDER_MISMATCH, Extra, GroupRow, api_key, brings_back_removed, certify_by_pinned,
    certify_leaves_by_pinned, check, check_applied, commit_asks_first, delete_group, digest,
    merge_own, note_removed, openmls_error, rule_context, skip_unchanged_leaves, storage_error,
    stored_group, stored_state, welcome_asks_first,
};
use crate::identity::{invalid, not_found};
use crate::protocol::b64;
use crate::{Error, Tx};

#[derive(Debug, Deserialize)]
pub(crate) struct ApplyRequest {
    conversation_id: Uuid,
    entries: Vec<Entry>,
    /// The API's key, as the client pinned it: a welcome's group must have it as its one external
    /// sender. Without it, a welcome's is held to having one, whatever its key.
    #[serde(default, with = "b64::option")]
    external_sender: Option<Vec<u8>>,
}

/// An entry of a conversation's queue, as the API hands it out.
#[derive(Debug, Deserialize)]
pub(crate) struct Entry {
    pub(crate) seq: u64,
    pub(crate) kind: EntryKind,
    /// The MLS message.
    #[serde(with = "b64")]
    pub(crate) data: Vec<u8>,
    /// On the welcome of a conversation from before the cutover: its owner and members as this
    /// device's client showed them then, from the client's own record (the API never gives it).
    /// The founding welcome must have its users, in any order, kind and owner, and any other join
    /// keep to it ([`Expected::hold`]), but a reset's welcome to a device that holds the group,
    /// which goes by the members it had.
    #[serde(default)]
    pub(crate) expected: Option<Expected>,
    /// On the server's proposal to remove a leaf of a user who leaves: their signed statement, for
    /// the commit that takes them out.
    #[serde(default, with = "b64::option")]
    pub(crate) statement: Option<Vec<u8>>,
    /// On a message, an edit or a deletion: the message's ID, as the API gives it (an edit's or a
    /// deletion's is the ID of the message it changes).
    #[serde(default)]
    pub(crate) message_id: Option<Uuid>,
    /// Who sent it, as the API says: a message this device can't open is shown as theirs.
    #[serde(default)]
    pub(crate) sender_user: Option<Uuid>,
    #[serde(default)]
    pub(crate) sender_device: Option<Uuid>,
    /// When the API took it, in Unix milliseconds.
    #[serde(default)]
    pub(crate) sent_at: Option<i64>,
    /// The users a message mentions, as its sender listed them for the API.
    #[serde(default)]
    pub(crate) mentions: Vec<Uuid>,
    /// The message a message answers, as the API gives it: replies go in the clear.
    #[serde(default)]
    pub(crate) reply_to: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EntryKind {
    Commit,
    Welcome,
    Proposal,
    Message,
    Edit,
    Delete,
}

/// A conversation's members as a device knew them before the cutover.
#[derive(Debug, Deserialize)]
pub(crate) struct Expected {
    /// A group's owner; a DM has none.
    #[serde(default)]
    owner: Option<Uuid>,
    members: Vec<Uuid>,
}

impl Expected {
    /// The record as a list at `generation`'s start: a group's when there's an owner, a DM's when
    /// there isn't.
    pub(crate) fn list(&self, generation: u32) -> MemberList {
        let kind = if self.owner.is_some() {
            Kind::Group
        } else {
            Kind::Dm
        };
        entered_at_start(kind, self.owner, &self.members, generation)
    }

    /// Holds a group this device joins at `generation` to this record, in `ctx`: the founding
    /// welcome, the first commit's at generation 0, to the record's members (`is_record`); any
    /// other join, at any generation, with a row for the conversation or without, to
    /// `keeps_record`.
    pub(crate) fn hold(&self, ctx: &mut RuleContext, generation: u32, founding: bool) {
        let list = self.list(generation);
        ctx.record = Some(if founding {
            Record::Founding(list)
        } else {
            Record::Joined(list)
        });
    }
}

/// What an entry did.
#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub(crate) enum Applied {
    /// It took effect: a commit merged, a welcome joined, a proposal kept for the next commit, a
    /// message, an edit or a deletion opened and kept. The group's epoch after it.
    #[serde(rename = "applied")]
    Done { epoch: u64 },
    /// This device's own commit: merged by `commit_result`, or now, when the server took the commit
    /// it answered as refused. Or its own message, edit or deletion, kept as it was made.
    Own,
    /// A message, an edit or a deletion this device couldn't open, for the `reason` the client
    /// reports: `message` (MLS refused it), `envelope` (what it held isn't an envelope) or
    /// `too_large` (over 32 KiB, unread). A message is kept as waiting, for an import to replace.
    Undecryptable { reason: &'static str },
    /// A commit that took this device out of the group.
    Removed,
    /// Refused, for the rule it breaks (or `malformed`, `invalid_commit`, `invalid_welcome`,
    /// `invalid_proposal`, `wrong_group` for what isn't a valid message of this group,
    /// `stale_welcome` for a welcome to an epoch this device held or saw pass, and
    /// `external_sender_mismatch` for one whose group doesn't have the API's key the client gave as
    /// its one external sender; `not_author` for an edit or a deletion of another user's message).
    /// Another device's commit refused for a rule, or one OpenMLS can't process, also blocks the
    /// group, and nothing goes on it but a reset; a malformed entry, a commit entry that holds no
    /// commit, and a refused welcome or proposal leave the group as it was.
    Rejected { rule: String },
    /// Not for this device, or not now: a welcome for other devices, an entry of another generation
    /// or epoch, of a group this device isn't in, or after its group was blocked; a message this
    /// device has already, or an edit or a deletion of one deleted.
    Ignored,
}

#[derive(Serialize)]
struct EntryResult {
    seq: u64,
    kind: EntryKind,
    #[serde(flatten)]
    applied: Applied,
}

#[derive(Serialize)]
pub(crate) struct ApplyReply {
    /// Every entry this device needs up to this one is applied: the next it needs comes after it.
    /// None while nothing anchored the device's count.
    applied_through: Option<u64>,
    /// What each entry this call applied did; those applied before aren't in it.
    results: Vec<EntryResult>,
    catch_up_due: Vec<Uuid>,
}

/// A conversation as `apply` walks its queue: its row, and the group this device holds of it,
/// loaded once for the whole call.
pub(crate) struct Conversation {
    pub(crate) id: Uuid,
    pub(crate) row: Option<GroupRow>,
    /// The group at the row's generation, while this device is in it.
    pub(crate) group: Option<MlsGroup>,
    /// The API's key the client gave, which a welcome's group must have as its one external sender.
    external_sender: Option<[u8; 32]>,
}

/// What an entry of one kind does to its conversation. `apply` hands each entry, in order, to the
/// handler of its kind, which changes `at` (its row and group are written once all are applied).
pub(crate) trait EntryHandler {
    fn apply(&self, tx: &Tx<'_>, at: &mut Conversation, entry: &Entry) -> Result<Applied, Error>;
}

fn handler(kind: EntryKind) -> &'static dyn EntryHandler {
    match kind {
        EntryKind::Commit => &Commits,
        EntryKind::Welcome => &Welcomes,
        EntryKind::Proposal => &Proposals,
        EntryKind::Message | EntryKind::Edit | EntryKind::Delete => &crate::messages::Messages,
    }
}

/// Applies `entries` to the conversation, in order: one already applied is skipped, and one after
/// a missing one is a `gap` that names the first entry the core still needs (nothing of the call
/// is kept then). Numbers count while this device holds the conversation's group, from the entry
/// that anchored it (its own commit's, through `commit_result`, or the welcome that brought it in).
/// While it isn't in the group it takes entries as they come, and only one that took effect
/// (`Done`: the welcome that brings it back) moves its count; what it passed by or refused stays
/// to come, in its turn. `applied_through` never passes what the device still needs.
pub(crate) fn apply(tx: &Tx<'_>, request: ApplyRequest) -> Result<ApplyReply, Error> {
    let row = GroupRow::read(tx, request.conversation_id)?;
    if row.as_ref().is_some_and(|row| row.pending.is_some()) {
        return Err(Error::PendingCommit);
    }
    let group = match &row {
        Some(row) => stored_group(tx, request.conversation_id, row.generation)?,
        None => None,
    };
    let mut at = Conversation {
        id: request.conversation_id,
        row,
        group,
        external_sender: request
            .external_sender
            .as_deref()
            .map(api_key)
            .transpose()?,
    };
    let start = at.last_seq();
    let held = at.group.is_some();
    let mut first_counted = None;
    let mut results = Vec::new();
    for entry in &request.entries {
        if i64::try_from(entry.seq).is_err() {
            return Err(invalid("entries", "an entry's number is out of range"));
        }
        if let Some(last) = at.last_seq() {
            if entry.seq <= last {
                continue;
            }
            if at.group.is_some() && entry.seq != last + 1 {
                // Nothing of this call is kept: the core needs what it needed when the call began.
                let from = match start {
                    Some(start) if held => start + 1,
                    _ => first_counted.unwrap_or(last + 1),
                };
                return Err(Error::Gap { from });
            }
        }
        let holding = at.group.is_some();
        let applied = handler(entry.kind).apply(tx, &mut at, entry)?;
        crate::backup::followed(tx, at.id, holding, at.group.is_some(), entry.sent_at)?;
        // In the group, every entry counts, in order; out of it, only one that took effect.
        let counts = if holding {
            !matches!(applied, Applied::Ignored)
                || at.row.as_ref().is_some_and(|row| row.last_seq.is_some())
        } else {
            matches!(applied, Applied::Done { .. })
        };
        if let Some(row) = at.row.as_mut()
            && counts
        {
            row.last_seq = Some(entry.seq);
            first_counted.get_or_insert(entry.seq);
        }
        results.push(EntryResult {
            seq: entry.seq,
            kind: entry.kind,
            applied,
        });
    }
    if let Some(row) = &at.row {
        row.write(tx)?;
    }
    Ok(ApplyReply {
        applied_through: at.last_seq(),
        results,
        catch_up_due: crate::messages::catch_up_due(tx, at.id, at.row.as_ref())?,
    })
}

impl Conversation {
    fn last_seq(&self) -> Option<u64> {
        self.row.as_ref().and_then(|row| row.last_seq)
    }
}

/// Commits: each one at this device's epoch is held to the rules, then merged. Another device's
/// commit that breaks them, or that this device can't process, blocks the group, but one refused
/// for what this device knows of some users (their leaves' certificates, their leave statements)
/// first asks to observe them anew (`needs_identities`), until the client did and the same
/// knowledge refuses it again. Then a leaf, or a leave statement's signer, that only its user's
/// latest list refuses, or that an identity the user had before certified, is let in
/// (`check_applied_change`): the server took the commit then, and the device may have left the list
/// since. But not a device this device saw the group take out (`brings_back_removed`), nor one an
/// identity from before certified where the group has moved past it (`check_applied`): those are
/// refused, and block. This device's own commit never blocks it: one the server answered as refused
/// is merged when the queue brings it back, and dropped once the queue shows it never entered.
struct Commits;

impl EntryHandler for Commits {
    fn apply(&self, tx: &Tx<'_>, at: &mut Conversation, entry: &Entry) -> Result<Applied, Error> {
        let Some(row) = at.row.as_mut() else {
            return Ok(Applied::Ignored);
        };
        let Some(message) = protocol_message(&entry.data) else {
            return Ok(rejected("malformed"));
        };
        if !in_group(&message, at.id, row.generation) || row.blocked {
            return Ok(Applied::Ignored);
        }
        let provider = tx.provider();
        if row.echo.as_deref() == Some(digest(&entry.data).as_slice()) {
            row.echo = None;
            // Taken after all: merged now, as `commit_result` would have.
            if let Some(group) = at.group.as_mut()
                && group.pending_commit().is_some()
                && message.epoch() == group.epoch()
            {
                merge_own(tx, row, group)?;
            }
            return Ok(Applied::Own);
        }
        let Some(group) = at.group.as_mut() else {
            return Ok(Applied::Ignored);
        };
        // Another epoch's: an old one replayed, or one this device can't follow.
        let epoch = message.epoch().as_u64();
        if epoch != group.epoch().as_u64() {
            return Ok(Applied::Ignored);
        }
        let context = group.public_group().group_context().clone();
        let leaves = leaves(group.members()).map_err(|_| stored_state())?;
        let processed = match group.process_message(provider, message) {
            Ok(processed) => processed,
            Err(ProcessMessageError::StorageError(error)) => return Err(storage_error(error)),
            Err(_) => return Ok(block(row, "invalid_commit")),
        };
        let sender = processed.sender().clone();
        let aad = processed.aad().to_vec();
        let staged = match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => staged,
            // This device's waiting commit, in bytes other than those it made.
            ProcessedMessageContent::OwnPendingCommit => {
                row.echo = None;
                merge_own(tx, row, group)?;
                return Ok(Applied::Own);
            }
            _ => return Ok(rejected("invalid_commit")),
        };
        let mut change = match extract_change(&context, &leaves, &staged, &sender, &aad) {
            Ok(change) => change,
            Err(violation) => return Ok(block(row, violation.name())),
        };
        skip_unchanged_leaves(&mut change);
        certify_by_pinned(tx, &mut change)?;
        if let Err(violation) = check(tx, &change, Extra::default())? {
            let asked = digest(&entry.data);
            commit_asks_first(tx, &asked, &change, violation)?;
            // A device this group took out, back off its user's list, stays out.
            if brings_back_removed(tx, &change)? {
                return Ok(block(row, violation.name()));
            }
            // Observed, a leaf or a leave statement's signer that only the user's latest list
            // refuses is let in: the server may have taken the commit while it was listed, and this
            // device sends nothing while such a leaf is in (`ready_to_send`).
            if let Err(violation) = check_applied(tx, &change)? {
                commit_asks_first(tx, &asked, &change, violation)?;
                return Ok(block(row, violation.name()));
            }
        }
        let after =
            MemberList::from_group_context(staged.group_context()).map_err(|_| stored_state())?;
        // Merging another device's commit drops this device's waiting one: its epoch is taken.
        group
            .merge_staged_commit(provider, *staged)
            .map_err(openmls_error)?;
        note_removed(tx, at.id, &leaves, group)?;
        // A member without a device whose device it brings is due a catch-up.
        crate::messages::entered(tx, at.id, &change.added)?;
        row.echo = None;
        row.members = after;
        row.statements.clear();
        // The epoch the commit leads to, whether or not this device is in it.
        row.epoch = epoch + 1;
        if group.is_active() {
            return Ok(Applied::Done {
                epoch: group.epoch().as_u64(),
            });
        }
        // The commit took this device out: nothing of the group is of use to it any more.
        if let Some(mut group) = at.group.take() {
            group.delete(provider.storage()).map_err(storage_error)?;
        }
        Ok(Applied::Removed)
    }
}

/// Welcomes: one for this device brings it into a group, after it holds that group to the rules,
/// and to the API's key as its one external sender when the client gives it. One refused only for
/// what this device knows of its leaves' users first asks to observe them anew, as a commit does.
struct Welcomes;

impl EntryHandler for Welcomes {
    fn apply(&self, tx: &Tx<'_>, at: &mut Conversation, entry: &Entry) -> Result<Applied, Error> {
        let Some(welcome) = welcome(&entry.data) else {
            return Ok(rejected("malformed"));
        };
        let provider = tx.provider();
        // The welcome's secrets for this device open with one of its key packages, which this uses
        // up (but the last resort): only then is its group info readable.
        let joining = match StagedWelcome::build_from_welcome(provider, &join_config(), welcome) {
            Ok(joining) => joining,
            Err(WelcomeError::NoMatchingKeyPackage) => return Ok(Applied::Ignored),
            Err(WelcomeError::StorageError(error)) => return Err(storage_error(error)),
            Err(_) => return Ok(rejected("invalid_welcome")),
        };
        let processed = joining.processed_welcome();
        let Ok((conversation, generation)) =
            group_id_parts(processed.unverified_group_info().group_id())
        else {
            return Ok(rejected("malformed"));
        };
        if conversation != at.id {
            return Ok(rejected("wrong_group"));
        }
        // A welcome to a later generation is a reset, which keeps the members the group had, as
        // this device has them while it's in the group.
        let reset = match &at.row {
            None => None,
            Some(row) if generation > row.generation => at.group.is_some().then(|| {
                let users: Vec<Uuid> = row.members.users.iter().map(|entry| entry.user).collect();
                entered_at_start(row.members.kind, row.members.owner, &users, generation)
            }),
            Some(row) if generation == row.generation && at.group.is_none() && !row.blocked => {
                // A welcome to an epoch this device held or saw pass is an old one, handed out
                // again: in it, members removed since still hold the keys.
                if processed.unverified_group_info().epoch().as_u64() <= row.epoch {
                    return Ok(rejected("stale_welcome"));
                }
                None
            }
            // An older generation's, or this device is in the group, or the group is blocked.
            Some(_) => return Ok(Applied::Ignored),
        };
        let key_package = processed
            .own_key_package()
            .map(|key_package| key_package.hash_ref(provider.crypto()))
            .transpose()
            .map_err(openmls_error)?;
        // What this device held of the group at that generation (a group it left) goes.
        delete_group(tx, at.id, generation)?;

        // A leaf that a device which never came back left in the tree must not keep anyone out.
        let staged = match joining.skip_lifetime_validation().build() {
            Ok(staged) => staged,
            Err(WelcomeError::StorageError(error)) => return Err(storage_error(error)),
            Err(_) => return Ok(rejected("invalid_welcome")),
        };
        if let Some(key) = &at.external_sender
            && !external_sender_is(staged.group_context(), key)
        {
            return Ok(rejected(EXTERNAL_SENDER_MISMATCH));
        }
        let mut leaves = match leaves(staged.members()) {
            Ok(leaves) => leaves,
            Err(violation) => return Ok(rejected(violation.name())),
        };
        certify_leaves_by_pinned(tx, &mut leaves)?;
        let context = staged.group_context();
        let epoch = context.epoch().as_u64();
        let mut ctx = rule_context(tx, leaves.values().map(|leaf| leaf.user))?;
        match (reset, &entry.expected) {
            // A reset's welcome to a device that holds the group goes by the members it had: they
            // carry the legitimate changes since the cutover, which the record doesn't.
            (Some(members), _) => ctx.expected_initial = Some(members),
            (None, Some(record)) => {
                // The founding welcome is the first commit's, at generation 0.
                let founding = (generation, epoch) == (0, 1);
                record.hold(&mut ctx, generation, founding);
            }
            (None, None) => {}
        }
        if let Err(violation) = check_joined_state(&ctx, context, &leaves) {
            welcome_asks_first(tx, &digest(&entry.data), &ctx, &leaves, violation)?;
            return Ok(rejected(violation.name()));
        }
        let list = MemberList::from_group_context(context).map_err(|_| stored_state())?;
        // Only the owner adds a user to a group, and a welcome's group info is signed by the
        // commit's maker: the welcome of the commit that added this device's user must be the
        // owner's. Who made a group's epoch 0 the validator checked, as no welcome shows it.
        let own_user = tx.own_user()?.ok_or_else(|| not_found("device"))?;
        let added_now = list
            .entry(own_user)
            .is_some_and(|entry| (entry.generation, entry.epoch) == (generation, epoch));
        let signer = leaves
            .get(&staged.welcome_sender_index().u32())
            .map(|leaf| leaf.user);
        if list.kind == Kind::Group && added_now && signer != list.owner {
            return Ok(rejected(RuleViolation::MembersChangedByNonOwner.name()));
        }

        // In: the group of the generation before goes. What a reset doesn't bring from it, it left
        // out, as a commit takes a device out.
        let before = match at.group.take() {
            Some(mut old) => {
                let before = duvet_e2e_rules::leaves(old.members()).map_err(|_| stored_state())?;
                old.delete(provider.storage()).map_err(storage_error)?;
                Some(before)
            }
            None => None,
        };
        let group = staged.into_group(provider).map_err(|error| match error {
            WelcomeError::StorageError(error) => storage_error(error),
            error => openmls_error(error),
        })?;
        if let Some(before) = before {
            note_removed(tx, at.id, &before, &group)?;
        }
        // The leaf this device joined with is its key package's, as new as that.
        let made: Option<i64> = match &key_package {
            Some(reference) => tx
                .conn()
                .query_row(
                    "SELECT created_at FROM key_packages WHERE hash_ref = ?1",
                    [reference.as_slice()],
                    |row| row.get(0),
                )
                .optional()?,
            None => None,
        };
        at.row = Some(GroupRow {
            conversation: at.id,
            generation,
            last_seq: at.row.as_ref().and_then(|row| row.last_seq),
            epoch,
            members: list,
            blocked: false,
            leaf_updated_at: made.unwrap_or(tx.now()),
            pending: None,
            echo: None,
            statements: Vec::new(),
        });
        at.group = Some(group);
        Ok(Applied::Done { epoch })
    }
}

/// Proposals: the server's removals of leaves, kept for the next commit, with the statement of a
/// user who leaves. The rules take nothing else from the server, and members propose nothing. A
/// removal this device's waiting commit leaves out shows that commit never entered (the validator
/// holds every member's commit to the removals pending at its epoch), and drops it.
struct Proposals;

impl EntryHandler for Proposals {
    fn apply(&self, tx: &Tx<'_>, at: &mut Conversation, entry: &Entry) -> Result<Applied, Error> {
        let Some(row) = at.row.as_mut() else {
            return Ok(Applied::Ignored);
        };
        let Some(message) = protocol_message(&entry.data) else {
            return Ok(rejected("malformed"));
        };
        if !in_group(&message, at.id, row.generation) || row.blocked {
            return Ok(Applied::Ignored);
        }
        let Some(group) = at.group.as_mut() else {
            return Ok(Applied::Ignored);
        };
        // Proposals last one epoch.
        if message.epoch() != group.epoch() {
            return Ok(Applied::Ignored);
        }
        let provider = tx.provider();
        let processed = match group.process_message(provider, message) {
            Ok(processed) => processed,
            Err(ProcessMessageError::StorageError(error)) => return Err(storage_error(error)),
            Err(_) => return Ok(rejected("invalid_proposal")),
        };
        let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
            return Ok(rejected("invalid_proposal"));
        };
        let removed = match (proposal.sender(), proposal.proposal()) {
            (Sender::External(_), Proposal::Remove(remove)) => remove.removed(),
            _ => return Ok(rejected(RuleViolation::ServerProposalNotRemove.name())),
        };
        let left_out = group.pending_commit().is_some_and(|waiting| {
            !waiting
                .remove_proposals()
                .any(|carried| carried.remove_proposal().removed() == removed)
        });
        if left_out {
            group
                .clear_pending_commit(provider.storage())
                .map_err(storage_error)?;
            row.echo = None;
        }
        group
            .store_pending_proposal(provider.storage(), *proposal)
            .map_err(storage_error)?;
        if let Some(statement) = &entry.statement {
            keep_statement(tx, row, group, statement)?;
        }
        Ok(Applied::Done {
            epoch: group.epoch().as_u64(),
        })
    }
}

/// Keeps a leave statement that came with a removal, when it holds for this group now, for the
/// commit that takes its user out; one that doesn't hold changes nothing.
fn keep_statement(
    tx: &Tx<'_>,
    row: &mut GroupRow,
    group: &MlsGroup,
    signed: &[u8],
) -> Result<(), Error> {
    let Ok(claimed) = LeaveStatement::read_unverified(signed) else {
        return Ok(());
    };
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    if !list.contains(claimed.user) {
        return Ok(());
    }
    let leaves = leaves(group.members()).map_err(|_| stored_state())?;
    let ctx = rule_context(tx, [claimed.user])?;
    let place = Place {
        conversation: row.conversation,
        generation: row.generation,
        epoch: group.epoch().as_u64(),
    };
    let Some(user) = statement_user(&ctx, &list, &leaves, place, signed) else {
        return Ok(());
    };
    row.statements.retain(
        |kept| !matches!(LeaveStatement::read_unverified(kept), Ok(kept) if kept.user == user),
    );
    row.statements.push(signed.to_vec());
    Ok(())
}

pub(crate) fn rejected(rule: &str) -> Applied {
    Applied::Rejected { rule: rule.into() }
}

/// A commit refused: the group is blocked, and only a reset takes it on.
fn block(row: &mut GroupRow, rule: &str) -> Applied {
    row.blocked = true;
    rejected(rule)
}

/// `users` entered at the start of `generation`.
fn entered_at_start(
    kind: Kind,
    owner: Option<Uuid>,
    users: &[Uuid],
    generation: u32,
) -> MemberList {
    let entries = users
        .iter()
        .map(|&user| ListEntry {
            user,
            generation,
            epoch: 0,
        })
        .collect();
    MemberList::new(kind, owner, entries)
}

pub(crate) fn protocol_message(bytes: &[u8]) -> Option<ProtocolMessage> {
    MlsMessageIn::tls_deserialize_exact_bytes(bytes)
        .ok()?
        .try_into_protocol_message()
        .ok()
}

fn welcome(bytes: &[u8]) -> Option<Welcome> {
    match MlsMessageIn::tls_deserialize_exact_bytes(bytes)
        .ok()?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => Some(welcome),
        _ => None,
    }
}

/// Whether `message` is of `conversation`'s group at `generation`.
fn in_group(message: &ProtocolMessage, conversation: Uuid, generation: u32) -> bool {
    group_id_parts(message.group_id()) == Ok((conversation, generation))
}
