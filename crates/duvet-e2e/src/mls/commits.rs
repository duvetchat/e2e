//! The server's word on this device's commits, the commits a device makes on its own (pending
//! removals, its leaf's renewal), joining by external commit, and what the group is.

use duvet_e2e_rules::{
    CommitAad, Entry, Kind, MemberList, check_joined_state, external_sender_is, group_id,
    join_config, leaf_capabilities, leaves,
};
use openmls::prelude::tls_codec::DeserializeBytes as _;
use openmls::prelude::{
    CreationFromExternalError, ExternalCommitBuilderError, LeafNodeParameters, MlsGroup,
    MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, OpenMlsProvider,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::apply::Expected;
use super::members::Committed;
use super::{
    ConversationId, EXTERNAL_SENDER_MISMATCH, Extra, GroupRow, Pending, REFRESH_AFTER_MS, api_key,
    can_commit, certify_leaves_by_pinned, delete_group, digest, draft, load_group, note_removed,
    openmls_error, own_merged, removals_waiting, rule_context, stage, storage_error, stored_group,
    stored_state, tls, violation,
};
use crate::identity::{invalid, not_found, stored_uuid};
use crate::messages::Empty;
use crate::protocol::b64;
use crate::{Error, Tx};

#[derive(Debug, Deserialize)]
pub(crate) struct CommitResult {
    conversation_id: Uuid,
    /// Whether the server took the commit.
    accepted: bool,
    /// The commit's own number in the queue, which the server's answer gives when it takes it:
    /// required then. A new group's creator and an external joiner count the queue from there.
    #[serde(default)]
    seq: Option<u64>,
    /// The validator refused the commit: it never entered. A refusal without it (a 409, or an
    /// answer the client lost) may have entered after all.
    #[serde(default)]
    invalid: bool,
}

#[derive(Serialize)]
pub(crate) struct Epoch {
    /// The group's epoch after the server's word; none once the group is gone.
    epoch: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct JoinExternal {
    conversation_id: Uuid,
    generation: u32,
    /// The group info of the group's latest epoch, as the API serves it.
    #[serde(with = "b64")]
    group_info: Vec<u8>,
    /// For a conversation from before the cutover: the client's own record of it, as a welcome
    /// entry's `expected`.
    #[serde(default)]
    expected: Option<Expected>,
    /// The API's key, as the client pinned it: the group must have it as its one external sender,
    /// as `apply`'s welcomes do.
    #[serde(default, with = "b64::option")]
    external_sender: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub(crate) struct Due {
    conversations: Vec<Uuid>,
}

#[derive(Serialize)]
pub(crate) struct Forgotten {
    /// The members the forgotten group had, with its owner in a group: the record of what brings
    /// the group back.
    expected: Expected,
}

#[derive(Serialize)]
pub(crate) struct ForgottenGroups {
    /// The record of each group this device forgot, by conversation.
    records: Vec<ForgottenGroup>,
}

#[derive(Serialize)]
struct ForgottenGroup {
    conversation_id: Uuid,
    /// As `forget_group` answered it.
    expected: Expected,
}

#[derive(Serialize)]
pub(crate) struct GroupState {
    generation: u32,
    epoch: u64,
    kind: Kind,
    owner: Option<Uuid>,
    members: Vec<Member>,
    devices: Vec<Device>,
    /// The epoch's authenticator: the same on every device in the same group at the same epoch.
    #[serde(with = "b64")]
    authenticator: Vec<u8>,
    blocked: bool,
}

#[derive(Serialize)]
struct Member {
    user_id: Uuid,
    /// When the user entered.
    generation: u32,
    epoch: u64,
}

#[derive(Serialize)]
struct Device {
    user_id: Uuid,
    device_id: Uuid,
    leaf: u32,
}

/// The server's word on this device's waiting commit. Taken, it's merged (an external commit,
/// merged as it was made, stays), and a founding or an external join holds the group again: the
/// record of a group this device forgot there goes ([`drop_record`]). Refused, epoch 0 goes whole
/// with its group, for the winner's welcome to come through `apply`, and so does a refused
/// external commit or reset. A member's commit the validator refused (`invalid`) is dropped. One
/// refused otherwise stays staged: the server may have taken it after all (a lost answer, then a
/// retry's 409), so `apply` settles it from the queue. It merges it when the queue brings it back,
/// and drops it when another commit takes its epoch, or a server proposal at its epoch shows it
/// can't have entered. Until then this device makes no other commit (`pending_commit`). A commit
/// left so is dropped by a later word that the validator refused it (`invalid`), which a client
/// that knows it never sent the commit gives too: its bytes are lost, and only another member's
/// commit would settle it.
pub(crate) fn commit_result(tx: &Tx<'_>, request: CommitResult) -> Result<Epoch, Error> {
    let conversation = request.conversation_id;
    match request.seq {
        None if request.accepted => {
            return Err(invalid("seq", "an accepted commit comes with its number"));
        }
        Some(seq) if i64::try_from(seq).is_err() => {
            return Err(invalid("seq", "the commit's number is out of range"));
        }
        _ => {}
    }
    let mut row = GroupRow::read(tx, conversation)?.ok_or_else(|| not_found("group"))?;
    let Some(pending) = row.pending.take() else {
        if !request.accepted && request.invalid {
            return drop_staged(tx, row);
        }
        return Err(not_found("commit"));
    };
    let generation = match pending {
        Pending::Reset => row
            .generation
            .checked_add(1)
            .ok_or_else(|| Error::Internal("the conversation's generations ran out".into()))?,
        Pending::Create | Pending::Commit | Pending::External => row.generation,
    };
    let provider = tx.provider();
    let mut group = MlsGroup::load(provider.storage(), &group_id(conversation, generation))
        .map_err(storage_error)?
        .ok_or_else(|| Error::Internal("the waiting commit's group isn't stored".into()))?;

    if !request.accepted {
        if pending == Pending::Commit {
            if request.invalid {
                row.echo = None;
                group
                    .clear_pending_commit(provider.storage())
                    .map_err(storage_error)?;
            }
            // Otherwise OpenMLS keeps the commit staged, and the row its echo, for `apply`.
            row.write(tx)?;
            return Ok(Epoch {
                epoch: Some(group.epoch().as_u64()),
            });
        }
        row.echo = None;
        group.delete(provider.storage()).map_err(storage_error)?;
        if pending == Pending::Create {
            GroupRow::delete(tx, conversation)?;
        } else {
            row.write(tx)?;
        }
        return Ok(Epoch { epoch: None });
    }

    // The leaves before: the devices a commit takes out, or a reset leaves out of the generation
    // before, are noted.
    let before = match pending {
        Pending::Commit => Some(leaves(group.members()).map_err(|_| stored_state())?),
        Pending::Reset => stored_group(tx, conversation, row.generation)?
            .map(|old| leaves(old.members()).map_err(|_| stored_state()))
            .transpose()?,
        Pending::Create | Pending::External => None,
    };
    if pending != Pending::External {
        group
            .merge_pending_commit(provider)
            .map_err(openmls_error)?;
    }
    if let Some(before) = before {
        note_removed(tx, conversation, &before, &group)?;
    }
    if pending == Pending::Reset {
        delete_group(tx, conversation, row.generation)?;
        row.generation = generation;
        row.blocked = false;
    }
    own_merged(tx, &mut row, &group)?;
    // A new group's creator and an external joiner count the queue from their commit. A device that
    // counts it already takes the commit there, in order, after what comes before it.
    if matches!(pending, Pending::Create | Pending::External) {
        row.last_seq = request.seq;
        // A creator's clock can't misplace its start: nothing comes before epoch 0. An external
        // joiner's could, so its stay begins at the first time the API gives.
        let at = (pending == Pending::Create).then(|| tx.now());
        crate::backup::entered(tx, conversation, at)?;
        drop_record(tx, conversation)?;
    }
    row.write(tx)?;
    Ok(Epoch {
        epoch: Some(group.epoch().as_u64()),
    })
}

/// Drops this device's commit left staged after the server's word on it, which never entered.
fn drop_staged(tx: &Tx<'_>, mut row: GroupRow) -> Result<Epoch, Error> {
    let staged = stored_group(tx, row.conversation, row.generation)?
        .filter(|group| group.pending_commit().is_some());
    let Some(mut group) = staged else {
        return Err(not_found("commit"));
    };
    group
        .clear_pending_commit(tx.provider().storage())
        .map_err(storage_error)?;
    row.echo = None;
    row.write(tx)?;
    Ok(Epoch {
        epoch: Some(group.epoch().as_u64()),
    })
}

/// Commits the removals the server proposed, with the leave statements that came with them, and
/// takes out every member's leaves whose devices are off their users' latest lists as this device
/// knows them: what `encrypt` asks for first when it answers `pending_proposals`. Nothing pending is
/// `not_found` (`proposals`).
pub(crate) fn commit_pending(tx: &Tx<'_>, request: ConversationId) -> Result<Committed, Error> {
    let (group, row) = load_group(tx, request.conversation_id)?;
    can_commit(&group, &row)?;
    if !removals_waiting(tx, &group)? {
        return Err(not_found("proposals"));
    }
    own_commit(tx, group, row)
}

/// Renews this device's leaf with a commit that has a path, with whatever is pending.
pub(crate) fn refresh(tx: &Tx<'_>, request: ConversationId) -> Result<Committed, Error> {
    let (group, row) = load_group(tx, request.conversation_id)?;
    can_commit(&group, &row)?;
    own_commit(tx, group, row)
}

fn own_commit(tx: &Tx<'_>, mut group: MlsGroup, mut row: GroupRow) -> Result<Committed, Error> {
    let own = tx.own_device()?;
    let draft = draft(tx, &group, &row, Vec::new(), &[], &[])?;
    let staged = stage(tx, &mut group, &own, draft, Extra::default())?;
    row.staged(Pending::Commit, &staged);
    row.write(tx)?;
    Ok(Committed {
        commit: staged.commit,
        group_info: staged.group_info,
    })
}

/// The conversations whose group this device's leaf is due to renew in (`refresh`): 7 days after
/// it was last new, by the core's clock, where the device can commit.
pub(crate) fn refresh_due(tx: &Tx<'_>) -> Result<Due, Error> {
    let before = tx.now().saturating_sub(REFRESH_AFTER_MS);
    let mut candidates = Vec::new();
    for conversation in tx
        .conn()
        .prepare(
            "SELECT conversation_id FROM groups WHERE pending IS NULL AND blocked = 0 \
             AND leaf_updated_at <= ?1 ORDER BY leaf_updated_at, conversation_id",
        )?
        .query_map([before], |row| row.get::<_, Vec<u8>>(0))?
    {
        candidates.push(stored_uuid(&conversation?)?);
    }
    let mut conversations = Vec::new();
    for conversation in candidates {
        match load_group(tx, conversation) {
            Ok((group, row)) => {
                if can_commit(&group, &row).is_ok() {
                    conversations.push(conversation);
                }
            }
            // Not in the group any more: nothing to renew.
            Err(Error::NotFound { .. }) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Due { conversations })
}

/// Joins the conversation's group at `generation` with an external commit on the group info the
/// API serves: a device on its user's list whose user is a member, coming back after it was
/// removed or its state fell behind, or new to the group. Whatever this device had of the group
/// goes, and the queue counts again from this commit. The group it enters is held to the rules
/// first, to the client's record of a conversation from before the cutover, as a welcome's is, and
/// to the API's key as its one external sender when the client gives it. Merged as it's made, it
/// waits for `commit_result` all the same.
pub(crate) fn join_external(tx: &Tx<'_>, request: JoinExternal) -> Result<Committed, Error> {
    let conversation = request.conversation_id;
    let api = request
        .external_sender
        .as_deref()
        .map(api_key)
        .transpose()?;
    let own = tx.own_device()?;
    let credential = own.credential()?;
    let info = match MlsMessageIn::tls_deserialize_exact_bytes(&request.group_info)
        .map(MlsMessageIn::extract)
    {
        Ok(MlsMessageBodyIn::GroupInfo(info)) => info,
        _ => {
            return Err(invalid(
                "group_info",
                "the group info isn't an MLS group info",
            ));
        }
    };
    if info.group_id() != &group_id(conversation, request.generation) {
        return Err(invalid(
            "group_info",
            "the group info is another conversation's or generation's",
        ));
    }
    let row = GroupRow::read(tx, conversation)?;
    if let Some(row) = &row {
        if row.pending.is_some() {
            return Err(Error::PendingCommit);
        }
        if row.generation > request.generation {
            return Err(invalid(
                "generation",
                "the conversation is at a later generation",
            ));
        }
        if row.blocked && row.generation == request.generation {
            return Err(Error::RuleViolation {
                rule: super::GROUP_BLOCKED.into(),
            });
        }
        // A group info of an epoch this device saw pass: every member of that epoch, a removed one
        // too, could read the group an external commit on it makes. The same epoch stays open, as
        // a refused join's retry needs.
        if row.generation == request.generation && info.epoch().as_u64() < row.epoch {
            return Err(Error::RuleViolation {
                rule: "stale_group_info".into(),
            });
        }
    }
    // This device must be on its user's list as it knows it, as every member checks.
    let listed = tx
        .device_list_of(own.user)?
        .is_some_and(|list| list.contains(own.device));
    if !listed {
        return Err(violation(duvet_e2e_rules::RuleViolation::DeviceNotListed));
    }

    // The epoch the group info shows is one this device has now seen.
    let seen = match &row {
        Some(row) if row.generation == request.generation => row.epoch.max(info.epoch().as_u64()),
        _ => info.epoch().as_u64(),
    };

    if let Some(row) = &row {
        delete_group(tx, conversation, row.generation)?;
    }
    delete_group(tx, conversation, request.generation)?;
    let provider = tx.provider();
    let (group, bundle) = MlsGroup::external_commit_builder()
        .with_config(join_config())
        .with_aad(CommitAad::new(Vec::new()).encode())
        // A leaf a device that never came back left in the tree must not keep anyone out.
        .skip_lifetime_validation()
        .build_group(provider, info, credential)
        .map_err(|error| match error {
            ExternalCommitBuilderError::PublicGroupError(
                CreationFromExternalError::InvalidGroupInfoSignature,
            ) => Error::InvalidSignature {
                what: "group_info".into(),
            },
            ExternalCommitBuilderError::PublicGroupError(
                CreationFromExternalError::WriteToStorageError(error),
            )
            | ExternalCommitBuilderError::StorageError(error) => storage_error(error),
            _ => invalid("group_info", "the group info doesn't make a group"),
        })?
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(leaf_capabilities())
                .build(),
        )
        .load_psks(provider.storage())
        .map_err(openmls_error)?
        .build(provider.rand(), provider.crypto(), &own.signer, |_| true)
        .map_err(openmls_error)?
        .finalize(provider)
        .map_err(openmls_error)?;

    // The group this device enters, as a welcome's: every leaf certified by its user's pinned
    // identity (or by the certificate it signed for the same device), its user a member, this
    // device's own among them.
    let context = group.public_group().group_context();
    if let Some(key) = &api
        && !external_sender_is(context, key)
    {
        return Err(Error::RuleViolation {
            rule: EXTERNAL_SENDER_MISMATCH.into(),
        });
    }
    let mut leaves = leaves(group.members()).map_err(violation)?;
    certify_leaves_by_pinned(tx, &mut leaves)?;
    let mut ctx = rule_context(tx, leaves.values().map(|leaf| leaf.user))?;
    if let Some(record) = &request.expected {
        record.hold(&mut ctx, request.generation, false);
    }
    check_joined_state(&ctx, context, &leaves).map_err(violation)?;

    let commit = tls(bundle.commit())?;
    let group_info = bundle
        .group_info()
        .ok_or_else(|| Error::Internal("the commit came without its group info".into()))?;
    let group_info = tls(&MlsMessageOut::from(group_info.clone()))?;
    GroupRow {
        conversation,
        generation: request.generation,
        last_seq: None,
        // Its own epoch once the server takes the commit (`commit_result`).
        epoch: seen,
        members: MemberList::from_group_context(context).map_err(|_| stored_state())?,
        blocked: false,
        leaf_updated_at: tx.now(),
        pending: Some(Pending::External),
        echo: Some(digest(&commit)),
        statements: Vec::new(),
    }
    .write(tx)?;
    Ok(Committed { commit, group_info })
}

/// Leaves the group this device holds of the conversation, for a client whose API holds none, or
/// holds another one at the device's generation (`apply`'s `another_group`): the conversation's row
/// goes (its numbers, its epoch, its members, its statements), and so does the group's MLS state,
/// as a group founded again at its generation has its ID. What waits to send there is stale
/// (`messages::group_forgotten`), and the messages it holds stay. It answers the members the group
/// had, without those whose leave statements it holds, with its owner in a group, for the client
/// to hold what brings the group back to (`expected`: `create_group`, `apply`'s welcomes,
/// `join_external`), so nobody the forgotten group didn't have comes in on the API's word alone.
/// It keeps that record too ([`keep_record`]): a client that closes before it keeps its own copy
/// takes it back ([`forgotten`]). Not while a commit of this device's waits for the server's word,
/// or for the queue after a refusal (`pending_commit`); and only a group this device is in
/// (`not_found`, as [`load_group`] names it).
pub(crate) fn forget_group(tx: &Tx<'_>, request: ConversationId) -> Result<Forgotten, Error> {
    let conversation = request.conversation_id;
    let (mut group, row) = load_group(tx, conversation)?;
    if row.pending.is_some() || group.pending_commit().is_some() {
        return Err(Error::PendingCommit);
    }
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    // Without the users whose leave statements this device holds, whom the API took off as they
    // left: a leaving owner's place goes to the first of those who stay, as the API gives it.
    let left = row.leavers();
    let staying: Vec<Entry> = list
        .users
        .iter()
        .filter(|entry| !left.contains(&entry.user))
        .copied()
        .collect();
    let owner = match list.owner {
        Some(owner) if left.contains(&owner) => staying.first().map(|entry| entry.user),
        owner => owner,
    };
    let list = MemberList::new(list.kind, owner, staying);
    group
        .delete(tx.provider().storage())
        .map_err(storage_error)?;
    GroupRow::delete(tx, conversation)?;
    crate::messages::group_forgotten(tx, conversation)?;
    let expected = Expected::of(&list);
    keep_record(tx, conversation, &expected)?;
    Ok(Forgotten { expected })
}

/// Keeps `expected`, the record of the group this device forgets of `conversation`, as the forget
/// answers it, in the forget's own transaction, until the device holds the group again or its
/// client lets the record go ([`drop_record`]): a client that closes before it keeps its own copy
/// takes it back ([`forgotten`]). A forget needs the group held, and the device holds it again only
/// once the conversation's last record went, so a second forget writes the newer group's where
/// there's none left.
fn keep_record(tx: &Tx<'_>, conversation: Uuid, expected: &Expected) -> Result<(), Error> {
    let record = serde_json::to_string(expected)
        .map_err(|_| Error::Internal("a forgotten group's record couldn't be written".into()))?;
    // The upsert is a defense: no command leaves a record here, as above. A row anything else left
    // gives way to the record this forget answers.
    tx.conn().execute(
        "INSERT INTO forgotten_groups (conversation_id, record) VALUES (?1, ?2) \
         ON CONFLICT (conversation_id) DO UPDATE SET record = excluded.record",
        params![conversation.as_bytes().as_slice(), record],
    )?;
    Ok(())
}

/// The record of `conversation`'s forgotten group goes, in this transaction: this device holds the
/// group again (a welcome brought it in, `apply`; or the server took its founding or its external
/// join, `commit_result`), or its client lets the record go ([`drop_forgotten`]). While the device
/// holds no group of the conversation (a join the server refused, which leaves a row alone; a
/// founding or a join still waiting for the server's word), the record stays.
pub(super) fn drop_record(tx: &Tx<'_>, conversation: Uuid) -> Result<(), Error> {
    tx.conn().execute(
        "DELETE FROM forgotten_groups WHERE conversation_id = ?1",
        [conversation.as_bytes().as_slice()],
    )?;
    Ok(())
}

/// Lets go of the record of `conversation`'s forgotten group, which [`forgotten`] then no longer
/// gives; with nothing kept, it changes nothing. A client calls it on its person's yes
/// (`members_accept`), before the comeback without `expected` goes, so every record `forgotten`
/// gives is newer than any yes; and once the API no longer lists the conversation for its user.
pub(crate) fn drop_forgotten(tx: &Tx<'_>, request: ConversationId) -> Result<Empty, Error> {
    drop_record(tx, request.conversation_id)?;
    Ok(Empty {})
}

/// The record of each group this device forgot (`forget_group`), by conversation, each as the
/// forget answered it: a client that lost its own copy, by a close before it wrote it or a store
/// that refused it, takes it again as it starts. It changes nothing.
pub(crate) fn forgotten(tx: &Tx<'_>) -> Result<ForgottenGroups, Error> {
    let mut statement = tx
        .conn()
        .prepare("SELECT conversation_id, record FROM forgotten_groups ORDER BY conversation_id")?;
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut records = Vec::new();
    for row in rows {
        let (conversation, record) = row?;
        records.push(ForgottenGroup {
            conversation_id: stored_uuid(&conversation)?,
            expected: serde_json::from_str(&record)
                .map_err(|_| Error::Internal("a forgotten group's record is malformed".into()))?,
        });
    }
    Ok(ForgottenGroups { records })
}

/// The group as this device has it.
pub(crate) fn group(tx: &Tx<'_>, request: ConversationId) -> Result<GroupState, Error> {
    let (group, row) = load_group(tx, request.conversation_id)?;
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    let devices = leaves(group.members())
        .map_err(|_| stored_state())?
        .into_iter()
        .map(|(leaf, device)| Device {
            user_id: device.user,
            device_id: device.device,
            leaf,
        })
        .collect();
    Ok(GroupState {
        generation: row.generation,
        epoch: group.epoch().as_u64(),
        kind: list.kind,
        owner: list.owner,
        members: list
            .users
            .iter()
            .map(|entry| Member {
                user_id: entry.user,
                generation: entry.generation,
                epoch: entry.epoch,
            })
            .collect(),
        devices,
        authenticator: group.epoch_authenticator().as_slice().to_vec(),
        blocked: row.blocked,
    })
}
