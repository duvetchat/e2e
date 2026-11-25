//! A conversation's group from its start: epoch 0 and the first commit, for a new conversation or
//! for the conversation's next generation.

use std::collections::BTreeMap;

use duvet_e2e_rules::{Entry, Kind, MemberList, RuleViolation, group_config, group_id, is_record};
use openmls::prelude::{BasicCredential, ExternalSender, MlsGroup, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::apply::Expected;
use super::{
    Draft, Extra, GroupRow, Pending, Skipped, Staged, api_key, choose, load_group, openmls_error,
    stage, tls, violation,
};
use crate::protocol::b64;
use crate::{Error, Tx};

/// The credential that names the API as an external sender: the rules know it by its key alone.
const API_CREDENTIAL: &[u8] = b"duvet";

#[derive(Debug, Deserialize)]
pub(crate) struct CreateGroup {
    conversation_id: Uuid,
    kind: Kind,
    #[serde(default)]
    owner: Option<Uuid>,
    /// The conversation's members as the API has them, in the order they entered.
    members: Vec<Uuid>,
    /// Key packages of the members' devices, by user.
    #[serde(default)]
    key_packages: BTreeMap<Uuid, Vec<b64::Bytes>>,
    /// The API's Ed25519 public key, the group's one external sender.
    #[serde(with = "b64")]
    external_sender: Vec<u8>,
    /// A conversation from before the cutover, whose epoch 0 any member may make.
    #[serde(default)]
    legacy: bool,
    /// For a conversation from before the cutover: the client's own record of it, as a welcome
    /// entry's `expected`, which the members given must be.
    #[serde(default)]
    expected: Option<Expected>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResetGroup {
    conversation_id: Uuid,
    /// The group's owner as the API has it; a DM has none.
    #[serde(default)]
    owner: Option<Uuid>,
    /// The conversation's members as the API has them, in the order they entered.
    members: Vec<Uuid>,
    /// Key packages of the members' devices, by user.
    #[serde(default)]
    key_packages: BTreeMap<Uuid, Vec<b64::Bytes>>,
}

#[derive(Serialize)]
pub(crate) struct Created {
    generation: u32,
    /// Epoch 0's group info, with its tree: the validator's `create` takes it with the commit.
    #[serde(with = "b64")]
    initial_group_info: Vec<u8>,
    #[serde(with = "b64")]
    commit: Vec<u8>,
    #[serde(with = "b64::option")]
    welcome: Option<Vec<u8>>,
    /// The group info of the epoch the commit makes.
    #[serde(with = "b64")]
    group_info: Vec<u8>,
    skipped_devices: Vec<Skipped>,
}

/// A new conversation's group: epoch 0, with the members and owner the API gives, and the first
/// commit, which brings in every device on their signed lists with a valid key package, waiting
/// for `commit_result`. The owner makes it, but in a DM or a conversation from before the cutover,
/// whose list must then be the API's, and the client's record of it when it passes one.
pub(crate) fn create_group(tx: &Tx<'_>, request: CreateGroup) -> Result<Created, Error> {
    let conversation = request.conversation_id;
    if GroupRow::read(tx, conversation)?.is_some() {
        return Err(Error::Exists {
            what: "group".into(),
        });
    }
    let key = api_key(&request.external_sender)?;
    let entries = request
        .members
        .iter()
        .map(|&user| Entry {
            user,
            generation: 0,
            epoch: 0,
        })
        .collect();
    let list = MemberList::new(request.kind, request.owner, entries);
    // The group this device founds holds its members to the client's record, as the founding
    // welcome holds every other member's device to theirs.
    if let Some(record) = &request.expected
        && !is_record(&list, &record.list(0))
    {
        return Err(violation(RuleViolation::MemberListMismatch));
    }
    let api = ExternalSender::new(
        key.as_slice().into(),
        BasicCredential::new(API_CREDENTIAL.to_vec()).into(),
    );
    let extra = Extra {
        expected_initial: request.legacy.then(|| list.clone()),
        external_sender: Some(key.to_vec()),
    };
    let first = start(
        tx,
        conversation,
        0,
        &list,
        api,
        &request.key_packages,
        extra,
    )?;
    let mut row = GroupRow {
        conversation,
        generation: 0,
        last_seq: None,
        epoch: 0,
        members: list,
        blocked: false,
        leaf_updated_at: tx.now(),
        pending: None,
        echo: None,
        statements: Vec::new(),
    };
    row.staged(Pending::Create, &first.staged);
    row.write(tx)?;
    Ok(first.reply(0))
}

/// The conversation's group again, at its next generation: epoch 0 with the members and owner the
/// API gives, and a first commit, as a new conversation's. The way out of a group a commit that
/// broke the rules blocked: its owner makes it (in a DM, either member), and the members take it
/// as an epoch 0 with their list, without whoever left. A user can leave while a commit that would
/// take their leaf out can't come (a blocked group takes none), and the API, which took them off
/// at once, holds epoch 0 to its members: so a reset goes by those, and the owner the API named
/// when the owner left. It brings no one in: the members must be what [`founds_reset`] takes from
/// the group's, or the reset is `rule_violation` `member_list_mismatch`. The current generation's
/// group stays until the server takes the new one. A device without the group can't reset it
/// (`not_found`): it has no members to hold the API's to.
pub(crate) fn reset_group(tx: &Tx<'_>, request: ResetGroup) -> Result<Created, Error> {
    let conversation = request.conversation_id;
    let (group, mut row) = load_group(tx, conversation)?;
    if row.pending.is_some() {
        return Err(Error::PendingCommit);
    }
    let api = group
        .extensions()
        .external_senders()
        .and_then(|senders| senders.first())
        .cloned()
        .ok_or_else(|| Error::Internal("the group has no external sender".into()))?;
    let generation = row
        .generation
        .checked_add(1)
        .ok_or_else(|| Error::Internal("the conversation's generations ran out".into()))?;
    let current = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| super::stored_state())?;
    let entries = request
        .members
        .iter()
        .map(|&user| Entry {
            user,
            generation,
            epoch: 0,
        })
        .collect();
    let list = MemberList::new(current.kind, request.owner, entries);
    if !founds_reset(&current, &list) {
        return Err(violation(RuleViolation::MemberListMismatch));
    }
    let first = start(
        tx,
        conversation,
        generation,
        &list,
        api,
        &request.key_packages,
        Extra::default(),
    )?;
    row.staged(Pending::Reset, &first.staged);
    row.write(tx)?;
    Ok(first.reply(generation))
}

/// Whether a reset may found the next generation of a group whose list is `current` with `next`:
/// the same kind, and the group's users in the order they entered without those who left, so it
/// brings no one in (only the owner's commit adds a user); a DM's two users; and a group's owner,
/// the one it has while they stay, else the first of those who stay, as when an owner leaves (the
/// API's choice too: who joined first). Who left is the API's word, which the validator holds
/// epoch 0 to: no statement shows it, as a blocked group takes no commit to carry one. What the
/// owner makes this way, the members that hold the group take (`apply`'s welcomes).
pub(crate) fn founds_reset(current: &MemberList, next: &MemberList) -> bool {
    let users: Vec<Uuid> = next.users.iter().map(|entry| entry.user).collect();
    let staying: Vec<Uuid> = current
        .users
        .iter()
        .map(|entry| entry.user)
        .filter(|&user| next.contains(user))
        .collect();
    let owned = match next.kind {
        Kind::Dm => next.owner.is_none() && users.len() == current.users.len(),
        Kind::Group => {
            let successor = match current.owner {
                Some(owner) if next.contains(owner) => Some(owner),
                _ => users.first().copied(),
            };
            next.owner.is_some() && next.owner == successor
        }
    };
    next.kind == current.kind && users == staying && owned
}

/// Epoch 0 and the first commit, staged.
struct First {
    initial_group_info: Vec<u8>,
    staged: Staged,
    skipped: Vec<Skipped>,
}

impl First {
    fn reply(self, generation: u32) -> Created {
        Created {
            generation,
            initial_group_info: self.initial_group_info,
            commit: self.staged.commit,
            welcome: self.staged.welcome,
            group_info: self.staged.group_info,
            skipped_devices: self.skipped,
        }
    }
}

/// Epoch 0 of `conversation`'s group at `generation`, with `list` as its members and `api` as its
/// external sender, and its first commit, which adds every device on the members' signed lists
/// that has a valid key package: staged, and held to the rules from epoch 0 on.
fn start(
    tx: &Tx<'_>,
    conversation: Uuid,
    generation: u32,
    list: &MemberList,
    api: ExternalSender,
    offered: &BTreeMap<Uuid, Vec<b64::Bytes>>,
    extra: Extra,
) -> Result<First, Error> {
    let own = tx.own_device()?;
    let credential = own.credential()?;
    let users: Vec<Uuid> = list.users.iter().map(|entry| entry.user).collect();
    let (adds, skipped) = choose(tx, own.device, &users, offered)?;
    let provider = tx.provider();
    let mut group = MlsGroup::new_with_group_id(
        provider,
        &own.signer,
        &group_config(list, api),
        group_id(conversation, generation),
        credential,
    )
    .map_err(openmls_error)?;
    let initial = group
        .export_group_info(provider.crypto(), &own.signer, true)
        .map_err(openmls_error)?;
    let draft = Draft {
        adds,
        ..Draft::default()
    };
    let staged = stage(tx, &mut group, &own, draft, extra)?;
    Ok(First {
        initial_group_info: tls(&initial)?,
        staged,
        skipped,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(kind: Kind, owner: Option<Uuid>, users: &[Uuid]) -> MemberList {
        let entries = users
            .iter()
            .map(|&user| Entry {
                user,
                generation: 1,
                epoch: 0,
            })
            .collect();
        MemberList::new(kind, owner, entries)
    }

    #[test]
    fn a_reset_founds_the_group_without_those_who_left() {
        let [a, b, c, d] = [1, 2, 3, 4].map(Uuid::from_u128);
        let group = list(Kind::Group, Some(a), &[a, b, c]);
        let founds = |owner, users: &[Uuid]| founds_reset(&group, &list(Kind::Group, owner, users));
        // The users who stay, in the order they entered, with the owner while they stay, else the
        // first of those who stay.
        assert!(founds(Some(a), &[a, b, c]));
        assert!(founds(Some(a), &[a, c]));
        assert!(founds(Some(b), &[b, c]));
        assert!(founds(Some(c), &[c]));
        // No one new, no one twice, no other order, no other owner, and a group has one.
        assert!(!founds(Some(a), &[a, b, c, d]));
        assert!(!founds(Some(a), &[a, b, b]));
        assert!(!founds(Some(a), &[a, c, b]));
        assert!(!founds(Some(b), &[a, b]));
        assert!(!founds(Some(c), &[b, c]));
        assert!(!founds(Some(d), &[a, b]));
        assert!(!founds(None, &[a, b]));
        assert!(!founds(None, &[]));
        assert!(!founds_reset(&group, &list(Kind::Dm, None, &[a, b])));

        // A DM keeps its two users, and has no owner.
        let dm = list(Kind::Dm, None, &[a, b]);
        assert!(founds_reset(&dm, &list(Kind::Dm, None, &[a, b])));
        assert!(!founds_reset(&dm, &list(Kind::Dm, None, &[a])));
        assert!(!founds_reset(&dm, &list(Kind::Dm, None, &[a, c])));
        assert!(!founds_reset(&dm, &list(Kind::Dm, None, &[b, a])));
        assert!(!founds_reset(&dm, &list(Kind::Dm, Some(a), &[a, b])));
        assert!(!founds_reset(&dm, &list(Kind::Group, Some(a), &[a, b])));
    }
}
