//! Who is in a conversation: the owner adds and removes users, and a user leaves with their word.

use std::collections::{BTreeMap, BTreeSet};

use duvet_e2e_rules::{LeaveStatement, MemberList};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    ConversationId, Extra, Pending, Skipped, can_commit, choose, draft, load_group, stage,
    stored_state,
};
use crate::identity::{invalid, not_found};
use crate::protocol::b64;
use crate::{Error, Tx};

#[derive(Debug, Deserialize)]
pub(crate) struct AddMembers {
    conversation_id: Uuid,
    users: Vec<NewMember>,
}

#[derive(Debug, Deserialize)]
struct NewMember {
    user_id: Uuid,
    /// Key packages of the user's devices.
    #[serde(default)]
    key_packages: Vec<b64::Bytes>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RemoveMembers {
    conversation_id: Uuid,
    users: Vec<Uuid>,
}

#[derive(Serialize)]
pub(crate) struct Added {
    #[serde(with = "b64")]
    commit: Vec<u8>,
    #[serde(with = "b64::option")]
    welcome: Option<Vec<u8>>,
    #[serde(with = "b64")]
    group_info: Vec<u8>,
    skipped_devices: Vec<Skipped>,
}

/// A commit's messages, for a commit that welcomes no one.
#[derive(Serialize)]
pub(crate) struct Committed {
    #[serde(with = "b64")]
    pub(crate) commit: Vec<u8>,
    #[serde(with = "b64")]
    pub(crate) group_info: Vec<u8>,
}

#[derive(Serialize)]
pub(crate) struct Left {
    #[serde(with = "b64")]
    statement: Vec<u8>,
}

/// The owner adds `users`: each one enters the list, entered now, with every device on their
/// signed list that has a valid key package. The commit waits for `commit_result`.
pub(crate) fn add_members(tx: &Tx<'_>, request: AddMembers) -> Result<Added, Error> {
    let (mut group, mut row) = load_group(tx, request.conversation_id)?;
    can_commit(&group, &row)?;
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    let users: Vec<Uuid> = request.users.iter().map(|user| user.user_id).collect();
    let distinct: BTreeSet<Uuid> = users.iter().copied().collect();
    if distinct.len() != users.len() || users.iter().any(|user| list.contains(*user)) {
        return Err(Error::Exists {
            what: "member".into(),
        });
    }
    let offered: BTreeMap<Uuid, Vec<b64::Bytes>> = request
        .users
        .into_iter()
        .map(|user| (user.user_id, user.key_packages))
        .collect();
    let own = tx.own_device()?;
    let (adds, skipped) = choose(tx, own.device, &users, &offered)?;
    let draft = draft(tx, &group, &row, adds, &users, &[])?;
    let staged = stage(tx, &mut group, &own, draft, Extra::default())?;
    row.staged(Pending::Commit, &staged);
    row.write(tx)?;
    Ok(Added {
        commit: staged.commit,
        welcome: staged.welcome,
        group_info: staged.group_info,
        skipped_devices: skipped,
    })
}

/// The owner removes `users`, all their devices with them. A user leaves on their own with
/// `leave`, this device's user too. The commit waits for `commit_result`.
pub(crate) fn remove_members(tx: &Tx<'_>, request: RemoveMembers) -> Result<Committed, Error> {
    let (mut group, mut row) = load_group(tx, request.conversation_id)?;
    can_commit(&group, &row)?;
    let own = tx.own_device()?;
    if request.users.contains(&own.user) {
        return Err(invalid("users", "this device's own user leaves with leave"));
    }
    let list = MemberList::from_group_context(group.public_group().group_context())
        .map_err(|_| stored_state())?;
    if request.users.iter().any(|user| !list.contains(*user)) {
        return Err(not_found("member"));
    }
    let draft = draft(tx, &group, &row, Vec::new(), &[], &request.users)?;
    let staged = stage(tx, &mut group, &own, draft, Extra::default())?;
    row.staged(Pending::Commit, &staged);
    row.write(tx)?;
    Ok(Committed {
        commit: staged.commit,
        group_info: staged.group_info,
    })
}

/// This device's user's word that they leave the conversation, signed by this device, for the
/// server: it proposes the removal of their devices, and the commit that makes it, any member's,
/// carries the statement and takes the user off the list.
pub(crate) fn leave(tx: &Tx<'_>, request: ConversationId) -> Result<Left, Error> {
    let (group, row) = load_group(tx, request.conversation_id)?;
    let own = tx.own_device()?;
    let statement = LeaveStatement::new(
        own.user,
        row.conversation,
        row.generation,
        group.epoch().as_u64(),
        own.device,
    )
    .sign(&own.signer)
    .map_err(|_| Error::Internal("the device couldn't sign".into()))?;
    Ok(Left { statement })
}
