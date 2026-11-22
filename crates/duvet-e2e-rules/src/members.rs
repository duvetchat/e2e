//! A conversation's members, kept in the group's context, and what a commit carries in its
//! authenticated data.

use openmls::prelude::{Extension, GroupContext, UnknownExtension};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use uuid::Uuid;

use crate::RuleViolation;
use crate::signed::{decode, encode};

/// The member list's extension type, in RFC 9420's private range.
pub const MEMBER_LIST_EXTENSION: u16 = 0xF0D1;

/// The most people a conversation holds.
pub const MAX_MEMBERS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Dm,
    Group,
}

/// When a user entered the conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub user: Uuid,
    pub generation: u32,
    pub epoch: u64,
}

/// The conversation's members, in the order they entered, and its owner (a DM has none).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberList {
    pub v: u32,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Uuid>,
    pub users: Vec<Entry>,
}

impl MemberList {
    pub fn new(kind: Kind, owner: Option<Uuid>, users: Vec<Entry>) -> Self {
        Self {
            v: 1,
            kind,
            owner,
            users,
        }
    }

    /// The list as the group context's extension.
    pub fn to_extension(&self) -> Extension {
        Extension::Unknown(MEMBER_LIST_EXTENSION, UnknownExtension(encode(self)))
    }

    pub fn from_group_context(context: &GroupContext) -> Result<Self, RuleViolation> {
        let extension = context
            .extensions()
            .unknown(MEMBER_LIST_EXTENSION)
            .ok_or(RuleViolation::Malformed)?;
        let list: Self = decode(&extension.0)?;
        if list.v == 1 {
            Ok(list)
        } else {
            Err(RuleViolation::Malformed)
        }
    }

    pub fn entry(&self, user: Uuid) -> Option<&Entry> {
        self.users.iter().find(|entry| entry.user == user)
    }

    pub fn contains(&self, user: Uuid) -> bool {
        self.entry(user).is_some()
    }
}

/// A commit's authenticated data, which the API reads in the clear: the leave statements of the
/// users the commit takes out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitAad {
    pub v: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaves: Vec<ByteBuf>,
}

impl CommitAad {
    pub fn new(statements: Vec<Vec<u8>>) -> Self {
        Self {
            v: 1,
            leaves: statements.into_iter().map(ByteBuf::from).collect(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        encode(self)
    }

    /// The signed statements a commit's authenticated data carries; none when it has no data.
    pub fn statements(aad: &[u8]) -> Result<Vec<Vec<u8>>, RuleViolation> {
        if aad.is_empty() {
            return Ok(Vec::new());
        }
        let aad: Self = decode(aad)?;
        if aad.v != 1 {
            return Err(RuleViolation::Malformed);
        }
        Ok(aad.leaves.into_iter().map(ByteBuf::into_vec).collect())
    }
}
