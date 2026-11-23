//! Duvet's group rules: the core checks every commit with them as it applies it, and the API's
//! validator as it accepts it.

mod extract;
mod identity;
mod members;
mod rules;
mod signed;

use openmls::prelude::{
    Capabilities, Ciphersuite, Extension, ExtensionType, Extensions, ExternalSender, GroupId,
    MlsGroupCreateConfig, MlsGroupJoinConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
    RequiredCapabilitiesExtension,
};
use uuid::Uuid;

pub use extract::{
    Committer, Leaf, Leaves, MembershipChange, NewLeaf, Removed, extract_change, leaves,
};
pub use identity::{DeviceCertificate, DeviceList, LeaveStatement};
pub use members::{CommitAad, Entry, Kind, MAX_MEMBERS, MEMBER_LIST_EXTENSION, MemberList};
pub use rules::{
    Place, RuleContext, RuleViolation, certified, check_change, check_joined_state, check_state,
    is_record, keeps_record, signed_for, statement_user, unlisted_candidates,
};
pub use signed::{
    DEVICE_CERTIFICATE, DEVICE_LIST, DIRECT_MESSAGE, HISTORY_SHARE, LEAVE, sign, verify,
};

/// Duvet's one ciphersuite, 0x0001: X25519, AES-128-GCM, SHA-256 and Ed25519.
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// The past epochs a group keeps secrets for, so a message that arrives late still opens.
pub const MAX_PAST_EPOCHS: usize = 5;

/// A conversation's MLS group ID: its 16 bytes, then its generation (u32, big-endian).
pub fn group_id(conversation: Uuid, generation: u32) -> GroupId {
    let mut id = conversation.as_bytes().to_vec();
    id.extend_from_slice(&generation.to_be_bytes());
    GroupId::from_slice(&id)
}

/// The conversation and the generation a group ID names.
pub fn group_id_parts(id: &GroupId) -> Result<(Uuid, u32), RuleViolation> {
    let (conversation, generation) = id
        .as_slice()
        .split_first_chunk::<16>()
        .ok_or(RuleViolation::Malformed)?;
    let generation: [u8; 4] = generation
        .try_into()
        .map_err(|_| RuleViolation::Malformed)?;
    Ok((
        Uuid::from_bytes(*conversation),
        u32::from_be_bytes(generation),
    ))
}

/// What every leaf supports: Duvet's suite, the member list, and last-resort key packages.
pub fn leaf_capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![SUITE])
        .extensions(vec![
            ExtensionType::Unknown(MEMBER_LIST_EXTENSION),
            ExtensionType::LastResort,
        ])
        .build()
}

/// What a group requires of every leaf: the member list, and nothing else.
pub(crate) fn required_capabilities() -> RequiredCapabilitiesExtension {
    RequiredCapabilitiesExtension::new(&[ExtensionType::Unknown(MEMBER_LIST_EXTENSION)], &[], &[])
}

/// A conversation's new group: Duvet's suite, commits in the clear so the API can check them
/// (application messages stay encrypted), the member list in the context and required of every
/// leaf, and the API as the one external sender.
pub fn group_config(members: &MemberList, external_sender: ExternalSender) -> MlsGroupCreateConfig {
    let extensions = Extensions::from_vec(vec![
        members.to_extension(),
        Extension::RequiredCapabilities(required_capabilities()),
        Extension::ExternalSenders(vec![external_sender]),
    ])
    .expect("three different extensions, each valid in a group context");
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .capabilities(leaf_capabilities())
        .with_group_context_extensions(extensions)
        .build()
}

/// How a device joins a conversation's group, by welcome or by external commit.
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(MAX_PAST_EPOCHS)
        .use_ratchet_tree_extension(true)
        .build()
}
