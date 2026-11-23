//! A command's failure, and its stable code.

use serde_json::error::Category;
use serde_json::{Map, Value, json};

/// Why a command failed. Clients decide by [`Error::code`], which stays the same for each kind of failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("another instance has the database open")]
    Locked,
    #[error("the key doesn't open the database")]
    BadKey,
    /// The command isn't JSON, isn't a known command, or lacks a field it needs (`field`, when it's
    /// known). The message is fixed, so it never carries a value the command held.
    #[error("{message}")]
    BadCommand {
        message: &'static str,
        field: Option<String>,
    },
    #[error("{what} not found")]
    NotFound { what: String },
    #[error("{what} exists already")]
    Exists { what: String },
    /// The entry numbered `from` hasn't been applied, so the ones after it can't be.
    #[error("entry {from} is missing")]
    Gap { from: u64 },
    #[error("a commit waits for commit_result")]
    PendingCommit,
    #[error("removals are pending: commit them first with commit_pending")]
    PendingProposals,
    #[error("the identities of these users are missing: call observe_user")]
    NeedsIdentities { users: Vec<String> },
    #[error("the {what}'s signature doesn't verify")]
    InvalidSignature { what: String },
    #[error("the change breaks the rule {rule}")]
    RuleViolation { rule: String },
    #[error("the {kind} couldn't be decrypted")]
    DecryptFailed { kind: String },
    #[error("over the limit of {limit}")]
    TooLarge { limit: u64 },
    #[error("storage: {0}")]
    Storage(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// The failure's stable code.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Locked => "locked",
            Error::BadKey => "bad_key",
            Error::BadCommand { .. } => "bad_command",
            Error::NotFound { .. } => "not_found",
            Error::Exists { .. } => "exists",
            Error::Gap { .. } => "gap",
            Error::PendingCommit => "pending_commit",
            Error::PendingProposals => "pending_proposals",
            Error::NeedsIdentities { .. } => "needs_identities",
            Error::InvalidSignature { .. } => "invalid_signature",
            Error::RuleViolation { .. } => "rule_violation",
            Error::DecryptFailed { .. } => "decrypt_failed",
            Error::TooLarge { .. } => "too_large",
            Error::Storage(_) => "storage",
            Error::Internal(_) => "internal",
        }
    }

    /// The reply to a command that failed: `{"error": {"code", "message", ...extra}}`. The
    /// bindings answer a failed `open` with it too.
    pub fn to_reply(&self) -> Value {
        let mut error = Map::new();
        error.insert("code".into(), self.code().into());
        error.insert("message".into(), self.to_string().into());
        let extra = match self {
            Error::BadCommand {
                field: Some(field), ..
            } => Some(("field", json!(field))),
            Error::NotFound { what } | Error::InvalidSignature { what } => {
                Some(("what", json!(what)))
            }
            Error::Gap { from } => Some(("from", json!(from))),
            Error::NeedsIdentities { users } => Some(("users", json!(users))),
            Error::RuleViolation { rule } => Some(("rule", json!(rule))),
            Error::DecryptFailed { kind } => Some(("kind", json!(kind))),
            Error::TooLarge { limit } => Some(("limit", json!(limit))),
            _ => None,
        };
        if let Some((name, value)) = extra {
            error.insert(name.into(), value);
        }
        json!({ "error": error })
    }

    /// A command serde couldn't read. serde's message can quote the value it refused (a key, a
    /// message's text), so the reply says only what kind of failure it was, and the field serde
    /// names when its message starts with missing field `name` or unknown field `name`. The
    /// bindings read their own configuration with it.
    pub fn bad_command(error: serde_json::Error) -> Error {
        let message = match error.classify() {
            Category::Data => "the command's fields don't match",
            Category::Io | Category::Syntax | Category::Eof => "the command isn't valid JSON",
        };
        let text = error.to_string();
        let field = ["missing field `", "unknown field `"]
            .into_iter()
            .find_map(|prefix| text.strip_prefix(prefix)?.split_once('`'))
            .map(|(field, _)| field.to_owned());
        Error::BadCommand { message, field }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(error: rusqlite::Error) -> Self {
        Error::Storage(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_command_names_the_missing_field() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Request {
            user_id: String,
        }
        let error = Error::bad_command(serde_json::from_str::<Request>("{}").unwrap_err());
        assert_eq!(error.to_reply()["error"]["field"], "user_id");

        let error = Error::bad_command(serde_json::from_str::<Request>("{").unwrap_err());
        assert!(error.to_reply()["error"].get("field").is_none());
    }

    #[test]
    fn bad_command_keeps_values_out() {
        #[derive(Debug, serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct Request {
            count: u32,
            kind: Kind,
        }
        #[derive(Debug, serde::Deserialize)]
        enum Kind {
            Dm,
        }
        let reply = |command: &str| {
            Error::bad_command(serde_json::from_str::<Request>(command).unwrap_err()).to_reply()
        };

        // serde quotes a value of the wrong type and a variant it doesn't know, even one that
        // reads like its own message about a field.
        for command in [
            r#"{"count": "s3cr3t", "kind": "Dm"}"#,
            r#"{"count": 1, "kind": "s3cr3t"}"#,
            r#"{"count": "missing field `s3cr3t`", "kind": "Dm"}"#,
        ] {
            let reply = reply(command);
            assert!(!reply.to_string().contains("s3cr3t"), "{command}: {reply}");
            assert_eq!(
                reply["error"]["message"], "the command's fields don't match",
                "{command}"
            );
        }

        let unknown = reply(r#"{"count": 1, "kind": "Dm", "extra": "s3cr3t"}"#);
        assert_eq!(unknown["error"]["field"], "extra");
        assert!(!unknown.to_string().contains("s3cr3t"), "{unknown}");

        let broken = reply(r#"{"count": s3cr3t"#);
        assert_eq!(broken["error"]["message"], "the command isn't valid JSON");
        assert!(!broken.to_string().contains("s3cr3t"), "{broken}");
    }
}
