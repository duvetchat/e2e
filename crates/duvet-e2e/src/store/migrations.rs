//! The database's schema, numbered by `PRAGMA user_version`.

use rusqlite::Connection;

use crate::Error;

/// The schema this core writes. It opens every earlier one and refuses a later one.
pub(crate) const VERSION: i64 = 1;

pub(crate) fn run(conn: &mut Connection) -> Result<(), Error> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version > VERSION {
        return Err(Error::Storage(format!(
            "the database is from a newer core (schema {version})"
        )));
    }
    if version == 0 {
        let txn = conn.transaction()?;
        txn.execute_batch(V1)?;
        txn.pragma_update(None, "user_version", 1)?;
        txn.commit()?;
    }
    Ok(())
}

const V1: &str = r#"
-- Settings and secrets of this installation, by name (the identity, the backup key).
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- OpenMLS's state, through SqlStorage.
CREATE TABLE openmls_kv (
    key BLOB PRIMARY KEY,
    value BLOB NOT NULL
);

-- This installation's device: one row.
CREATE TABLE device (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    user_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    signature_key BLOB NOT NULL,
    hpke_public BLOB NOT NULL,
    hpke_private BLOB NOT NULL,
    certificate BLOB,
    created_at INTEGER NOT NULL
);

-- Other users' pinned identities, and the latest device list each one signed.
CREATE TABLE contacts (
    user_id BLOB PRIMARY KEY,
    identity_key BLOB NOT NULL,
    device_list BLOB NOT NULL,
    list_version INTEGER NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
);

-- The identities a contact had before their current one.
CREATE TABLE contact_identities (
    user_id BLOB NOT NULL,
    identity_key BLOB NOT NULL,
    replaced_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, identity_key)
);

-- Each conversation's MLS group, at its current generation.
CREATE TABLE groups (
    conversation_id BLOB PRIMARY KEY,
    generation INTEGER NOT NULL,
    -- The last entry of the conversation's queue applied; none until one takes effect.
    last_seq INTEGER,
    -- The member list in CBOR, as the group last had it.
    members BLOB NOT NULL,
    owner BLOB,
    kind TEXT NOT NULL CHECK (kind IN ('dm', 'group')),
    blocked INTEGER NOT NULL DEFAULT 0,
    leaf_updated_at INTEGER NOT NULL,
    -- This device's commit waiting for commit_result.
    pending TEXT CHECK (pending IN ('create', 'reset', 'commit', 'external')),
    -- The SHA-256 of this device's last commit, to know it in the queue.
    echo BLOB,
    -- The leave statements this epoch's removal proposals brought, in CBOR.
    statements BLOB
);

-- Messages as decrypted, with their edits applied. message_id is the API's, unknown while one is being sent.
CREATE TABLE messages (
    id INTEGER PRIMARY KEY,
    message_id BLOB UNIQUE,
    nonce TEXT UNIQUE,
    conversation_id BLOB NOT NULL,
    seq INTEGER,
    user_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    sent_at INTEGER NOT NULL,
    envelope BLOB,
    text TEXT,
    edited_at INTEGER,
    deleted INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('ok', 'waiting', 'pending')),
    shared_by BLOB,
    has TEXT
);
CREATE INDEX messages_by_conversation ON messages (conversation_id, seq);

-- Local search over the messages' text.
CREATE VIRTUAL TABLE messages_fts USING fts5 (
    text,
    content = 'messages',
    content_rowid = 'id',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TABLE mentions (
    message INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    user_id BLOB NOT NULL,
    PRIMARY KEY (message, user_id)
);

-- Messages encrypted and not yet sent, so a retry gets the same ciphertext.
CREATE TABLE outbox (
    nonce TEXT PRIMARY KEY,
    conversation_id BLOB NOT NULL,
    ciphertext BLOB NOT NULL,
    generation INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

-- What was sent while a member had no device, for their catch-up.
CREATE TABLE deviceless (
    conversation_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    message INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    PRIMARY KEY (conversation_id, user_id, message)
);

-- The backup's days: which are complete, and which to upload (again).
CREATE TABLE segments (
    conversation_id BLOB NOT NULL,
    day TEXT NOT NULL,
    complete INTEGER NOT NULL DEFAULT 0,
    dirty INTEGER NOT NULL DEFAULT 1,
    uploaded_at INTEGER,
    PRIMARY KEY (conversation_id, day)
);

-- The key packages this device handed out, to know when to make more.
CREATE TABLE key_packages (
    hash_ref BLOB PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    last_resort INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

-- Device approvals under way.
CREATE TABLE approvals (
    id BLOB PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('new', 'approver')),
    state BLOB NOT NULL,
    expires_at INTEGER NOT NULL
);
"#;
