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

-- The identities a contact had before their current one, and those this device's own user had.
CREATE TABLE contact_identities (
    user_id BLOB NOT NULL,
    identity_key BLOB NOT NULL,
    replaced_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, identity_key)
);

-- Each user's devices' certificates (this device's own user's too), as observe_user and rotations
-- bring them: only ever ones the identity this device pins or holds for the user signed.
CREATE TABLE certificates (
    user_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    certificate BLOB NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

-- The users a refused commit or welcome (by its SHA-256) asked the client to observe anew, with
-- what the device knew of each then (their identity, and their list's version), and whether
-- observe_user ran for them since. The same entry refused again at the same knowledge, observed
-- since, is refused for good; otherwise it asks again.
CREATE TABLE observe_asks (
    entry BLOB NOT NULL,
    user_id BLOB NOT NULL,
    identity_key BLOB NOT NULL,
    list_version INTEGER NOT NULL,
    observed INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (entry, user_id)
);

-- Each conversation's MLS group, at its current generation.
CREATE TABLE groups (
    conversation_id BLOB PRIMARY KEY,
    generation INTEGER NOT NULL,
    -- The last entry of the conversation's queue applied; none until one takes effect.
    last_seq INTEGER,
    -- The latest epoch of this generation the device held, or saw a commit take the group to.
    epoch INTEGER NOT NULL DEFAULT 0,
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
-- envelope is the message as it was sent, text its author's latest; a deleted message keeps neither.
-- reply_to is the message it answers, as the API gives it: replies go in the clear.
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
    has TEXT,
    reply_to BLOB
);
CREATE INDEX messages_by_conversation ON messages (conversation_id, seq);

-- Local search over the messages' text.
CREATE VIRTUAL TABLE messages_fts USING fts5 (
    text,
    content = 'messages',
    content_rowid = 'id',
    tokenize = 'unicode61 remove_diacritics 2'
);
-- A deletion takes a text's words out of the index's own storage, not just out of its results.
INSERT INTO messages_fts (messages_fts, rank) VALUES ('secure-delete', 1);
CREATE TRIGGER messages_fts_insert AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts (rowid, text) VALUES (new.id, new.text);
END;
CREATE TRIGGER messages_fts_delete AFTER DELETE ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, text) VALUES ('delete', old.id, old.text);
END;
CREATE TRIGGER messages_fts_update AFTER UPDATE OF text ON messages BEGIN
    INSERT INTO messages_fts (messages_fts, rowid, text) VALUES ('delete', old.id, old.text);
    INSERT INTO messages_fts (rowid, text) VALUES (new.id, new.text);
END;

-- Each edit of a message as it came: a message's text is its author's latest. An edit of a message
-- this device can't read yet (waiting, or not here at all) waits here for it.
CREATE TABLE edits (
    id INTEGER PRIMARY KEY,
    conversation_id BLOB NOT NULL,
    message_id BLOB NOT NULL,
    seq INTEGER,
    user_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    sent_at INTEGER NOT NULL,
    text TEXT NOT NULL,
    -- The SHA-256 of this device's own edit, to know its number when the queue brings it back.
    echo BLOB,
    shared_by BLOB
);
CREATE INDEX edits_by_message ON edits (message_id);
CREATE INDEX edits_by_echo ON edits (echo) WHERE echo IS NOT NULL;

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

-- What was sent while a member had no device, for their catch-up, with the identity this device had
-- pinned for them then (none when it had none). `taken` counts the times the note was taken again
-- (an edit while they had no device), so a catch-up made before forgets only what it carried.
CREATE TABLE deviceless (
    conversation_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    message INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    identity_key BLOB,
    taken INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id, user_id, message)
);

-- The members the client says have no device in a conversation now, until one of theirs enters.
CREATE TABLE deviceless_users (
    conversation_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

-- The keys of the history packages other devices sent this one (shares and catch-ups), by package:
-- whose they are, of which conversation, and the sending device's signature key, which must have
-- signed the package.
CREATE TABLE history_keys (
    share_id BLOB PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('share', 'catch_up')),
    conversation_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    device_id BLOB NOT NULL,
    signature_key BLOB NOT NULL,
    key BLOB NOT NULL,
    received_at INTEGER NOT NULL
);

-- The messages each catch-up this device made carried, by package, with their notes' `taken` then,
-- until its client says it delivered it (catch_up_delivered): then those notes go, unless they were
-- taken again since.
CREATE TABLE catch_ups (
    share_id BLOB NOT NULL,
    conversation_id BLOB NOT NULL,
    user_id BLOB NOT NULL,
    message INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE,
    taken INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (share_id, message)
);

-- The backup's days: a row for each conversation and UTC day (YYYY-MM-DD) this device holds anything
-- of, or the server holds a segment of as far as it knows. `dirty` while what the device holds of the
-- day changed since the server last held the same; `version` counts the day's changes, so that
-- backup_uploaded takes as the day only the build of its current version; `uploaded` what the server
-- holds: none it knows of, an incomplete copy (0) or a complete one (1); `held` once the device
-- imported a complete copy of the day, which it then holds whole.
CREATE TABLE segments (
    conversation_id BLOB NOT NULL,
    day TEXT NOT NULL,
    dirty INTEGER NOT NULL DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 0,
    uploaded INTEGER CHECK (uploaded IN (0, 1)),
    held INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (conversation_id, day)
);
-- A conversation and a time written here mark that UTC day's segment changed.
CREATE VIEW segment_changes (conversation_id, at) AS SELECT NULL, NULL WHERE 0;
CREATE TRIGGER segment_changed INSTEAD OF INSERT ON segment_changes BEGIN
    INSERT OR IGNORE INTO segments (conversation_id, day)
        VALUES (new.conversation_id, strftime('%Y-%m-%d', new.at / 1000.0, 'unixepoch'));
    UPDATE segments SET dirty = 1, version = version + 1
        WHERE conversation_id = new.conversation_id
        AND day = strftime('%Y-%m-%d', new.at / 1000.0, 'unixepoch');
END;
-- A message or an edit written, dropped, or changed in what a segment carries of it (not its shown
-- text) changes its day, and the day it had: a deletion, the message's day and its edits'.
CREATE TRIGGER segments_message_insert AFTER INSERT ON messages BEGIN
    INSERT INTO segment_changes VALUES (new.conversation_id, new.sent_at);
END;
CREATE TRIGGER segments_message_update AFTER UPDATE OF message_id, conversation_id, seq, user_id,
    device_id, sent_at, envelope, deleted, status, shared_by, reply_to ON messages BEGIN
    INSERT INTO segment_changes VALUES (old.conversation_id, old.sent_at);
    INSERT INTO segment_changes VALUES (new.conversation_id, new.sent_at);
END;
CREATE TRIGGER segments_message_delete AFTER DELETE ON messages BEGIN
    INSERT INTO segment_changes VALUES (old.conversation_id, old.sent_at);
END;
CREATE TRIGGER segments_edit_insert AFTER INSERT ON edits BEGIN
    INSERT INTO segment_changes VALUES (new.conversation_id, new.sent_at);
END;
CREATE TRIGGER segments_edit_update AFTER UPDATE OF conversation_id, message_id, seq, user_id,
    device_id, sent_at, text, shared_by ON edits BEGIN
    INSERT INTO segment_changes VALUES (old.conversation_id, old.sent_at);
    INSERT INTO segment_changes VALUES (new.conversation_id, new.sent_at);
END;
CREATE TRIGGER segments_edit_delete AFTER DELETE ON edits BEGIN
    INSERT INTO segment_changes VALUES (old.conversation_id, old.sent_at);
END;
-- A day's messages and edits, as a segment and a complete day read them.
CREATE INDEX messages_by_day ON messages (conversation_id, sent_at);
CREATE INDEX edits_by_day ON edits (conversation_id, sent_at);

-- When this device was in each conversation's group, for the backup's complete days: from when it
-- entered to the latest time it knows it was still in (the newest entry it applied there, or the
-- commit that took it out). A row each time it enters; `open` while it's in. A stay whose start only
-- the device's own clock knew (an external join, a welcome without the API's time) begins at the
-- first time the API gives after it: both are NULL until then.
CREATE TABLE memberships (
    conversation_id BLOB NOT NULL,
    entered_at INTEGER,
    seen_until INTEGER,
    open INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX memberships_by_conversation ON memberships (conversation_id);

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
