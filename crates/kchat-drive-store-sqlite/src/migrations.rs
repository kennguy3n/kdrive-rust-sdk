use kchat_drive_types::DriveError;
use rusqlite::Connection;

/// Embedded SQL migrations for the Drive DB.
/// In production, these are run by refinery on startup.
/// For the demo, we use a simple schema string.
const SCHEMA_V1: &str = r#"
CREATE TABLE IF NOT EXISTS drive_keys (
    key_id      TEXT PRIMARY KEY,
    ciphertext  BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS journal (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    op_type     INTEGER NOT NULL,
    status      INTEGER NOT NULL,
    node_id     BLOB,
    version_id  BLOB,
    timestamp   INTEGER NOT NULL,
    error       TEXT
);

CREATE TABLE IF NOT EXISTS sync_state (
    node_id         BLOB PRIMARY KEY,
    state           INTEGER NOT NULL,
    local_version   BLOB,
    remote_version  BLOB,
    last_sync       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS domain_keys (
    domain_id       BLOB NOT NULL,
    generation      INTEGER NOT NULL,
    key_ciphertext  BLOB NOT NULL,
    key_nonce       BLOB NOT NULL,
    prev_envelope   BLOB,
    prev_nonce      BLOB,
    is_checkpoint   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (domain_id, generation)
);

CREATE TABLE IF NOT EXISTS share_grant_keys (
    grant_id            BLOB NOT NULL,
    generation          INTEGER NOT NULL,
    key_ciphertext      BLOB NOT NULL,
    key_nonce           BLOB NOT NULL,
    recipient_set_root  BLOB NOT NULL,
    user_snapshot_hash  BLOB NOT NULL,
    mls_epoch           INTEGER NOT NULL,
    mls_tree_hash       BLOB NOT NULL,
    PRIMARY KEY (grant_id, generation)
);
"#;

/// Runs the schema migration on the given connection.
pub fn run_migrations(conn: &Connection) -> Result<(), DriveError> {
    conn.execute_batch(SCHEMA_V1)
        .map_err(|e| DriveError::Io(format!("sqlite migration: {}", e)))?;
    Ok(())
}
