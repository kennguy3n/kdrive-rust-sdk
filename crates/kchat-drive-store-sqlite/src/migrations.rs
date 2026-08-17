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

-- Indexes for common query patterns.
CREATE INDEX IF NOT EXISTS idx_journal_node_id     ON journal(node_id);
CREATE INDEX IF NOT EXISTS idx_journal_version_id  ON journal(version_id);
CREATE INDEX IF NOT EXISTS idx_journal_status       ON journal(status);
CREATE INDEX IF NOT EXISTS idx_sync_state_node_id  ON sync_state(node_id);
CREATE INDEX IF NOT EXISTS idx_domain_keys_domain_id     ON domain_keys(domain_id);
CREATE INDEX IF NOT EXISTS idx_share_grant_keys_grant_id ON share_grant_keys(grant_id);
"#;

/// Schema V2: adds composite indexes for common query patterns.
const SCHEMA_V2: &str = r#"
-- Composite index for journal cleanup queries that filter by status and timestamp.
CREATE INDEX IF NOT EXISTS idx_journal_status_timestamp ON journal(status, timestamp);

-- Composite index for domain key lookups by domain + generation.
CREATE INDEX IF NOT EXISTS idx_domain_keys_domain_gen ON domain_keys(domain_id, generation);
"#;

/// Schema V3: adds index for sync_state cleanup queries by last_sync.
const SCHEMA_V3: &str = r#"
-- Index for sync_state queries that filter or sort by last_sync.
CREATE INDEX IF NOT EXISTS idx_sync_state_last_sync ON sync_state(last_sync);
"#;

/// Runs the schema migration on the given connection.
///
/// Uses `PRAGMA user_version` to track which schema version has been applied so
/// that future migrations can be added incrementally without re-running prior
/// ones.
pub fn run_migrations(conn: &Connection) -> Result<(), DriveError> {
    let current: i32 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| DriveError::Io(format!("pragma user_version: {}", e)))?;
    if current < 1 {
        conn.execute_batch(SCHEMA_V1)
            .map_err(|e| DriveError::Io(format!("sqlite migration v1: {}", e)))?;
        conn.pragma_update(None, "user_version", 1)
            .map_err(|e| DriveError::Io(format!("set user_version: {}", e)))?;
    }
    if current < 2 {
        conn.execute_batch(SCHEMA_V2)
            .map_err(|e| DriveError::Io(format!("sqlite migration v2: {}", e)))?;
        conn.pragma_update(None, "user_version", 2)
            .map_err(|e| DriveError::Io(format!("set user_version: {}", e)))?;
    }
    if current < 3 {
        conn.execute_batch(SCHEMA_V3)
            .map_err(|e| DriveError::Io(format!("sqlite migration v3: {}", e)))?;
        conn.pragma_update(None, "user_version", 3)
            .map_err(|e| DriveError::Io(format!("set user_version: {}", e)))?;
    }
    Ok(())
}
