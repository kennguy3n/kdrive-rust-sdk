use std::sync::{Arc, Mutex};

use kchat_drive_types::DriveError;
use rusqlite::Connection;

use crate::migrations;

/// SQLite-backed Drive store. Separate from the MLS schema.
///
/// The underlying `Connection` is wrapped in `Arc<Mutex<Connection>>` so the
/// store is `Send + Sync` and safe to share across threads (connection pooling
/// for the single-writer SQLite model).
pub struct SqliteDriveStore {
    conn: Arc<Mutex<Connection>>,
}

/// Applies encryption pragmas to a connection.
///
/// `PRAGMA key` MUST be issued before any other pragma (and before any other
/// SQL) on a SQLCipher connection, otherwise the database page reads will fail.
/// When `encryption_key` is empty, encryption is skipped entirely (dev mode).
fn apply_encryption_pragmas(conn: &Connection, encryption_key: &str) -> Result<(), DriveError> {
    if encryption_key.is_empty() {
        // Dev mode: no encryption. Plain SQLite.
        return Ok(());
    }
    // PRAGMA key must be the very first statement on a SQLCipher connection.
    conn.pragma_update(None, "key", encryption_key)
        .map_err(|e| DriveError::Io(format!("pragma key: {}", e)))?;
    // SQLCipher 4 default (AES-256-CBC HMAC-SHA512). Must be set right after key.
    conn.pragma_update(None, "cipher_compatibility", 4)
        .map_err(|e| DriveError::Io(format!("pragma cipher_compatibility: {}", e)))?;
    Ok(())
}

/// Applies performance-oriented PRAGMAs to a connection.
///
/// Order matters: `page_size` must be set before `journal_mode` because changing
/// the journal mode to WAL rewrites the database header and the page size is
/// fixed once the database file is created.
fn apply_pragmas(conn: &Connection) -> Result<(), DriveError> {
    // page_size must be set BEFORE journal_mode (WAL). 32 KiB pages improve
    // throughput for the blob-heavy Drive workload.
    conn.pragma_update(None, "page_size", 32768)
        .map_err(|e| DriveError::Io(format!("pragma page_size: {}", e)))?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| DriveError::Io(format!("pragma journal_mode: {}", e)))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| DriveError::Io(format!("pragma synchronous: {}", e)))?;
    conn.pragma_update(None, "cache_size", -10000) // 10MB
        .map_err(|e| DriveError::Io(format!("pragma cache_size: {}", e)))?;
    conn.pragma_update(None, "temp_store", "MEMORY")
        .map_err(|e| DriveError::Io(format!("pragma temp_store: {}", e)))?;
    conn.pragma_update(None, "mmap_size", 268435456) // 256MB
        .map_err(|e| DriveError::Io(format!("pragma mmap_size: {}", e)))?;
    conn.pragma_update(None, "wal_autocheckpoint", 1000)
        .map_err(|e| DriveError::Io(format!("pragma wal_autocheckpoint: {}", e)))?;
    // Wait up to 5 s for a locked database before returning SQLITE_BUSY.
    conn.pragma_update(None, "busy_timeout", 5000)
        .map_err(|e| DriveError::Io(format!("pragma busy_timeout: {}", e)))?;
    // Enforce foreign-key constraints.
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| DriveError::Io(format!("pragma foreign_keys: {}", e)))?;
    Ok(())
}

impl SqliteDriveStore {
    /// Opens a Drive store at the given path.
    ///
    /// `encryption_key` is the SQLCipher passphrase. It is applied via
    /// `PRAGMA key` before any other statement. Pass an empty string for
    /// dev mode (no encryption).
    pub fn open(path: &str, encryption_key: &str) -> Result<Self, DriveError> {
        let conn =
            Connection::open(path).map_err(|e| DriveError::Io(format!("open sqlite: {}", e)))?;
        apply_encryption_pragmas(&conn, encryption_key)?;
        apply_pragmas(&conn)?;
        migrations::run_migrations(&conn)?;
        // Verify database integrity after migrations.
        let integrity: String = conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .map_err(|e| DriveError::Io(format!("integrity check: {}", e)))?;
        if integrity != "ok" {
            return Err(DriveError::Io(format!(
                "sqlite integrity check failed: {}",
                integrity
            )));
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens an in-memory Drive store (for tests). No encryption.
    pub fn open_in_memory() -> Result<Self, DriveError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DriveError::Io(format!("open in-memory sqlite: {}", e)))?;
        apply_pragmas(&conn)?;
        migrations::run_migrations(&conn)?;
        // Verify database integrity after migrations.
        let integrity: String = conn
            .pragma_query_value(None, "integrity_check", |row| row.get(0))
            .map_err(|e| DriveError::Io(format!("integrity check: {}", e)))?;
        if integrity != "ok" {
            return Err(DriveError::Io(format!(
                "sqlite integrity check failed: {}",
                integrity
            )));
        }
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Stores an encrypted key blob.
    pub fn store_key(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<(), DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        let mut stmt = conn
            .prepare_cached(
                "INSERT OR REPLACE INTO drive_keys (key_id, ciphertext, nonce) VALUES (?1, ?2, ?3)",
            )
            .map_err(|e| DriveError::Io(e.to_string()))?;
        stmt.execute(rusqlite::params![key_id, ciphertext, nonce])
            .map_err(|e| DriveError::Io(e.to_string()))?;
        Ok(())
    }

    /// Loads an encrypted key blob.
    pub fn load_key(&self, key_id: &str) -> Result<(Vec<u8>, Vec<u8>), DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        let mut stmt = conn
            .prepare_cached("SELECT ciphertext, nonce FROM drive_keys WHERE key_id = ?1")
            .map_err(|e| DriveError::Io(e.to_string()))?;
        stmt.query_row(rusqlite::params![key_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(|e| {
            if e == rusqlite::Error::QueryReturnedNoRows {
                DriveError::NotFound(format!("key not found: {}", key_id))
            } else {
                DriveError::Io(e.to_string())
            }
        })
    }

    /// Returns whether a key exists.
    pub fn has_key(&self, key_id: &str) -> Result<bool, DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        let mut stmt = conn
            .prepare_cached("SELECT 1 FROM drive_keys WHERE key_id = ?1")
            .map_err(|e| DriveError::Io(e.to_string()))?;
        Ok(stmt.query_row(rusqlite::params![key_id], |_| Ok(())).is_ok())
    }

    /// Truncates the WAL back into the main database and resets the WAL file to
    /// its minimum size. Call this during idle periods (e.g. after sync) to
    /// bound disk usage and keep checkpoint latency predictable.
    pub fn checkpoint(&self) -> Result<(), DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        conn.pragma_update(None, "wal_checkpoint", "TRUNCATE")
            .map_err(|e| DriveError::Io(format!("pragma wal_checkpoint: {}", e)))?;
        Ok(())
    }

    /// Rebuilds the database file, reclaiming free pages and defragmenting.
    /// Expensive: acquires an exclusive lock. Run only when idle.
    pub fn vacuum(&self) -> Result<(), DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        conn.execute_batch("VACUUM")
            .map_err(|e| DriveError::Io(format!("vacuum: {}", e)))?;
        Ok(())
    }

    /// Explicitly closes the connection, performing best-effort cleanup.
    ///
    /// Because the `Connection` is behind an `Arc<Mutex<>>`, it cannot actually
    /// be dropped here; it is released when the last `Arc` clone is dropped.
    /// This method checkpoints the WAL and shrinks the page cache to minimize
    /// the on-disk footprint before that final drop.
    pub fn close(&self) -> Result<(), DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        // Checkpoint WAL before close to minimize WAL file size.
        let _ = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE");
        // Clear cache to release cached pages.
        let _ = conn.pragma_update(None, "cache_size", 0);
        Ok(())
    }

    /// Deletes completed (status = 3) and failed (status = 4) journal entries
    /// older than `older_than_seconds` and returns the number of rows removed.
    ///
    /// Status values mirror `OperationStatus` from `kchat-drive-sync-core`:
    /// `Completed = 3`, `Failed = 4`.
    pub fn cleanup_journal(&self, older_than_seconds: i64) -> Result<u64, DriveError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cutoff = now - older_than_seconds;
        conn.execute(
            "DELETE FROM journal WHERE status IN (3, 4) AND timestamp < ?1",
            rusqlite::params![cutoff],
        )
        .map_err(|e| DriveError::Io(format!("cleanup journal: {}", e)))?;
        Ok(conn.changes() as u64)
    }

    /// Runs `f` inside a database transaction. Commits on success, rolls back
    /// on error. The closure receives a locked connection guard.
    pub fn transaction<F, R>(&self, f: F) -> Result<R, DriveError>
    where
        F: FnOnce(&Connection) -> Result<R, DriveError>,
    {
        let conn = self
            .conn
            .lock()
            .map_err(|e| DriveError::Io(format!("sqlite mutex poisoned: {}", e)))?;
        conn.execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| DriveError::Io(format!("begin: {}", e)))?;
        match f(&conn) {
            Ok(r) => {
                conn.execute_batch("COMMIT")
                    .map_err(|e| DriveError::Io(format!("commit: {}", e)))?;
                Ok(r)
            }
            Err(e) => {
                // Best-effort rollback; surface the original error.
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}
