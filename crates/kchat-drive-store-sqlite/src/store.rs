use kchat_drive_types::DriveError;
use rusqlite::Connection;

use crate::migrations;

/// SQLite-backed Drive store. Separate from the MLS schema.
pub struct SqliteDriveStore {
    conn: Connection,
}

/// Applies performance-oriented PRAGMAs to a connection.
fn apply_pragmas(conn: &Connection) -> Result<(), DriveError> {
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
    Ok(())
}

impl SqliteDriveStore {
    /// Opens a Drive store at the given path.
    pub fn open(path: &str) -> Result<Self, DriveError> {
        let conn =
            Connection::open(path).map_err(|e| DriveError::Io(format!("open sqlite: {}", e)))?;
        apply_pragmas(&conn)?;
        migrations::run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Opens an in-memory Drive store (for tests).
    pub fn open_in_memory() -> Result<Self, DriveError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DriveError::Io(format!("open in-memory sqlite: {}", e)))?;
        apply_pragmas(&conn)?;
        migrations::run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Stores an encrypted key blob.
    pub fn store_key(
        &self,
        key_id: &str,
        ciphertext: &[u8],
        nonce: &[u8],
    ) -> Result<(), DriveError> {
        let mut stmt = self
            .conn
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
        let mut stmt = self
            .conn
            .prepare_cached("SELECT ciphertext, nonce FROM drive_keys WHERE key_id = ?1")
            .map_err(|e| DriveError::Io(e.to_string()))?;
        stmt.query_row(
            rusqlite::params![key_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(|e| {
            if e == rusqlite::Error::QueryReturnedNoRows {
                DriveError::NotFound(format!("key not found: {}", key_id))
            } else {
                DriveError::Io(e.to_string())
            }
        })
    }

    /// Returns whether a key exists.
    pub fn has_key(&self, key_id: &str) -> bool {
        let mut stmt = match self
            .conn
            .prepare_cached("SELECT 1 FROM drive_keys WHERE key_id = ?1")
        {
            Ok(s) => s,
            Err(_) => return false,
        };
        stmt.query_row(rusqlite::params![key_id], |_| Ok(()))
            .is_ok()
    }
}
