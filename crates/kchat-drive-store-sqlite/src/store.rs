use kchat_drive_types::DriveError;
use rusqlite::Connection;

use crate::migrations;

/// SQLite-backed Drive store. Separate from the MLS schema.
pub struct SqliteDriveStore {
    conn: Connection,
}

impl SqliteDriveStore {
    /// Opens a Drive store at the given path.
    pub fn open(path: &str) -> Result<Self, DriveError> {
        let conn =
            Connection::open(path).map_err(|e| DriveError::Io(format!("open sqlite: {}", e)))?;
        migrations::run_migrations(&conn)?;
        Ok(Self { conn })
    }

    /// Opens an in-memory Drive store (for tests).
    pub fn open_in_memory() -> Result<Self, DriveError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| DriveError::Io(format!("open in-memory sqlite: {}", e)))?;
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
        self.conn
            .execute(
                "INSERT OR REPLACE INTO drive_keys (key_id, ciphertext, nonce) VALUES (?1, ?2, ?3)",
                rusqlite::params![key_id, ciphertext, nonce],
            )
            .map_err(|e| DriveError::Io(e.to_string()))?;
        Ok(())
    }

    /// Loads an encrypted key blob.
    pub fn load_key(&self, key_id: &str) -> Result<(Vec<u8>, Vec<u8>), DriveError> {
        self.conn
            .query_row(
                "SELECT ciphertext, nonce FROM drive_keys WHERE key_id = ?1",
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
        self.conn
            .query_row(
                "SELECT 1 FROM drive_keys WHERE key_id = ?1",
                rusqlite::params![key_id],
                |_| Ok(()),
            )
            .is_ok()
    }
}
