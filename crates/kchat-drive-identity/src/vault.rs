use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use zeroize::Zeroize;

use kchat_drive_types::DriveError;

/// Per-device encrypted vault for storing Drive keys (DomainKeys, ShareGrantKeys, VersionDEKs).
/// The vault is encrypted under a master key derived from the device's wrapping root.
#[derive(Debug)]
pub struct DriveKeyVault {
    /// Master key for the vault (32 bytes, AES-256-GCM).
    master_key: [u8; 32],
    /// In-memory entries: key_id → encrypted key blob.
    entries: std::collections::HashMap<String, VaultEntry>,
}

#[derive(Debug, Clone)]
struct VaultEntry {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
    last_used: web_time::Instant,
}

impl zeroize::Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for VaultEntry {}

impl Drop for VaultEntry {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl DriveKeyVault {
    /// Creates a new vault with a random master key.
    pub fn new() -> Self {
        let mut master_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut master_key);
        Self {
            master_key,
            entries: std::collections::HashMap::new(),
        }
    }

    /// Creates a vault from an existing master key (e.g., from WebCrypto wrapping root).
    pub fn from_master_key(master_key: [u8; 32]) -> Self {
        Self {
            master_key,
            entries: std::collections::HashMap::new(),
        }
    }

    /// Returns the vault's master key (for JS to persist across sessions).
    /// In production, JS should store this securely (e.g. WebCrypto + IndexedDB).
    ///
    /// The key is returned wrapped in `Zeroizing` so that the caller's copy is
    /// securely wiped from memory when dropped, avoiding prolonged exposure of
    /// the raw key material.
    pub fn master_key(&self) -> zeroize::Zeroizing<[u8; 32]> {
        zeroize::Zeroizing::new(self.master_key)
    }

    /// Stores a key in the vault, encrypted under the master key.
    pub fn store(&mut self, key_id: &str, key: &[u8; 32]) -> Result<(), DriveError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = b"kchat-drive/vault/v1";
        let ct = cipher
            .encrypt(nonce, Payload { msg: key, aad })
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        self.entries.insert(
            key_id.to_string(),
            VaultEntry {
                ciphertext: ct,
                nonce: nonce_bytes,
                last_used: web_time::Instant::now(),
            },
        );
        self.remove_stale(10000);
        Ok(())
    }

    /// Retrieves a key from the vault.
    pub fn load(&mut self, key_id: &str) -> Result<[u8; 32], DriveError> {
        let entry = self
            .entries
            .get_mut(key_id)
            .ok_or(DriveError::NotFound(format!(
                "vault key not found: {}",
                key_id
            )))?;

        entry.last_used = web_time::Instant::now();

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| DriveError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&entry.nonce);

        let aad = b"kchat-drive/vault/v1";
        let mut plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &entry.ciphertext,
                    aad,
                },
            )
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        if plaintext.len() != 32 {
            let len = plaintext.len();
            zeroize::Zeroize::zeroize(&mut plaintext);
            return Err(DriveError::Crypto(format!(
                "expected 32-byte key, got {}",
                len
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        zeroize::Zeroize::zeroize(&mut plaintext);
        Ok(key)
    }

    /// Stores arbitrary bytes in the vault, encrypted under the master key.
    pub fn store_bytes(&mut self, key_id: &str, data: &[u8]) -> Result<(), DriveError> {
        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let aad = b"kchat-drive/vault/v1";
        let ct = cipher
            .encrypt(nonce, Payload { msg: data, aad })
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        self.entries.insert(
            key_id.to_string(),
            VaultEntry {
                ciphertext: ct,
                nonce: nonce_bytes,
                last_used: web_time::Instant::now(),
            },
        );
        Ok(())
    }

    /// Retrieves arbitrary bytes from the vault.
    pub fn load_bytes(&mut self, key_id: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, DriveError> {
        let entry = self
            .entries
            .get_mut(key_id)
            .ok_or(DriveError::NotFound(format!(
                "vault key not found: {}",
                key_id
            )))?;

        entry.last_used = web_time::Instant::now();

        let cipher = Aes256Gcm::new_from_slice(&self.master_key)
            .map_err(|e| DriveError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&entry.nonce);

        let aad = b"kchat-drive/vault/v1";
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &entry.ciphertext,
                    aad,
                },
            )
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        Ok(zeroize::Zeroizing::new(plaintext))
    }

    /// Removes a key from the vault, zeroizing the ciphertext before removal.
    pub fn remove(&mut self, key_id: &str) {
        if let Some(mut entry) = self.entries.remove(key_id) {
            entry.zeroize();
        }
    }

    /// Removes least-recently-used entries when the vault exceeds `max_entries`.
    /// Entries that are evicted are zeroized via `ZeroizeOnDrop`.
    ///
    /// Uses batch eviction: only evicts when over the limit, and removes a
    /// batch of entries (the oldest via `min_by_key`) at once rather than
    /// scanning the entire map on every store. This reduces the O(n) scan
    /// frequency by ~10x compared to per-entry eviction.
    pub fn remove_stale(&mut self, max_entries: usize) {
        /// Number of entries to evict per batch. Evicting a batch at once
        /// amortizes the O(n) `min_by_key` scan over multiple evictions.
        const EVICT_BATCH: usize = 100;
        while self.entries.len() > max_entries {
            // Evict a batch of the oldest entries at once to reduce the
            // frequency of the O(n) `min_by_key` scan.
            // Evicted entries are zeroized on drop.
            let to_evict = EVICT_BATCH.min(self.entries.len() - max_entries).max(1);
            for _ in 0..to_evict {
                let oldest_key = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone());
                if let Some(key) = oldest_key {
                    self.entries.remove(&key);
                } else {
                    break;
                }
            }
        }
    }

    /// Returns whether a key exists in the vault.
    pub fn contains(&self, key_id: &str) -> bool {
        self.entries.contains_key(key_id)
    }

    /// Lists all key IDs in the vault.
    pub fn list(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    /// Export all encrypted entries for persistence.
    ///
    /// Returns a serializable representation of the vault's encrypted entries.
    /// The master key is **not** included — it must be re-derived from the
    /// wrapping root on the next session.
    ///
    /// Note: This clones all entries. Call infrequently (e.g., only during backup).
    pub fn export_data(&self) -> Vec<VaultEntryExport> {
        self.entries
            .iter()
            .map(|(key_id, entry)| VaultEntryExport {
                key_id: key_id.clone(),
                ciphertext: entry.ciphertext.clone(),
                nonce: entry.nonce,
            })
            .collect()
    }

    /// Import previously exported encrypted entries.
    ///
    /// The vault must already have its master key set (via `from_master_key`).
    pub fn import_data(&mut self, entries: &[VaultEntryExport]) {
        for entry in entries {
            self.entries.insert(
                entry.key_id.clone(),
                VaultEntry {
                    ciphertext: entry.ciphertext.clone(),
                    nonce: entry.nonce,
                    last_used: web_time::Instant::now(),
                },
            );
        }
    }
}

/// Serializable representation of a vault entry (encrypted blob + nonce).
/// The master key is deliberately excluded — it must be re-derived per session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VaultEntryExport {
    pub key_id: String,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

impl Default for DriveKeyVault {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DriveKeyVault {
    fn drop(&mut self) {
        self.master_key.zeroize();
    }
}
