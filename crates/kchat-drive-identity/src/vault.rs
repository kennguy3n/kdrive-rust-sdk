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
    pub fn master_key(&self) -> &[u8; 32] {
        &self.master_key
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
            },
        );
        Ok(())
    }

    /// Retrieves a key from the vault.
    pub fn load(&self, key_id: &str) -> Result<[u8; 32], DriveError> {
        let entry = self
            .entries
            .get(key_id)
            .ok_or(DriveError::NotFound(format!(
                "vault key not found: {}",
                key_id
            )))?;

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
            },
        );
        Ok(())
    }

    /// Retrieves arbitrary bytes from the vault.
    pub fn load_bytes(&self, key_id: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, DriveError> {
        let entry = self
            .entries
            .get(key_id)
            .ok_or(DriveError::NotFound(format!(
                "vault key not found: {}",
                key_id
            )))?;

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

    /// Removes a key from the vault.
    pub fn remove(&mut self, key_id: &str) {
        self.entries.remove(key_id);
    }

    /// Returns whether a key exists in the vault.
    pub fn contains(&self, key_id: &str) -> bool {
        self.entries.contains_key(key_id)
    }

    /// Lists all key IDs in the vault.
    pub fn list(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
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
