use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

use kchat_drive_types::{
    DriveError, Hash256, Key256, Nonce12, ShareGrantId, ShareGrantKeyRecord, UserId,
};

use crate::kdf::generate_key;
use kchat_drive_types::recipient_user_set_root;

/// Generates a new ShareGrantKey at generation 0.
#[must_use]
pub fn generate_share_grant_key(
    grant_id: ShareGrantId,
    recipients: &[UserId],
    user_snapshot_hash: &Hash256,
    mls_epoch: u64,
    mls_tree_hash: &Hash256,
) -> ShareGrantKeyRecord {
    let key = generate_key();
    let user_set_root = recipient_user_set_root(recipients, user_snapshot_hash);

    ShareGrantKeyRecord {
        grant_id,
        generation: 0,
        key: Key256::new(key),
        recipient_user_set_root: user_set_root,
        user_snapshot_hash: user_snapshot_hash.clone(),
        mls_epoch,
        mls_tree_hash: mls_tree_hash.clone(),
    }
}

/// Rotates a ShareGrantKey: creates a new generation.
/// In Max mode, rotation happens when a user is removed or a re-share is requested.
pub fn rotate_share_grant_key(
    current: &ShareGrantKeyRecord,
    recipients: &[UserId],
    user_snapshot_hash: &Hash256,
    mls_epoch: u64,
    mls_tree_hash: &Hash256,
) -> ShareGrantKeyRecord {
    let key = generate_key();
    let user_set_root = recipient_user_set_root(recipients, user_snapshot_hash);

    ShareGrantKeyRecord {
        grant_id: current.grant_id.clone(),
        generation: current.generation + 1,
        key: Key256::new(key),
        recipient_user_set_root: user_set_root,
        user_snapshot_hash: user_snapshot_hash.clone(),
        mls_epoch,
        mls_tree_hash: mls_tree_hash.clone(),
    }
}

/// Wraps a VersionDEK under a ShareGrantKey (Max mode).
pub fn wrap_version_dek_under_share_grant_key(
    share_grant_key: &Key256,
    version_dek: &[u8; 32],
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    let cipher = Aes256Gcm::new_from_slice(share_grant_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = b"kchat-drive/share-grant-wrap/v1";
    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: version_dek,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok((ct, Nonce12::new(nonce_bytes)))
}

/// Unwraps a VersionDEK from a ShareGrantKey wrap.
pub fn unwrap_version_dek_from_share_grant_key(
    share_grant_key: &Key256,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<[u8; 32], DriveError> {
    let cipher = Aes256Gcm::new_from_slice(share_grant_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = b"kchat-drive/share-grant-wrap/v1";
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        return Err(DriveError::Crypto(format!(
            "expected 32-byte key, got {}",
            plaintext.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    Ok(key)
}

/// Computes the hash of a ShareGrantKeyRecord (for audit).
pub fn share_grant_key_hash(record: &ShareGrantKeyRecord) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(record.grant_id.as_bytes());
    hasher.update(record.generation.to_be_bytes());
    hasher.update(record.key.as_bytes());
    hasher.update(record.recipient_user_set_root.as_bytes());
    hasher.update(record.user_snapshot_hash.as_bytes());
    hasher.update(record.mls_epoch.to_be_bytes());
    hasher.update(record.mls_tree_hash.as_bytes());
    Hash256::from_slice(&hasher.finalize())
}
