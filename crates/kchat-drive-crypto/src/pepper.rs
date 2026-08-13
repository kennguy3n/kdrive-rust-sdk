use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use kchat_drive_types::{DriveError, Key256, Nonce12};
use rand::RngCore;
use zeroize::Zeroize;

use crate::kdf::generate_tenant_pepper;

/// Generates a new random 32-byte tenant pepper.
#[must_use]
pub fn generate_pepper() -> [u8; 32] {
    generate_tenant_pepper()
}

/// Wraps a tenant pepper under a DomainKey (Secured/Advanced mode).
/// Uses AES-256-GCM with a random nonce.
pub fn wrap_pepper_under_domain_key(
    domain_key: &Key256,
    pepper: &[u8; 32],
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    let cipher = Aes256Gcm::new_from_slice(domain_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = crate::labels::PEPPER_WRAP_AAD;
    let ct = cipher
        .encrypt(nonce, Payload { msg: pepper, aad })
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok((ct, Nonce12::new(nonce_bytes)))
}

/// Unwraps a tenant pepper from a DomainKey wrap.
pub fn unwrap_pepper_from_domain_key(
    domain_key: &Key256,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<[u8; 32], DriveError> {
    let cipher = Aes256Gcm::new_from_slice(domain_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = crate::labels::PEPPER_WRAP_AAD;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Crypto(format!(
            "expected 32-byte pepper, got {}",
            len
        )));
    }

    let mut pepper = [0u8; 32];
    pepper.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(pepper)
}

/// Wraps a tenant pepper under a ShareGrantKey (Max mode).
/// Uses AES-256-GCM with a random nonce.
pub fn wrap_pepper_under_share_grant_key(
    share_grant_key: &Key256,
    pepper: &[u8; 32],
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    // Same AEAD construction as domain key wrap, different AAD tag
    let cipher = Aes256Gcm::new_from_slice(share_grant_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = crate::labels::PEPPER_WRAP_MAX_AAD;
    let ct = cipher
        .encrypt(nonce, Payload { msg: pepper, aad })
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok((ct, Nonce12::new(nonce_bytes)))
}

/// Unwraps a tenant pepper from a ShareGrantKey wrap.
pub fn unwrap_pepper_from_share_grant_key(
    share_grant_key: &Key256,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<[u8; 32], DriveError> {
    let cipher = Aes256Gcm::new_from_slice(share_grant_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = crate::labels::PEPPER_WRAP_MAX_AAD;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Crypto(format!(
            "expected 32-byte pepper, got {}",
            len
        )));
    }

    let mut pepper = [0u8; 32];
    pepper.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(pepper)
}

/// Computes the SHA-256 hash of a tenant pepper (for audit, not the pepper itself).
pub fn pepper_hash(pepper: &[u8; 32]) -> kchat_drive_types::Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(crate::labels::PEPPER_HASH_TAG);
    hasher.update(pepper);
    kchat_drive_types::Hash256::from_slice(&hasher.finalize())
}

// Re-export the wrap salt for callers that need it.
pub use crate::kdf::PEPPER_WRAP_SALT as PEPPER_SALT;
