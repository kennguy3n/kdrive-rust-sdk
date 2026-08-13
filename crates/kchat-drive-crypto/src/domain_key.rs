use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kchat_drive_types::{DomainId, DomainKeyRecord, DriveError, Hash256, Key256, Nonce12};

use crate::kdf::generate_key;

/// Generates a new DomainKey at generation 0.
#[must_use]
pub fn generate_domain_key(domain_id: DomainId) -> DomainKeyRecord {
    let key = generate_key();
    DomainKeyRecord {
        domain_id,
        generation: 0,
        key: Key256::new(key),
        prev_envelope: None,
        prev_envelope_nonce: None,
        is_checkpoint: true, // Generation 0 is always a checkpoint
    }
}

/// Rotates a DomainKey: creates a new generation with the previous key
/// encrypted under the new key (backward chain).
/// PrevEnvelope[g] = AEAD(DomainKey[g], DomainKey[g-1])
pub fn rotate_domain_key(current: &DomainKeyRecord) -> Result<DomainKeyRecord, DriveError> {
    let new_key = generate_key();
    let new_gen = current.generation + 1;

    // Encrypt the old key under the new key.
    let cipher =
        Aes256Gcm::new_from_slice(&new_key).map_err(|e| DriveError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = crate::labels::DOMAIN_KEY_CHAIN_AAD;
    let prev_envelope = cipher
        .encrypt(
            nonce,
            Payload {
                msg: current.key.as_bytes(),
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok(DomainKeyRecord {
        domain_id: current.domain_id.clone(),
        generation: new_gen,
        key: Key256::new(new_key),
        prev_envelope: Some(prev_envelope),
        prev_envelope_nonce: Some(Nonce12::new(nonce_bytes)),
        is_checkpoint: new_gen.is_multiple_of(32),
    })
}

/// Walks the backward chain: given the current DomainKey and the
/// prev_envelope, recovers the previous generation's key.
pub fn walk_backward(current: &DomainKeyRecord) -> Result<Key256, DriveError> {
    let prev_envelope = current
        .prev_envelope
        .as_ref()
        .ok_or(DriveError::InvalidState(
            "no previous envelope at generation 0".into(),
        ))?;
    let prev_nonce = current
        .prev_envelope_nonce
        .as_ref()
        .ok_or(DriveError::InvalidState(
            "no previous envelope nonce".into(),
        ))?;

    let cipher = Aes256Gcm::new_from_slice(current.key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(prev_nonce.as_bytes());

    let aad = crate::labels::DOMAIN_KEY_CHAIN_AAD;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: prev_envelope,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Crypto(format!(
            "expected 32-byte key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(Key256::new(key))
}

/// Wraps a VersionDEK under a DomainKey (Secured/Advanced mode).
/// Uses AES-256-GCM with a random nonce.
pub fn wrap_version_dek_under_domain_key(
    domain_key: &Key256,
    version_dek: &[u8; 32],
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    let cipher = Aes256Gcm::new_from_slice(domain_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = crate::labels::DOMAIN_WRAP_AAD;
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

/// Unwraps a VersionDEK from a DomainKey wrap.
pub fn unwrap_version_dek_from_domain_key(
    domain_key: &Key256,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<[u8; 32], DriveError> {
    let cipher = Aes256Gcm::new_from_slice(domain_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = crate::labels::DOMAIN_WRAP_AAD;
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
            "expected 32-byte key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Computes the hash of a DomainKeyRecord (for audit).
pub fn domain_key_hash(record: &DomainKeyRecord) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(record.domain_id.as_bytes());
    hasher.update(record.generation.to_be_bytes());
    hasher.update(record.key.as_bytes());
    Hash256::from_slice(&hasher.finalize())
}
