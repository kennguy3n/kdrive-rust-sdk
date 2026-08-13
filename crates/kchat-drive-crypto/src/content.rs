#![allow(clippy::type_complexity)]

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kchat_drive_types::{ChunkDescriptor, ChunkPlan, DriveError, Hash256};

use crate::kdf::{
    PROTOCOL_KDRV1, SUITE_KDRV1, chunk_count, compute_content_id, derive_content_chunk_key,
    derive_content_chunk_nonce, derive_content_key, derive_content_wrap_key,
    derive_content_wrap_nonce, select_chunk_size,
};

/// Builds the content-layer chunk AAD.
/// AAD = (protocol, suite, content_id, chunk_index, plaintext_len)
/// NO node_id, version_id, domain_id — purely content-scoped for dedup.
pub fn build_content_chunk_aad(
    content_id: &Hash256,
    chunk_index: u64,
    plaintext_len: u64,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&PROTOCOL_KDRV1.to_be_bytes());
    aad.extend_from_slice(&SUITE_KDRV1.to_be_bytes());
    aad.extend_from_slice(content_id.as_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

/// Encrypts a single content chunk with AES-256-GCM using derived key + nonce.
/// The ciphertext is deterministic for the same (ContentKey, content_id, chunk_index, plaintext).
pub fn encrypt_content_chunk(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, DriveError> {
    let key_bytes = derive_content_chunk_key(content_key, chunk_index);
    let nonce_bytes = derive_content_chunk_nonce(content_key, chunk_index);

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_content_chunk_aad(content_id, chunk_index, plaintext.len() as u64);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))
}

/// Decrypts a single content chunk with AES-256-GCM.
pub fn decrypt_content_chunk(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_index: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, DriveError> {
    let key_bytes = derive_content_chunk_key(content_key, chunk_index);
    let nonce_bytes = derive_content_chunk_nonce(content_key, chunk_index);

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // plaintext_len is ciphertext_len - 16 (GCM tag)
    let plaintext_len = ciphertext.len().saturating_sub(16) as u64;
    let aad = build_content_chunk_aad(content_id, chunk_index, plaintext_len);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))
}

/// Computes the SHA-256 of plaintext.
#[must_use]
pub fn plaintext_sha256(plaintext: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    Hash256::from_slice(&hasher.finalize())
}

/// Computes the SHA-256 of ciphertext (for blob dedup).
#[must_use]
pub fn ciphertext_sha256(ciphertext: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    Hash256::from_slice(&hasher.finalize())
}

/// Builds a content-addressed blob key: "blob_{content_id}_{chunk_content_hash}".
#[must_use]
pub fn content_blob_key(content_id: &Hash256, chunk_content_hash: &Hash256) -> String {
    format!(
        "blob_{}_{}",
        content_id.to_hex(),
        chunk_content_hash.to_hex()
    )
}

/// Encrypts a file into content-layer chunks (KDRV1).
/// Returns (chunk_plan, ciphertexts, content_id, content_key).
/// The content_key should be wrapped under a VersionDEK by the caller.
pub fn encrypt_content_file(
    plaintext: &[u8],
    tenant_pepper: &[u8; 32],
) -> Result<(ChunkPlan, Vec<Vec<u8>>, Hash256, [u8; 32]), DriveError> {
    let pt_hash = plaintext_sha256(plaintext);
    let content_id = compute_content_id(&pt_hash, tenant_pepper);
    let content_key = derive_content_key(&pt_hash, tenant_pepper);

    let cs = select_chunk_size(plaintext.len() as u64);
    let n = chunk_count(plaintext.len() as u64, cs);

    let mut chunks = Vec::with_capacity(n as usize);
    let mut ciphertexts = Vec::with_capacity(n as usize);

    for i in 0..n {
        let start = (i * cs) as usize;
        let end = ((i + 1) * cs).min(plaintext.len() as u64) as usize;
        let chunk_plaintext = &plaintext[start..end];
        let plaintext_len = chunk_plaintext.len() as u64;

        let ct = encrypt_content_chunk(&content_key, &content_id, i, chunk_plaintext)?;
        let ct_hash = ciphertext_sha256(&ct);
        let blob_key = content_blob_key(&content_id, &ct_hash);

        chunks.push(ChunkDescriptor {
            index: i,
            plaintext_len,
            ciphertext_len: ct.len() as u64,
            ciphertext_sha256: ct_hash,
            blob_key,
        });
        ciphertexts.push(ct);
    }

    Ok((ChunkPlan { chunks }, ciphertexts, content_id, content_key))
}

/// Decrypts a file from content-layer chunks (KDRV1).
pub fn decrypt_content_file(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_plan: &ChunkPlan,
    ciphertexts: &[Vec<u8>],
) -> Result<Vec<u8>, DriveError> {
    if ciphertexts.len() != chunk_plan.chunks.len() {
        return Err(DriveError::InvalidState(format!(
            "ciphertexts length ({}) does not match chunk plan length ({})",
            ciphertexts.len(),
            chunk_plan.chunks.len()
        )));
    }

    let mut plaintext = Vec::new();
    for (i, ct) in ciphertexts.iter().enumerate() {
        let desc = &chunk_plan.chunks[i];
        let pt = decrypt_content_chunk(content_key, content_id, desc.index, ct)?;
        plaintext.extend_from_slice(&pt);
    }

    Ok(plaintext)
}

/// Wraps a ContentKey under a VersionDEK (KDRV1 version binding).
/// Uses AES-256-GCM with a deterministic nonce derived from VersionDEK + version_id.
pub fn wrap_content_key(
    version_dek: &[u8; 32],
    version_id: &kchat_drive_types::VersionId,
    content_id: &Hash256,
    content_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), DriveError> {
    let key_bytes = derive_content_wrap_key(version_dek, version_id);
    let nonce_bytes = derive_content_wrap_nonce(version_dek, version_id);

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD binds the wrap to this specific content_id
    let mut aad = Vec::new();
    aad.extend_from_slice(crate::labels::CONTENT_WRAP_AAD);
    aad.extend_from_slice(version_id.as_bytes());
    aad.extend_from_slice(content_id.as_bytes());

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: content_key,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok((ct, nonce_bytes))
}

/// Unwraps a ContentKey from a VersionDEK wrap.
pub fn unwrap_content_key(
    version_dek: &[u8; 32],
    version_id: &kchat_drive_types::VersionId,
    content_id: &Hash256,
    wrapped_content_key: &[u8],
    wrap_nonce: &[u8; 12],
) -> Result<[u8; 32], DriveError> {
    let key_bytes = derive_content_wrap_key(version_dek, version_id);

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(wrap_nonce);

    let mut aad = Vec::new();
    aad.extend_from_slice(crate::labels::CONTENT_WRAP_AAD);
    aad.extend_from_slice(version_id.as_bytes());
    aad.extend_from_slice(content_id.as_bytes());

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: wrapped_content_key,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Crypto(format!(
            "expected 32-byte content key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Computes the KDRV1 chunk plan Merkle root.
/// Uses the same domain-separated tags as `ChunkPlan::merkle_root()` in header.rs.
pub fn content_chunk_plan_root(chunk_plan: &ChunkPlan) -> Hash256 {
    let mut leaves: Vec<[u8; 32]> = chunk_plan
        .chunks
        .iter()
        .map(|c| {
            let mut hasher = Sha256::new();
            hasher.update(crate::labels::CHUNK_PLAN_LEAF_TAG);
            hasher.update(c.index.to_be_bytes());
            hasher.update(c.plaintext_len.to_be_bytes());
            hasher.update(c.ciphertext_sha256.as_bytes());
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            arr
        })
        .collect();

    if leaves.is_empty() {
        return Hash256::new([0u8; 32]);
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(crate::labels::CHUNK_PLAN_NODE_TAG);
            hasher.update(pair[0]);
            if pair.len() == 2 {
                hasher.update(pair[1]);
            } else {
                // Odd node: duplicate the last leaf (standard Merkle tree convention)
                hasher.update(pair[0]);
            }
            let result = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&result);
            next.push(arr);
        }
        leaves = next;
    }
    Hash256::new(leaves[0])
}

// Re-export PROTOCOL_VERSION for AAD construction in callers.
pub use kchat_drive_types::PROTOCOL_VERSION as KDRV1_PROTOCOL;
