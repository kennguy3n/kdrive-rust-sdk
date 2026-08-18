#![allow(clippy::type_complexity)]

use std::io::Read;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kchat_drive_types::{ChunkDescriptor, ChunkPlan, DriveError, Hash256};

use crate::kdf::{
    PROTOCOL_KDRV1, SUITE_KDRV1, chunk_count, compute_chunk_content_id, compute_content_id,
    derive_chunk_convergent_key, derive_chunk_convergent_nonce, derive_content_chunk_key,
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

/// Builds the content-layer chunk AAD into a reusable buffer, avoiding
/// per-chunk allocation in streaming contexts.
pub fn build_content_chunk_aad_into(
    buf: &mut Vec<u8>,
    content_id: &Hash256,
    chunk_index: u64,
    plaintext_len: u64,
) {
    buf.clear();
    buf.extend_from_slice(&PROTOCOL_KDRV1.to_be_bytes());
    buf.extend_from_slice(&SUITE_KDRV1.to_be_bytes());
    buf.extend_from_slice(content_id.as_bytes());
    buf.extend_from_slice(&chunk_index.to_be_bytes());
    buf.extend_from_slice(&plaintext_len.to_be_bytes());
}

/// Encrypts a single content chunk with AES-256-GCM using derived key + nonce.
/// The ciphertext is deterministic for the same (ContentKey, content_id, chunk_index, plaintext).
pub fn encrypt_content_chunk(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_index: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, DriveError> {
    let key_bytes = derive_content_chunk_key(content_key, chunk_index)?;
    let nonce_bytes = derive_content_chunk_nonce(content_key, chunk_index)?;

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
    let key_bytes = derive_content_chunk_key(content_key, chunk_index)?;
    let nonce_bytes = derive_content_chunk_nonce(content_key, chunk_index)?;

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
    let mut aad_buf = Vec::with_capacity(48);

    for i in 0..n {
        let start = (i * cs) as usize;
        let end = ((i + 1) * cs).min(plaintext.len() as u64) as usize;
        let chunk_plaintext = &plaintext[start..end];
        let plaintext_len = chunk_plaintext.len() as u64;

        // Convergent chunk encryption: derive key from the chunk's own plaintext
        // hash + tenant_pepper, so identical plaintext chunks produce identical
        // ciphertexts regardless of which file they belong to. This enables
        // real chunk-level dedup across file versions.
        let chunk_pt_hash = Hash256::from_slice(&Sha256::digest(chunk_plaintext));
        let chunk_key = derive_chunk_convergent_key(&chunk_pt_hash, tenant_pepper);
        let chunk_content_id = compute_chunk_content_id(&chunk_pt_hash, tenant_pepper);

        let key_bytes = chunk_key;
        let nonce_bytes = derive_chunk_convergent_nonce(&chunk_key)?;

        // Build AAD using the per-chunk content_id (not the file-level content_id)
        build_content_chunk_aad_into(&mut aad_buf, &chunk_content_id, 0, plaintext_len);

        let cipher =
            Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: chunk_plaintext,
                    aad: &aad_buf,
                },
            )
            .map_err(|e| DriveError::Crypto(e.to_string()))?;

        let ct_hash = ciphertext_sha256(&ct);
        let blob_key = content_blob_key(&content_id, &ct_hash);

        chunks.push(ChunkDescriptor {
            index: i,
            plaintext_len,
            ciphertext_len: ct.len() as u64,
            ciphertext_sha256: ct_hash,
            blob_key,
            plaintext_sha256: Some(chunk_pt_hash),
        });
        ciphertexts.push(ct);
    }

    Ok((ChunkPlan { chunks }, ciphertexts, content_id, content_key))
}

/// Decrypts a file from content-layer chunks (KDRV1).
/// Uses convergent per-chunk keys when plaintext_sha256 is available in the
/// chunk plan; falls back to file-level content_key for legacy chunks.
pub fn decrypt_content_file(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_plan: &ChunkPlan,
    ciphertexts: &[Vec<u8>],
    tenant_pepper: &[u8; 32],
) -> Result<Vec<u8>, DriveError> {
    if ciphertexts.len() != chunk_plan.chunks.len() {
        return Err(DriveError::InvalidState(format!(
            "ciphertexts length ({}) does not match chunk plan length ({})",
            ciphertexts.len(),
            chunk_plan.chunks.len()
        )));
    }

    // Pre-allocate plaintext buffer: total plaintext size is the sum of each
    // chunk's plaintext_len from the chunk plan (avoids repeated reallocs).
    let total_plaintext_size: u64 = chunk_plan
        .chunks
        .iter()
        .map(|c| c.plaintext_len)
        .sum();
    let mut plaintext = Vec::with_capacity(total_plaintext_size as usize);
    let mut aad_buf = Vec::with_capacity(48);
    for (i, ct) in ciphertexts.iter().enumerate() {
        let desc = &chunk_plan.chunks[i];

        if let Some(ref chunk_pt_hash) = desc.plaintext_sha256 {
            // Convergent mode: derive key from chunk plaintext hash + pepper
            let chunk_key = derive_chunk_convergent_key(chunk_pt_hash, tenant_pepper);
            let chunk_content_id = compute_chunk_content_id(chunk_pt_hash, tenant_pepper);
            let nonce_bytes = derive_chunk_convergent_nonce(&chunk_key)?;

            build_content_chunk_aad_into(&mut aad_buf, &chunk_content_id, 0, desc.plaintext_len);

            let cipher = Aes256Gcm::new_from_slice(&chunk_key)
                .map_err(|e| DriveError::Crypto(e.to_string()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let pt = cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ct,
                        aad: &aad_buf,
                    },
                )
                .map_err(|e| DriveError::Crypto(e.to_string()))?;
            plaintext.extend_from_slice(&pt);
        } else {
            // Legacy mode: derive key from file-level content_key + chunk index
            build_content_chunk_aad_into(&mut aad_buf, content_id, desc.index, desc.plaintext_len);

            let key_bytes = derive_content_chunk_key(content_key, desc.index)?;
            let nonce_bytes = derive_content_chunk_nonce(content_key, desc.index)?;

            let cipher = Aes256Gcm::new_from_slice(&key_bytes)
                .map_err(|e| DriveError::Crypto(e.to_string()))?;
            let nonce = Nonce::from_slice(&nonce_bytes);

            let pt = cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: ct,
                        aad: &aad_buf,
                    },
                )
                .map_err(|e| DriveError::Crypto(e.to_string()))?;
            plaintext.extend_from_slice(&pt);
        }
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
    let key_bytes = derive_content_wrap_key(version_dek, version_id)?;
    let nonce_bytes = derive_content_wrap_nonce(version_dek, version_id)?;

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
    let key_bytes = derive_content_wrap_key(version_dek, version_id)?;

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

/// Streaming content encryption: reads `chunk_size` bytes at a time from
/// `reader`, encrypts each content chunk, and yields the ciphertext. Plaintext
/// for each chunk is dropped after encryption, keeping peak memory bounded.
///
/// The caller must supply the precomputed `content_id` and `content_key`.
pub fn encrypt_content_streaming<'a, R: Read>(
    reader: &'a mut R,
    content_key: &'a [u8; 32],
    content_id: &'a Hash256,
    chunk_size: usize,
) -> impl Iterator<Item = Result<Vec<u8>, DriveError>> + 'a {
    let mut chunk_index: u64 = 0;
    // Reusable AAD buffer to avoid per-chunk allocation.
    let mut aad_buf: Vec<u8> = Vec::new();
    std::iter::from_fn(move || {
        let mut buf = vec![0u8; chunk_size];
        let mut read_total = 0;
        while read_total < chunk_size {
            match reader.read(&mut buf[read_total..]) {
                Ok(0) => break,
                Ok(n) => read_total += n,
                Err(e) => return Some(Err(DriveError::Io(e.to_string()))),
            }
        }
        if read_total == 0 {
            return None;
        }
        buf.truncate(read_total);

        // Build AAD into the reusable buffer.
        build_content_chunk_aad_into(&mut aad_buf, content_id, chunk_index, buf.len() as u64);

        let key_bytes = match derive_content_chunk_key(content_key, chunk_index) {
            Ok(k) => k,
            Err(e) => {
                drop(buf);
                return Some(Err(e));
            }
        };
        let nonce_bytes = match derive_content_chunk_nonce(content_key, chunk_index) {
            Ok(n) => n,
            Err(e) => {
                drop(buf);
                return Some(Err(e));
            }
        };

        let cipher = match Aes256Gcm::new_from_slice(&key_bytes) {
            Ok(c) => c,
            Err(e) => {
                drop(buf);
                return Some(Err(DriveError::Crypto(e.to_string())));
            }
        };
        let nonce = Nonce::from_slice(&nonce_bytes);

        let result = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &buf,
                    aad: &aad_buf,
                },
            )
            .map_err(|e| DriveError::Crypto(e.to_string()));
        // Drop plaintext buffer before yielding.
        drop(buf);
        chunk_index += 1;
        Some(result)
    })
}

/// Streaming content decryption: decrypts each ciphertext chunk and yields the
/// plaintext. The `chunks` iterator must yield ciphertexts in chunk-index
/// order.
pub fn decrypt_content_streaming<I: Iterator<Item = Vec<u8>>>(
    chunks: I,
    content_key: &[u8; 32],
    content_id: &Hash256,
) -> impl Iterator<Item = Result<Vec<u8>, DriveError>> {
    chunks.enumerate().map(move |(idx, ct)| {
        let chunk_index = idx as u64;
        decrypt_content_chunk(content_key, content_id, chunk_index, &ct)
    })
}
