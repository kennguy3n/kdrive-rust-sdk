use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sha2::{Digest, Sha256};

use kchat_drive_types::{ChunkDescriptor, ChunkPlan, DomainId, Hash256, NodeId, VersionId};

use crate::kdf::{
    chunk_count, derive_chunk_key, derive_chunk_nonce, extract_prk, select_chunk_size,
};

/// Chunk AAD = canonical CBOR of:
/// (protocol, suite, drive_id, node_id, version_id, chunk_index,
///  plaintext_len, domain_id, access_context_revision, access_context_snapshot_hash)
///
/// For simplicity in the demo, we use a deterministic byte encoding
/// rather than full CBOR.
pub fn build_chunk_aad(
    protocol: u16,
    suite: u16,
    drive_id: &[u8; 16],
    node_id: &[u8; 16],
    version_id: &[u8; 16],
    chunk_index: u64,
    plaintext_len: u64,
    domain_id: &[u8; 16],
    access_context_revision: u64,
    access_context_snapshot_hash: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&protocol.to_be_bytes());
    aad.extend_from_slice(&suite.to_be_bytes());
    aad.extend_from_slice(drive_id);
    aad.extend_from_slice(node_id);
    aad.extend_from_slice(version_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(domain_id);
    aad.extend_from_slice(&access_context_revision.to_be_bytes());
    aad.extend_from_slice(access_context_snapshot_hash);
    aad
}

/// Encrypts a single chunk with AES-256-GCM using derived key + nonce.
pub fn encrypt_chunk(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    chunk_index: u64,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, kchat_drive_types::DriveError> {
    let prk = extract_prk(version_dek);
    let key_bytes = derive_chunk_key(&prk, node_id, version_id, chunk_index);
    let nonce_bytes = derive_chunk_nonce(&prk, node_id, version_id, chunk_index);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| kchat_drive_types::DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| kchat_drive_types::DriveError::Crypto(e.to_string()))
}

/// Decrypts a single chunk with AES-256-GCM.
pub fn decrypt_chunk(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    chunk_index: u64,
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, kchat_drive_types::DriveError> {
    let prk = extract_prk(version_dek);
    let key_bytes = derive_chunk_key(&prk, node_id, version_id, chunk_index);
    let nonce_bytes = derive_chunk_nonce(&prk, node_id, version_id, chunk_index);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| kchat_drive_types::DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| kchat_drive_types::DriveError::Crypto(e.to_string()))
}

/// Encrypts a file into chunks and returns the chunk plan + ciphertexts.
pub fn encrypt_file(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    drive_id: &[u8; 16],
    domain_id: &DomainId,
    access_context_revision: u64,
    access_context_snapshot_hash: &[u8; 32],
    plaintext: &[u8],
) -> Result<(ChunkPlan, Vec<Vec<u8>>), kchat_drive_types::DriveError> {
    let protocol = kchat_drive_types::PROTOCOL_VERSION;
    let suite = kchat_drive_types::SUITE_KDRV1;
    let cs = select_chunk_size(plaintext.len() as u64);
    let n = chunk_count(plaintext.len() as u64, cs);

    let mut chunks = Vec::with_capacity(n as usize);
    let mut ciphertexts = Vec::with_capacity(n as usize);

    for i in 0..n {
        let start = (i * cs) as usize;
        let end = ((i + 1) * cs).min(plaintext.len() as u64) as usize;
        let chunk_plaintext = &plaintext[start..end];
        let plaintext_len = chunk_plaintext.len() as u64;

        let aad = build_chunk_aad(
            protocol,
            suite,
            drive_id,
            node_id.as_bytes(),
            version_id.as_bytes(),
            i,
            plaintext_len,
            domain_id.as_bytes(),
            access_context_revision,
            access_context_snapshot_hash,
        );

        let ct = encrypt_chunk(version_dek, node_id, version_id, i, chunk_plaintext, &aad)?;
        let ct_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&ct);
            let result = hasher.finalize();
            Hash256::from_slice(&result)
        };

        chunks.push(ChunkDescriptor {
            index: i,
            plaintext_len,
            ciphertext_len: ct.len() as u64,
            ciphertext_sha256: ct_hash,
            blob_key: format!("blob_{}_{}", version_id.to_hex(), i),
        });
        ciphertexts.push(ct);
    }

    Ok((ChunkPlan { chunks }, ciphertexts))
}

/// Decrypts a file from chunks.
pub fn decrypt_file(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    drive_id: &[u8; 16],
    domain_id: &DomainId,
    access_context_revision: u64,
    access_context_snapshot_hash: &[u8; 32],
    chunk_plan: &ChunkPlan,
    ciphertexts: &[Vec<u8>],
) -> Result<Vec<u8>, kchat_drive_types::DriveError> {
    let protocol = kchat_drive_types::PROTOCOL_VERSION;
    let suite = kchat_drive_types::SUITE_KDRV1;

    if ciphertexts.len() != chunk_plan.chunks.len() {
        return Err(kchat_drive_types::DriveError::InvalidState(format!(
            "ciphertexts length ({}) does not match chunk plan length ({})",
            ciphertexts.len(),
            chunk_plan.chunks.len()
        )));
    }

    let mut plaintext = Vec::new();
    for (i, ct) in ciphertexts.iter().enumerate() {
        let desc = &chunk_plan.chunks[i];
        let aad = build_chunk_aad(
            protocol,
            suite,
            drive_id,
            node_id.as_bytes(),
            version_id.as_bytes(),
            desc.index,
            desc.plaintext_len,
            domain_id.as_bytes(),
            access_context_revision,
            access_context_snapshot_hash,
        );

        let pt = decrypt_chunk(version_dek, node_id, version_id, desc.index, ct, &aad)?;
        plaintext.extend_from_slice(&pt);
    }

    Ok(plaintext)
}
