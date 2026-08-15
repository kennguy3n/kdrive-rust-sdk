#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_arguments)]
// Allow deprecated functions during the migration period from low-level
// crypto bindings to the facade-based API. External callers should migrate
// to DriveRuntime methods; these functions will be removed in a future release.
#![allow(deprecated)]

// Note: NAPI uses i64 (not u64) for all integer types because JS Number
// cannot represent u64 directly. All actual values (revision numbers,
// chunk counts, file sizes, epoch numbers) are well within i64 range.
// The `as u64` cast is safe for all realistic inputs. Using u64 would
// require BigInt on the JS side, which is less ergonomic for callers.

mod error;
mod runtime;

use error::{invalid_input, to_napi_error};
use napi::bindgen_prelude::Buffer;
use napi_derive::napi;

#[napi]
pub fn generate_version_dek() -> String {
    hex::encode(kchat_drive_crypto::generate_key())
}

#[napi]
pub fn generate_hpke_keypair() -> KeyPair {
    let (priv_key, pub_key) = kchat_drive_crypto::hpke::generate_keypair();
    KeyPair {
        private_key_hex: hex::encode(priv_key),
        public_key_hex: hex::encode(pub_key),
    }
}

#[napi]
pub fn generate_ed25519_keypair() -> KeyPair {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    KeyPair {
        private_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
    }
}

#[napi]
pub fn random_id_hex() -> String {
    kchat_drive_types::OpaqueId::random().to_hex()
}

#[napi]
pub fn get_test_vectors_json() -> String {
    kchat_drive_crypto::all_vectors_json()
}

#[napi(object)]
pub struct KeyPair {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

#[napi(object)]
pub struct EncryptResult {
    pub version_id_hex: String,
    pub chunk_plan_root_hex: String,
    pub chunk_count: i64,
    pub manifest_ciphertext_hex: String,
    pub manifest_nonce_hex: String,
    pub ciphertexts_hex: Vec<String>,
}

#[napi(object)]
pub struct ChunkInfo {
    pub index: i64,
    pub plaintext_len: i64,
    pub ciphertext_len: i64,
    pub ciphertext_sha256_hex: String,
    pub blob_key: String,
}

#[napi]
pub fn select_chunk_size(file_size: i64) -> i64 {
    kchat_drive_crypto::select_chunk_size(file_size as u64) as i64
}

#[napi]
pub fn chunk_count(file_size: i64, chunk_size: i64) -> i64 {
    kchat_drive_crypto::chunk_count(file_size as u64, chunk_size as u64) as i64
}

#[deprecated(since = "0.1.0", note = "Use DriveRuntime facade method instead")]
#[napi]
pub fn encrypt_file_napi(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: i64,
    access_context_snapshot_hash_hex: String,
    plaintext: Buffer,
) -> Result<EncryptResult, napi::Error> {
    let version_dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex).map_err(to_napi_error)?;
    let version_id =
        kchat_drive_types::VersionId::from_hex(&version_id_hex).map_err(to_napi_error)?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| invalid_input(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("drive_id must be 16 bytes".to_string()))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;

    let (chunk_plan, ciphertexts) = kchat_drive_crypto::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision as u64,
        &snapshot_hash,
        &plaintext,
    )
    .map_err(to_napi_error)?;

    let root = chunk_plan.merkle_root();

    let manifest = kchat_drive_types::Manifest {
        version_id: version_id.clone(),
        node_id: node_id.clone(),
        chunk_plan: chunk_plan.clone(),
        name_ciphertext: vec![],
        mime_type: None,
        plaintext_size: plaintext.len() as u64,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        parent_version_id: None,
        content_id: None,
        wrapped_content_key: None,
        content_wrap_nonce: None,
    };

    let (manifest_ct, manifest_nonce) =
        kchat_drive_crypto::encrypt_manifest(&version_dek, &node_id, &version_id, &manifest)
            .map_err(to_napi_error)?;

    Ok(EncryptResult {
        version_id_hex: version_id.to_hex(),
        chunk_plan_root_hex: root.to_hex(),
        chunk_count: chunk_plan.chunks.len() as i64,
        manifest_ciphertext_hex: hex::encode(&manifest_ct),
        manifest_nonce_hex: hex::encode(manifest_nonce.as_bytes()),
        ciphertexts_hex: ciphertexts.iter().map(hex::encode).collect(),
    })
}

#[deprecated(since = "0.1.0", note = "Use DriveRuntime facade method instead")]
#[napi]
pub fn decrypt_file_napi(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: i64,
    access_context_snapshot_hash_hex: String,
    manifest_ciphertext_hex: String,
    manifest_nonce_hex: String,
    ciphertexts_hex: Vec<String>,
) -> Result<Buffer, napi::Error> {
    let version_dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex).map_err(to_napi_error)?;
    let version_id =
        kchat_drive_types::VersionId::from_hex(&version_id_hex).map_err(to_napi_error)?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| invalid_input(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("drive_id must be 16 bytes".to_string()))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;

    let manifest_ct = hex::decode(&manifest_ciphertext_hex)
        .map_err(|e| invalid_input(format!("invalid manifest_ciphertext: {}", e)))?;
    let manifest_nonce_bytes = hex::decode(&manifest_nonce_hex)
        .map_err(|e| invalid_input(format!("invalid manifest_nonce: {}", e)))?;
    let manifest_nonce_bytes: [u8; 12] = manifest_nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("manifest_nonce must be 12 bytes".to_string()))?;
    let manifest_nonce = kchat_drive_types::Nonce12::new(manifest_nonce_bytes);

    let manifest = kchat_drive_crypto::decrypt_manifest(
        &version_dek,
        &node_id,
        &version_id,
        &manifest_ct,
        &manifest_nonce,
    )
    .map_err(to_napi_error)?;

    let ciphertexts: Vec<Vec<u8>> = ciphertexts_hex
        .iter()
        .map(|h| {
            hex::decode(h).map_err(|e| invalid_input(format!("invalid ciphertext hex: {}", e)))
        })
        .collect::<Result<_, _>>()?;

    let plaintext = kchat_drive_crypto::decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision as u64,
        &snapshot_hash,
        &manifest.chunk_plan,
        &ciphertexts,
    )
    .map_err(to_napi_error)?;

    Ok(Buffer::from(plaintext))
}

// ---- Additional crypto functions for the Electron Drive demo ----
// These mirror the WASM crate's `encrypt_file_wasm`, `decrypt_file_wasm`,
// DEK wrap/unwrap, domain/share-grant key generation, header sign/verify,
// and `sha256_hex`. They return JSON strings (like the WASM equivalents)
// so the Electron renderer can use the same parsing logic as the web-sample.

/// SHA-256 hash of arbitrary data, returned as hex.
#[napi(js_name = sha256Hex)]
pub fn sha256_hex(data: Buffer) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hex::encode(hasher.finalize())
}

/// Encrypt a file and return a JSON string with chunk-level details
/// (chunkPlanRoot, chunkCount, ciphertexts, chunks with blob keys + hashes).
/// This is the NAPI equivalent of WASM's `encrypt_file_wasm`.
#[napi(js_name = encryptFile)]
pub fn encrypt_file_json(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: i64,
    access_context_snapshot_hash_hex: String,
    plaintext: Buffer,
) -> Result<String, napi::Error> {
    let version_dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex).map_err(to_napi_error)?;
    let version_id =
        kchat_drive_types::VersionId::from_hex(&version_id_hex).map_err(to_napi_error)?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| invalid_input(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("drive_id must be 16 bytes".to_string()))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;

    let (chunk_plan, ciphertexts) = kchat_drive_crypto::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision as u64,
        &snapshot_hash,
        &plaintext,
    )
    .map_err(to_napi_error)?;

    let root = chunk_plan.merkle_root();

    let result = serde_json::json!({
        "chunkPlanRoot": root.to_hex(),
        "chunkCount": chunk_plan.chunks.len(),
        "ciphertexts": ciphertexts.iter().map(hex::encode).collect::<Vec<_>>(),
        "chunks": chunk_plan.chunks.iter().map(|c| {
            serde_json::json!({
                "index": c.index,
                "plaintextLen": c.plaintext_len,
                "ciphertextLen": c.ciphertext_len,
                "ciphertextSha256": c.ciphertext_sha256.to_hex(),
                "blobKey": c.blob_key,
            })
        }).collect::<Vec<_>>(),
    });
    Ok(result.to_string())
}

/// Decrypt a file from a chunk-plan JSON + ciphertexts JSON.
/// This is the NAPI equivalent of WASM's `decrypt_file_wasm`.
#[napi(js_name = decryptFile)]
pub fn decrypt_file_json(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: i64,
    access_context_snapshot_hash_hex: String,
    chunk_plan_json: String,
    ciphertexts_hex_json: String,
) -> Result<Buffer, napi::Error> {
    let version_dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex).map_err(to_napi_error)?;
    let version_id =
        kchat_drive_types::VersionId::from_hex(&version_id_hex).map_err(to_napi_error)?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| invalid_input(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("drive_id must be 16 bytes".to_string()))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;

    let plan_value: serde_json::Value = serde_json::from_str(&chunk_plan_json)
        .map_err(|e| invalid_input(format!("invalid chunk_plan_json: {}", e)))?;
    let chunks_arr = plan_value["chunks"]
        .as_array()
        .ok_or_else(|| invalid_input("chunk_plan_json missing chunks array".to_string()))?;

    let chunk_plan = kchat_drive_types::ChunkPlan {
        chunks: chunks_arr
            .iter()
            .map(|c| {
                let ct_hash_hex = c["ciphertextSha256"]
                    .as_str()
                    .ok_or_else(|| invalid_input("ciphertextSha256 missing".to_string()))?;
                let ct_hash = hex::decode(ct_hash_hex)
                    .map_err(|e| invalid_input(format!("invalid ciphertextSha256: {}", e)))?;
                if ct_hash.len() != 32 {
                    return Err(invalid_input("ciphertextSha256 must be 32 bytes".to_string()));
                }
                Ok(kchat_drive_types::ChunkDescriptor {
                    index: c["index"].as_u64().unwrap_or(0),
                    plaintext_len: c["plaintextLen"].as_u64().unwrap_or(0),
                    ciphertext_len: c["ciphertextLen"].as_u64().unwrap_or(0),
                    ciphertext_sha256: kchat_drive_types::Hash256::from_slice(&ct_hash),
                    blob_key: c["blobKey"].as_str().unwrap_or("").to_string(),
                })
            })
            .collect::<Result<_, _>>()?,
    };

    let ct_hex_arr: Vec<String> = serde_json::from_str(&ciphertexts_hex_json)
        .map_err(|e| invalid_input(format!("invalid ciphertexts_hex_json: {}", e)))?;
    let ciphertexts: Vec<Vec<u8>> = ct_hex_arr
        .iter()
        .map(|h| hex::decode(h).map_err(|e| invalid_input(format!("invalid ciphertext hex: {}", e))))
        .collect::<Result<_, _>>()?;

    let plaintext = kchat_drive_crypto::decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision as u64,
        &snapshot_hash,
        &chunk_plan,
        &ciphertexts,
    )
    .map_err(to_napi_error)?;

    Ok(Buffer::from(plaintext))
}

/// Generate a DomainKey. Returns JSON { domain_key_hex, generation }.
#[napi(js_name = generateDomainKey)]
pub fn generate_domain_key_napi(domain_id_hex: String) -> Result<String, napi::Error> {
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;
    let record = kchat_drive_crypto::generate_domain_key(domain_id);
    let result = serde_json::json!({
        "domain_key_hex": hex::encode(record.key.as_bytes()),
        "generation": record.generation,
    });
    Ok(result.to_string())
}

/// Generate a ShareGrantKey. Returns JSON { share_grant_key_hex, generation }.
#[napi(js_name = generateShareGrantKey)]
pub fn generate_share_grant_key_napi(
    grant_id_hex: String,
    recipients_json: String,
    user_snapshot_hash_hex: String,
    mls_epoch: i64,
    mls_tree_hash_hex: String,
) -> Result<String, napi::Error> {
    let grant_id =
        kchat_drive_types::ShareGrantId::from_hex(&grant_id_hex).map_err(to_napi_error)?;
    let recipients: Vec<String> = serde_json::from_str(&recipients_json)
        .map_err(|e| invalid_input(format!("invalid recipients: {}", e)))?;
    let recipients: Vec<kchat_drive_types::UserId> = recipients
        .iter()
        .map(|s| kchat_drive_types::UserId::from_hex(s))
        .collect::<Result<_, _>>()
        .map_err(|e| invalid_input(format!("invalid recipient id: {}", e)))?;
    let snapshot_hash = hex::decode(&user_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;
    let tree_hash = hex::decode(&mls_tree_hash_hex)
        .map_err(|e| invalid_input(format!("invalid tree_hash: {}", e)))?;
    let tree_hash: [u8; 32] = tree_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("tree_hash must be 32 bytes".to_string()))?;

    let record = kchat_drive_crypto::generate_share_grant_key(
        grant_id,
        &recipients,
        &kchat_drive_types::Hash256::new(snapshot_hash),
        mls_epoch as u64,
        &kchat_drive_types::Hash256::new(tree_hash),
    );

    let result = serde_json::json!({
        "share_grant_key_hex": hex::encode(record.key.as_bytes()),
        "generation": record.generation,
    });
    Ok(result.to_string())
}

/// Wrap a version DEK under a domain key. Returns JSON { wrapped_dek_hex, wrap_nonce_hex }.
#[napi(js_name = wrapDekUnderDomainKey)]
pub fn wrap_dek_under_domain_key_napi(
    domain_key_hex: String,
    version_dek_hex: String,
) -> Result<String, napi::Error> {
    let dk = hex::decode(&domain_key_hex)
        .map_err(|e| invalid_input(format!("invalid domain_key: {}", e)))?;
    let dk: [u8; 32] = dk
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("domain_key must be 32 bytes".to_string()))?;
    let dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let dek: [u8; 32] = dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let domain_key = kchat_drive_types::Key256::new(dk);
    let (wrapped, nonce) =
        kchat_drive_crypto::wrap_version_dek_under_domain_key(&domain_key, &dek)
            .map_err(to_napi_error)?;

    let result = serde_json::json!({
        "wrapped_dek_hex": hex::encode(&wrapped),
        "wrap_nonce_hex": hex::encode(nonce.as_bytes()),
    });
    Ok(result.to_string())
}

/// Unwrap a version DEK from a domain key. Returns the DEK hex.
#[napi(js_name = unwrapDekFromDomainKey)]
pub fn unwrap_dek_from_domain_key_napi(
    domain_key_hex: String,
    wrapped_dek_hex: String,
    wrap_nonce_hex: String,
) -> Result<String, napi::Error> {
    let dk = hex::decode(&domain_key_hex)
        .map_err(|e| invalid_input(format!("invalid domain_key: {}", e)))?;
    let dk: [u8; 32] = dk
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("domain_key must be 32 bytes".to_string()))?;
    let wrapped = hex::decode(&wrapped_dek_hex)
        .map_err(|e| invalid_input(format!("invalid wrapped_dek: {}", e)))?;
    let nonce_bytes = hex::decode(&wrap_nonce_hex)
        .map_err(|e| invalid_input(format!("invalid wrap_nonce: {}", e)))?;
    let nonce_bytes: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("wrap_nonce must be 12 bytes".to_string()))?;

    let domain_key = kchat_drive_types::Key256::new(dk);
    let dek = kchat_drive_crypto::unwrap_version_dek_from_domain_key(
        &domain_key,
        &wrapped,
        &kchat_drive_types::Nonce12::new(nonce_bytes),
    )
    .map_err(to_napi_error)?;
    Ok(hex::encode(dek))
}

/// Wrap a version DEK under a share grant key. Returns JSON { wrapped_dek_hex, wrap_nonce_hex }.
#[napi(js_name = wrapDekUnderShareGrantKey)]
pub fn wrap_dek_under_share_grant_key_napi(
    share_grant_key_hex: String,
    version_dek_hex: String,
) -> Result<String, napi::Error> {
    let sgk = hex::decode(&share_grant_key_hex)
        .map_err(|e| invalid_input(format!("invalid share_grant_key: {}", e)))?;
    let sgk: [u8; 32] = sgk
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("share_grant_key must be 32 bytes".to_string()))?;
    let dek = hex::decode(&version_dek_hex)
        .map_err(|e| invalid_input(format!("invalid version_dek: {}", e)))?;
    let dek: [u8; 32] = dek
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("version_dek must be 32 bytes".to_string()))?;

    let share_grant_key = kchat_drive_types::Key256::new(sgk);
    let (wrapped, nonce) =
        kchat_drive_crypto::wrap_version_dek_under_share_grant_key(&share_grant_key, &dek)
            .map_err(to_napi_error)?;

    let result = serde_json::json!({
        "wrapped_dek_hex": hex::encode(&wrapped),
        "wrap_nonce_hex": hex::encode(nonce.as_bytes()),
    });
    Ok(result.to_string())
}

/// Unwrap a version DEK from a share grant key. Returns the DEK hex.
#[napi(js_name = unwrapDekFromShareGrantKey)]
pub fn unwrap_dek_from_share_grant_key_napi(
    share_grant_key_hex: String,
    wrapped_dek_hex: String,
    wrap_nonce_hex: String,
) -> Result<String, napi::Error> {
    let sgk = hex::decode(&share_grant_key_hex)
        .map_err(|e| invalid_input(format!("invalid share_grant_key: {}", e)))?;
    let sgk: [u8; 32] = sgk
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("share_grant_key must be 32 bytes".to_string()))?;
    let wrapped = hex::decode(&wrapped_dek_hex)
        .map_err(|e| invalid_input(format!("invalid wrapped_dek: {}", e)))?;
    let nonce_bytes = hex::decode(&wrap_nonce_hex)
        .map_err(|e| invalid_input(format!("invalid wrap_nonce: {}", e)))?;
    let nonce_bytes: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("wrap_nonce must be 12 bytes".to_string()))?;

    let share_grant_key = kchat_drive_types::Key256::new(sgk);
    let dek = kchat_drive_crypto::unwrap_version_dek_from_share_grant_key(
        &share_grant_key,
        &wrapped,
        &kchat_drive_types::Nonce12::new(nonce_bytes),
    )
    .map_err(to_napi_error)?;
    Ok(hex::encode(dek))
}

/// Sign a version header with an Ed25519 signing key.
/// Returns JSON { signed_header_cbor_hex, signature_hex, verifying_key_hex }.
#[napi(js_name = signHeader)]
pub fn sign_header_napi(
    header_cbor_hex: String,
    signing_key_hex: String,
) -> Result<String, napi::Error> {
    let header_bytes = hex::decode(&header_cbor_hex)
        .map_err(|e| invalid_input(format!("invalid header_cbor: {}", e)))?;
    let mut header: kchat_drive_types::PublicVersionHeader = minicbor::decode(&header_bytes)
        .map_err(|e| invalid_input(format!("invalid header: {}", e)))?;
    let sk_bytes = hex::decode(&signing_key_hex)
        .map_err(|e| invalid_input(format!("invalid signing_key: {}", e)))?;
    let sk_bytes: [u8; 32] = sk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("signing_key must be 32 bytes".to_string()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);

    let sig = kchat_drive_crypto::sign_header(&header, &signing_key).map_err(to_napi_error)?;
    let sig_bytes = sig.as_bytes().to_vec();
    header.signature = Some(sig);

    let mut signed_buf = Vec::new();
    minicbor::encode(&header, &mut signed_buf)
        .map_err(|e| invalid_input(format!("encode header: {}", e)))?;

    let verifying_key = signing_key.verifying_key();
    let result = serde_json::json!({
        "signed_header_cbor_hex": hex::encode(&signed_buf),
        "signature_hex": hex::encode(&sig_bytes),
        "verifying_key_hex": hex::encode(verifying_key.to_bytes()),
    });
    Ok(result.to_string())
}

/// Verify a signed version header against an Ed25519 verifying key.
#[napi(js_name = verifyHeader)]
pub fn verify_header_napi(
    header_cbor_hex: String,
    verifying_key_hex: String,
) -> Result<bool, napi::Error> {
    let header_bytes = hex::decode(&header_cbor_hex)
        .map_err(|e| invalid_input(format!("invalid header_cbor: {}", e)))?;
    let header: kchat_drive_types::PublicVersionHeader = minicbor::decode(&header_bytes)
        .map_err(|e| invalid_input(format!("invalid header: {}", e)))?;
    let vk_bytes = hex::decode(&verifying_key_hex)
        .map_err(|e| invalid_input(format!("invalid verifying_key: {}", e)))?;
    let vk_bytes: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("verifying_key must be 32 bytes".to_string()))?;

    let pk = kchat_drive_types::Ed25519PublicKey::new(vk_bytes);
    let valid = kchat_drive_crypto::verify_header(&header, &pk).map_err(to_napi_error)?;
    Ok(valid)
}
