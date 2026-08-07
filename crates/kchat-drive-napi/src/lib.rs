#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_arguments)]

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
        .map_err(|e| napi::Error::from_reason(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("version_dek must be 32 bytes"))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(&version_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("drive_id must be 16 bytes"))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("snapshot_hash must be 32 bytes"))?;

    let (chunk_plan, ciphertexts) = kchat_drive_crypto::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision as u64,
        &snapshot_hash,
        &plaintext,
    ).map_err(|e| napi::Error::from_reason(e.to_string()))?;

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
    };

    let (manifest_ct, manifest_nonce) = kchat_drive_crypto::encrypt_manifest(
        &version_dek, &node_id, &version_id, &manifest,
    ).map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(EncryptResult {
        version_id_hex: version_id.to_hex(),
        chunk_plan_root_hex: root.to_hex(),
        chunk_count: chunk_plan.chunks.len() as i64,
        manifest_ciphertext_hex: hex::encode(&manifest_ct),
        manifest_nonce_hex: hex::encode(manifest_nonce.as_bytes()),
        ciphertexts_hex: ciphertexts.iter().map(hex::encode).collect(),
    })
}

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
        .map_err(|e| napi::Error::from_reason(format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("version_dek must be 32 bytes"))?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(&version_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let drive_id = hex::decode(&drive_id_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("drive_id must be 16 bytes"))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)
        .map_err(|e| napi::Error::from_reason(e.to_string()))?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("snapshot_hash must be 32 bytes"))?;

    let manifest_ct = hex::decode(&manifest_ciphertext_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid manifest_ciphertext: {}", e)))?;
    let manifest_nonce_bytes = hex::decode(&manifest_nonce_hex)
        .map_err(|e| napi::Error::from_reason(format!("invalid manifest_nonce: {}", e)))?;
    let manifest_nonce_bytes: [u8; 12] = manifest_nonce_bytes.as_slice().try_into()
        .map_err(|_| napi::Error::from_reason("manifest_nonce must be 12 bytes"))?;
    let manifest_nonce = kchat_drive_types::Nonce12::new(manifest_nonce_bytes);

    let manifest = kchat_drive_crypto::decrypt_manifest(
        &version_dek, &node_id, &version_id, &manifest_ct, &manifest_nonce,
    ).map_err(|e| napi::Error::from_reason(e.to_string()))?;

    let ciphertexts: Vec<Vec<u8>> = ciphertexts_hex
        .iter()
        .map(|h| hex::decode(h).map_err(|e| napi::Error::from_reason(format!("invalid ciphertext hex: {}", e))))
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
    ).map_err(|e| napi::Error::from_reason(e.to_string()))?;

    Ok(Buffer::from(plaintext))
}
