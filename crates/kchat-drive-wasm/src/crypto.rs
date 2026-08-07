use wasm_bindgen::prelude::*;

/// WASM-exposed crypto operations for KChat Drive.
/// These are the browser-callable functions for KDRV1 encryption/decryption.

#[wasm_bindgen]
pub fn generate_version_dek() -> String {
    let key = kchat_drive_crypto::generate_key();
    hex::encode(key)
}

#[wasm_bindgen]
pub fn select_chunk_size(file_size: u64) -> u64 {
    kchat_drive_crypto::select_chunk_size(file_size)
}

#[wasm_bindgen]
pub fn chunk_count(file_size: u64, chunk_size: u64) -> u64 {
    kchat_drive_crypto::chunk_count(file_size, chunk_size)
}

#[wasm_bindgen]
pub fn encrypt_file_wasm(
    version_dek_hex: &str,
    node_id_hex: &str,
    version_id_hex: &str,
    drive_id_hex: &str,
    domain_id_hex: &str,
    access_context_revision: u64,
    access_context_snapshot_hash_hex: &str,
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    let version_dek = hex::decode(version_dek_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;

    let node_id = kchat_drive_types::NodeId::from_hex(node_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(version_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let drive_id = hex::decode(drive_id_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("drive_id must be 16 bytes"))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let snapshot_hash = hex::decode(access_context_snapshot_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("snapshot_hash must be 32 bytes"))?;

    let (chunk_plan, ciphertexts) = kchat_drive_crypto::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &snapshot_hash,
        plaintext,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

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

    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_file_wasm(
    version_dek_hex: &str,
    node_id_hex: &str,
    version_id_hex: &str,
    drive_id_hex: &str,
    domain_id_hex: &str,
    access_context_revision: u64,
    access_context_snapshot_hash_hex: &str,
    chunk_plan_json: &str,
    ciphertexts_hex_json: &str,
) -> Result<Vec<u8>, JsValue> {
    let version_dek = hex::decode(version_dek_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;

    let node_id = kchat_drive_types::NodeId::from_hex(node_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(version_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let drive_id = hex::decode(drive_id_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid drive_id: {}", e)))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("drive_id must be 16 bytes"))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    let snapshot_hash = hex::decode(access_context_snapshot_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| JsValue::from_str("snapshot_hash must be 32 bytes"))?;

    // Parse chunk plan JSON.
    let plan_value: serde_json::Value = serde_json::from_str(chunk_plan_json)
        .map_err(|e| JsValue::from_str(&format!("invalid chunk_plan_json: {}", e)))?;
    let chunks_arr = plan_value["chunks"]
        .as_array()
        .ok_or(JsValue::from_str("chunk_plan_json missing chunks array"))?;

    let chunk_plan = kchat_drive_types::ChunkPlan {
        chunks: chunks_arr
            .iter()
            .map(|c| {
                let ct_hash_hex = c["ciphertextSha256"].as_str().ok_or(JsValue::from_str("ciphertextSha256 missing or not a string"))?;
                let ct_hash = hex::decode(ct_hash_hex).map_err(|e| JsValue::from_str(&format!("invalid ciphertextSha256: {}", e)))?;
                if ct_hash.len() != 32 {
                    return Err(JsValue::from_str("ciphertextSha256 must be 32 bytes"));
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

    // Parse ciphertexts.
    let ct_hex_arr: Vec<String> = serde_json::from_str(ciphertexts_hex_json)
        .map_err(|e| JsValue::from_str(&format!("invalid ciphertexts_hex_json: {}", e)))?;
    let ciphertexts: Vec<Vec<u8>> = ct_hex_arr
        .iter()
        .map(|h| hex::decode(h).map_err(|e| JsValue::from_str(&format!("invalid ciphertext hex: {}", e))))
        .collect::<Result<_, _>>()?;

    let plaintext = kchat_drive_crypto::decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &snapshot_hash,
        &chunk_plan,
        &ciphertexts,
    )
    .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext)
}

#[wasm_bindgen]
pub fn get_test_vectors_json() -> String {
    kchat_drive_crypto::vector::all_vectors_json()
}

#[wasm_bindgen]
pub fn wrap_dek_under_domain_key(domain_key_hex: &str, version_dek_hex: &str) -> Result<JsValue, JsValue> {
    let dk = hex::decode(domain_key_hex).map_err(|e| JsValue::from_str(&format!("invalid domain_key: {}", e)))?;
    let dk: [u8; 32] = dk.as_slice().try_into().map_err(|_| JsValue::from_str("domain_key must be 32 bytes"))?;
    let dek = hex::decode(version_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let dek: [u8; 32] = dek.as_slice().try_into().map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;

    let domain_key = kchat_drive_types::Key256::new(dk);
    let (wrapped, nonce) = kchat_drive_crypto::wrap_version_dek_under_domain_key(&domain_key, &dek)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "wrapped_dek_hex": hex::encode(&wrapped),
        "wrap_nonce_hex": hex::encode(nonce.as_bytes()),
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn unwrap_dek_from_domain_key(domain_key_hex: &str, wrapped_dek_hex: &str, wrap_nonce_hex: &str) -> Result<String, JsValue> {
    let dk = hex::decode(domain_key_hex).map_err(|e| JsValue::from_str(&format!("invalid domain_key: {}", e)))?;
    let dk: [u8; 32] = dk.as_slice().try_into().map_err(|_| JsValue::from_str("domain_key must be 32 bytes"))?;
    let wrapped = hex::decode(wrapped_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid wrapped_dek: {}", e)))?;
    let nonce_bytes = hex::decode(wrap_nonce_hex).map_err(|e| JsValue::from_str(&format!("invalid wrap_nonce: {}", e)))?;
    let nonce_bytes: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("wrap_nonce must be 12 bytes"))?;

    let domain_key = kchat_drive_types::Key256::new(dk);
    let dek = kchat_drive_crypto::unwrap_version_dek_from_domain_key(&domain_key, &wrapped, &kchat_drive_types::Nonce12::new(nonce_bytes))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(dek))
}

#[wasm_bindgen]
pub fn wrap_dek_under_share_grant_key(share_grant_key_hex: &str, version_dek_hex: &str) -> Result<JsValue, JsValue> {
    let sgk = hex::decode(share_grant_key_hex).map_err(|e| JsValue::from_str(&format!("invalid share_grant_key: {}", e)))?;
    let sgk: [u8; 32] = sgk.as_slice().try_into().map_err(|_| JsValue::from_str("share_grant_key must be 32 bytes"))?;
    let dek = hex::decode(version_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let dek: [u8; 32] = dek.as_slice().try_into().map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;

    let share_grant_key = kchat_drive_types::Key256::new(sgk);
    let (wrapped, nonce) = kchat_drive_crypto::wrap_version_dek_under_share_grant_key(&share_grant_key, &dek)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "wrapped_dek_hex": hex::encode(&wrapped),
        "wrap_nonce_hex": hex::encode(nonce.as_bytes()),
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn unwrap_dek_from_share_grant_key(share_grant_key_hex: &str, wrapped_dek_hex: &str, wrap_nonce_hex: &str) -> Result<String, JsValue> {
    let sgk = hex::decode(share_grant_key_hex).map_err(|e| JsValue::from_str(&format!("invalid share_grant_key: {}", e)))?;
    let sgk: [u8; 32] = sgk.as_slice().try_into().map_err(|_| JsValue::from_str("share_grant_key must be 32 bytes"))?;
    let wrapped = hex::decode(wrapped_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid wrapped_dek: {}", e)))?;
    let nonce_bytes = hex::decode(wrap_nonce_hex).map_err(|e| JsValue::from_str(&format!("invalid wrap_nonce: {}", e)))?;
    let nonce_bytes: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("wrap_nonce must be 12 bytes"))?;

    let share_grant_key = kchat_drive_types::Key256::new(sgk);
    let dek = kchat_drive_crypto::unwrap_version_dek_from_share_grant_key(&share_grant_key, &wrapped, &kchat_drive_types::Nonce12::new(nonce_bytes))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(hex::encode(dek))
}

#[wasm_bindgen]
pub fn encrypt_manifest_wasm(version_dek_hex: &str, node_id_hex: &str, version_id_hex: &str, manifest_cbor_hex: &str) -> Result<JsValue, JsValue> {
    let version_dek = hex::decode(version_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek.as_slice().try_into().map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;
    let node_id = kchat_drive_types::NodeId::from_hex(node_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(version_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let manifest_bytes = hex::decode(manifest_cbor_hex).map_err(|e| JsValue::from_str(&format!("invalid manifest_cbor: {}", e)))?;
    let manifest: kchat_drive_types::Manifest = minicbor::decode(&manifest_bytes).map_err(|e| JsValue::from_str(&format!("invalid manifest CBOR: {}", e)))?;

    let (ct, nonce) = kchat_drive_crypto::encrypt_manifest(&version_dek, &node_id, &version_id, &manifest)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = serde_json::json!({
        "manifest_ciphertext_hex": hex::encode(&ct),
        "manifest_nonce_hex": hex::encode(nonce.as_bytes()),
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn decrypt_manifest_wasm(version_dek_hex: &str, node_id_hex: &str, version_id_hex: &str, manifest_ct_hex: &str, manifest_nonce_hex: &str) -> Result<String, JsValue> {
    let version_dek = hex::decode(version_dek_hex).map_err(|e| JsValue::from_str(&format!("invalid version_dek: {}", e)))?;
    let version_dek: [u8; 32] = version_dek.as_slice().try_into().map_err(|_| JsValue::from_str("version_dek must be 32 bytes"))?;
    let node_id = kchat_drive_types::NodeId::from_hex(node_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let version_id = kchat_drive_types::VersionId::from_hex(version_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let ct = hex::decode(manifest_ct_hex).map_err(|e| JsValue::from_str(&format!("invalid manifest_ct: {}", e)))?;
    let nonce_bytes = hex::decode(manifest_nonce_hex).map_err(|e| JsValue::from_str(&format!("invalid manifest_nonce: {}", e)))?;
    let nonce_bytes: [u8; 12] = nonce_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("manifest_nonce must be 12 bytes"))?;

    let manifest = kchat_drive_crypto::decrypt_manifest(&version_dek, &node_id, &version_id, &ct, &kchat_drive_types::Nonce12::new(nonce_bytes))
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut buf = Vec::new();
    minicbor::encode(&manifest, &mut buf).map_err(|e| JsValue::from_str(&format!("encode manifest: {}", e)))?;
    Ok(hex::encode(&buf))
}

#[wasm_bindgen]
pub fn sign_header_wasm(header_cbor_hex: &str, signing_key_hex: &str) -> Result<JsValue, JsValue> {
    let header_bytes = hex::decode(header_cbor_hex).map_err(|e| JsValue::from_str(&format!("invalid header_cbor: {}", e)))?;
    let mut header: kchat_drive_types::PublicVersionHeader = minicbor::decode(&header_bytes).map_err(|e| JsValue::from_str(&format!("invalid header: {}", e)))?;
    let sk_bytes = hex::decode(signing_key_hex).map_err(|e| JsValue::from_str(&format!("invalid signing_key: {}", e)))?;
    let sk_bytes: [u8; 32] = sk_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("signing_key must be 32 bytes"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);

    let sig = kchat_drive_crypto::sign_header(&header, &signing_key).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let sig_bytes = sig.as_bytes().to_vec();
    header.signature = Some(sig);

    let mut signed_buf = Vec::new();
    minicbor::encode(&header, &mut signed_buf).map_err(|e| JsValue::from_str(&format!("encode header: {}", e)))?;

    let verifying_key = signing_key.verifying_key();
    let result = serde_json::json!({
        "signed_header_cbor_hex": hex::encode(&signed_buf),
        "signature_hex": hex::encode(&sig_bytes),
        "verifying_key_hex": hex::encode(verifying_key.to_bytes()),
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn verify_header_wasm(header_cbor_hex: &str, verifying_key_hex: &str) -> Result<bool, JsValue> {
    let header_bytes = hex::decode(header_cbor_hex).map_err(|e| JsValue::from_str(&format!("invalid header_cbor: {}", e)))?;
    let header: kchat_drive_types::PublicVersionHeader = minicbor::decode(&header_bytes).map_err(|e| JsValue::from_str(&format!("invalid header: {}", e)))?;
    let vk_bytes = hex::decode(verifying_key_hex).map_err(|e| JsValue::from_str(&format!("invalid verifying_key: {}", e)))?;
    let vk_bytes: [u8; 32] = vk_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("verifying_key must be 32 bytes"))?;

    let pk = kchat_drive_types::Ed25519PublicKey::new(vk_bytes);
    let valid = kchat_drive_crypto::verify_header(&header, &pk).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(valid)
}

#[wasm_bindgen]
pub fn generate_domain_key_wasm(domain_id_hex: &str) -> Result<JsValue, JsValue> {
    let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let record = kchat_drive_crypto::generate_domain_key(domain_id);
    let result = serde_json::json!({
        "domain_key_hex": hex::encode(record.key.as_bytes()),
        "generation": record.generation,
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn rotate_domain_key_wasm(current_key_hex: &str, domain_id_hex: &str, current_generation: u64) -> Result<JsValue, JsValue> {
    let key_bytes = hex::decode(current_key_hex).map_err(|e| JsValue::from_str(&format!("invalid key: {}", e)))?;
    let key_bytes: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| JsValue::from_str("key must be 32 bytes"))?;
    let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let current = kchat_drive_types::DomainKeyRecord {
        domain_id,
        generation: current_generation,
        key: kchat_drive_types::Key256::new(key_bytes),
        prev_envelope: None,
        prev_envelope_nonce: None,
        is_checkpoint: current_generation.is_multiple_of(32),
    };

    let new_record = kchat_drive_crypto::rotate_domain_key(&current).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let result = serde_json::json!({
        "domain_key_hex": hex::encode(new_record.key.as_bytes()),
        "generation": new_record.generation,
        "prev_envelope_hex": new_record.prev_envelope.as_ref().map(hex::encode).unwrap_or_default(),
        "prev_envelope_nonce_hex": new_record.prev_envelope_nonce.as_ref().map(|n| hex::encode(n.as_bytes())).unwrap_or_default(),
    });
    Ok(JsValue::from_str(&result.to_string()))
}

#[wasm_bindgen]
pub fn generate_share_grant_key_wasm(grant_id_hex: &str, recipients_json: &str, user_snapshot_hash_hex: &str, mls_epoch: u64, mls_tree_hash_hex: &str) -> Result<JsValue, JsValue> {
    let grant_id = kchat_drive_types::ShareGrantId::from_hex(grant_id_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let recipients: Vec<String> = serde_json::from_str(recipients_json).map_err(|e| JsValue::from_str(&format!("invalid recipients: {}", e)))?;
    let recipients: Vec<kchat_drive_types::UserId> = recipients
        .iter()
        .map(|s| kchat_drive_types::UserId::from_hex(s))
        .collect::<Result<_, _>>()
        .map_err(|e| JsValue::from_str(&format!("invalid recipient id: {}", e)))?;
    let snapshot_hash = hex::decode(user_snapshot_hash_hex).map_err(|e| JsValue::from_str(&format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash.as_slice().try_into().map_err(|_| JsValue::from_str("snapshot_hash must be 32 bytes"))?;
    let tree_hash = hex::decode(mls_tree_hash_hex).map_err(|e| JsValue::from_str(&format!("invalid tree_hash: {}", e)))?;
    let tree_hash: [u8; 32] = tree_hash.as_slice().try_into().map_err(|_| JsValue::from_str("tree_hash must be 32 bytes"))?;

    let record = kchat_drive_crypto::generate_share_grant_key(
        grant_id,
        &recipients,
        &kchat_drive_types::Hash256::new(snapshot_hash),
        mls_epoch,
        &kchat_drive_types::Hash256::new(tree_hash),
    );

    let result = serde_json::json!({
        "share_grant_key_hex": hex::encode(record.key.as_bytes()),
        "generation": record.generation,
    });
    Ok(JsValue::from_str(&result.to_string()))
}
