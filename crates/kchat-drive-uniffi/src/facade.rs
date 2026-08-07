use crate::error::DriveSdkError;
use uniffi;

/// UniFFI-exposed Drive facade for iOS/Android.
/// These are the functions callable from Swift/Kotlin.

#[derive(Debug, Clone, uniffi::Record)]
pub struct UploadResultFfi {
    pub version_id_hex: String,
    pub chunk_plan_root_hex: String,
    pub chunk_count: u64,
    pub manifest_ciphertext_hex: String,
    pub manifest_nonce_hex: String,
    pub header_cbor_hex: String,
    pub ciphertexts_hex: Vec<String>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct DownloadResultFfi {
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct KeyPairFfi {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

#[uniffi::export]
pub fn generate_version_dek() -> String {
    hex::encode(kchat_drive_crypto::generate_key())
}

#[uniffi::export]
pub fn generate_hpke_keypair() -> KeyPairFfi {
    let (priv_key, pub_key) = kchat_drive_crypto::hpke::generate_keypair();
    KeyPairFfi {
        private_key_hex: hex::encode(priv_key),
        public_key_hex: hex::encode(pub_key),
    }
}

#[uniffi::export]
pub fn generate_ed25519_keypair() -> KeyPairFfi {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    KeyPairFfi {
        private_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
    }
}

#[uniffi::export]
pub fn random_id_hex() -> String {
    kchat_drive_types::OpaqueId::random().to_hex()
}

#[uniffi::export]
pub fn select_chunk_size(file_size: u64) -> u64 {
    kchat_drive_crypto::select_chunk_size(file_size)
}

#[uniffi::export]
pub fn encrypt_file(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: u64,
    access_context_snapshot_hash_hex: String,
    plaintext: Vec<u8>,
) -> Result<UploadResultFfi, DriveSdkError> {
    let version_dek = hex::decode(&version_dek_hex).map_err(|e| DriveSdkError::InvalidState {
        msg: format!("invalid version_dek: {}", e),
    })?;
    let version_dek: [u8; 32] =
        version_dek
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "version_dek must be 32 bytes".into(),
            })?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex)?;
    let version_id = kchat_drive_types::VersionId::from_hex(&version_id_hex)?;
    let drive_id = hex::decode(&drive_id_hex).map_err(|e| DriveSdkError::InvalidState {
        msg: format!("invalid drive_id: {}", e),
    })?;
    let drive_id: [u8; 16] =
        drive_id
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "drive_id must be 16 bytes".into(),
            })?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex).map_err(|e| {
        DriveSdkError::InvalidState {
            msg: format!("invalid snapshot_hash: {}", e),
        }
    })?;
    let snapshot_hash: [u8; 32] =
        snapshot_hash
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "snapshot_hash must be 32 bytes".into(),
            })?;

    let (chunk_plan, ciphertexts) = kchat_drive_crypto::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &snapshot_hash,
        &plaintext,
    )?;

    let root = chunk_plan.merkle_root();

    // Encrypt manifest.
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

    let (manifest_ct, manifest_nonce) =
        kchat_drive_crypto::encrypt_manifest(&version_dek, &node_id, &version_id, &manifest)?;

    Ok(UploadResultFfi {
        version_id_hex: version_id.to_hex(),
        chunk_plan_root_hex: root.to_hex(),
        chunk_count: chunk_plan.chunks.len() as u64,
        manifest_ciphertext_hex: hex::encode(&manifest_ct),
        manifest_nonce_hex: hex::encode(manifest_nonce.as_bytes()),
        header_cbor_hex: String::new(), // Header is built by the caller with signing
        ciphertexts_hex: ciphertexts.iter().map(hex::encode).collect(),
    })
}

#[uniffi::export]
pub fn decrypt_file(
    version_dek_hex: String,
    node_id_hex: String,
    version_id_hex: String,
    drive_id_hex: String,
    domain_id_hex: String,
    access_context_revision: u64,
    access_context_snapshot_hash_hex: String,
    manifest_ciphertext_hex: String,
    manifest_nonce_hex: String,
    ciphertexts_hex: Vec<String>,
) -> Result<DownloadResultFfi, DriveSdkError> {
    let version_dek = hex::decode(&version_dek_hex).map_err(|e| DriveSdkError::InvalidState {
        msg: format!("invalid version_dek: {}", e),
    })?;
    let version_dek: [u8; 32] =
        version_dek
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "version_dek must be 32 bytes".into(),
            })?;

    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex)?;
    let version_id = kchat_drive_types::VersionId::from_hex(&version_id_hex)?;
    let drive_id = hex::decode(&drive_id_hex).map_err(|e| DriveSdkError::InvalidState {
        msg: format!("invalid drive_id: {}", e),
    })?;
    let drive_id: [u8; 16] =
        drive_id
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "drive_id must be 16 bytes".into(),
            })?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)?;
    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex).map_err(|e| {
        DriveSdkError::InvalidState {
            msg: format!("invalid snapshot_hash: {}", e),
        }
    })?;
    let snapshot_hash: [u8; 32] =
        snapshot_hash
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "snapshot_hash must be 32 bytes".into(),
            })?;

    let manifest_ct =
        hex::decode(&manifest_ciphertext_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid manifest_ciphertext: {}", e),
        })?;
    let manifest_nonce_bytes =
        hex::decode(&manifest_nonce_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid manifest_nonce: {}", e),
        })?;
    let manifest_nonce_bytes: [u8; 12] =
        manifest_nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DriveSdkError::InvalidState {
                msg: "manifest_nonce must be 12 bytes".into(),
            })?;
    let manifest_nonce = kchat_drive_types::Nonce12::new(manifest_nonce_bytes);

    let manifest = kchat_drive_crypto::decrypt_manifest(
        &version_dek,
        &node_id,
        &version_id,
        &manifest_ct,
        &manifest_nonce,
    )?;

    let ciphertexts: Vec<Vec<u8>> = ciphertexts_hex
        .iter()
        .map(|h| hex::decode(h).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid ciphertext hex: {}", e),
        }))
        .collect::<Result<_, _>>()?;

    let plaintext = kchat_drive_crypto::decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &snapshot_hash,
        &manifest.chunk_plan,
        &ciphertexts,
    )?;

    Ok(DownloadResultFfi { plaintext })
}

#[uniffi::export]
pub fn get_test_vectors_json() -> String {
    kchat_drive_crypto::vector::all_vectors_json()
}
