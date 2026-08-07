use kchat_drive_crypto::{
    decrypt_file, decrypt_manifest, encrypt_file, encrypt_manifest,
    generate_domain_key, generate_key, generate_share_grant_key, rotate_domain_key,
    rotate_share_grant_key, select_chunk_size, sign_header,
    wrap_version_dek_under_domain_key,
    wrap_version_dek_under_share_grant_key,
};
use kchat_drive_types::{
    DomainId, DriveError, DriveId, Ed25519PublicKey, Hash256, NodeId, Nonce12, PrivacyMode,
    PublicVersionHeader, VersionId,
};
use kchat_drive_types::{Key256, ShareGrantId, UserId};

use crate::runtime::ClientRuntime;

/// Drive facade: high-level API for Drive operations.
/// This is the unified facade that bindings (UniFFI/NAPI/WASM) expose.
/// It owns a reference to the ClientRuntime and delegates all
/// state mutations through it.
pub struct DriveFacade {
    runtime: std::sync::Arc<ClientRuntime>,
}

/// Result of an upload operation.
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub version_id: VersionId,
    pub chunk_plan_root: Hash256,
    pub chunk_count: u64,
    pub manifest_ciphertext: Vec<u8>,
    pub manifest_nonce: Nonce12,
    pub header: PublicVersionHeader,
    pub ciphertexts: Vec<Vec<u8>>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Nonce12,
}

/// Result of a download operation.
#[derive(Debug, Clone)]
pub struct DownloadResult {
    pub plaintext: Vec<u8>,
}

impl DriveFacade {
    pub fn new(runtime: std::sync::Arc<ClientRuntime>) -> Self {
        Self { runtime }
    }

    /// Uploads a file: encrypts with KDRV1, creates signed version header.
    /// The wrapping key depends on the privacy mode:
    /// - Secured/Advanced: DomainKey
    /// - Max: ShareGrantKey
    pub fn upload(
        &self,
        drive_id: &DriveId,
        node_id: &NodeId,
        domain_id: &DomainId,
        privacy_mode: PrivacyMode,
        plaintext: &[u8],
        creator_device_key: &Ed25519PublicKey,
        signing_key: &ed25519_dalek::SigningKey,
        access_context_revision: u64,
        access_context_snapshot_hash: &[u8; 32],
        wrapping_key: &Key256,
    ) -> Result<UploadResult, DriveError> {
        let version_id = VersionId::random();
        let version_dek = generate_key();

        // Encrypt file into chunks.
        let (chunk_plan, ciphertexts) = encrypt_file(
            &version_dek,
            node_id,
            &version_id,
            drive_id.as_bytes(),
            domain_id,
            access_context_revision,
            access_context_snapshot_hash,
            plaintext,
        )?;

        let chunk_plan_root = chunk_plan.merkle_root();

        // Encrypt manifest.
        let manifest = kchat_drive_types::Manifest {
            version_id: version_id.clone(),
            node_id: node_id.clone(),
            chunk_plan: chunk_plan.clone(),
            name_ciphertext: vec![], // Demo: no name encryption in this path
            mime_type: None,
            plaintext_size: plaintext.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            parent_version_id: None,
        };

        let (manifest_ct, manifest_nonce) =
            encrypt_manifest(&version_dek, node_id, &version_id, &manifest)?;

        let manifest_sha = kchat_drive_crypto::sha256(&manifest_ct);

        // Wrap VersionDEK under the wrapping key.
        let (wrapped_dek, wrap_nonce) = match privacy_mode {
            PrivacyMode::Secured | PrivacyMode::Advanced => {
                wrap_version_dek_under_domain_key(wrapping_key, &version_dek)?
            }
            PrivacyMode::Max => wrap_version_dek_under_share_grant_key(wrapping_key, &version_dek)?,
        };

        // Build public version header.
        let header = PublicVersionHeader {
            protocol: kchat_drive_types::PROTOCOL_VERSION,
            suite: kchat_drive_types::SUITE_KDRV1,
            drive_id: drive_id.clone(),
            node_id: node_id.clone(),
            version_id: version_id.clone(),
            domain_id: domain_id.clone(),
            privacy_mode,
            plaintext_size: plaintext.len() as u64,
            chunk_size: select_chunk_size(plaintext.len() as u64),
            chunk_count: chunk_plan.chunks.len() as u64,
            chunk_plan_root: chunk_plan_root.clone(),
            manifest_ciphertext_sha256: manifest_sha,
            manifest_ciphertext_len: manifest_ct.len() as u64,
            manifest_nonce: manifest_nonce.clone(),
            access_context_revision,
            access_context_snapshot_hash: Hash256::new(*access_context_snapshot_hash),
            creator_device_key: creator_device_key.clone(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signature: None,
        };

        // Sign the header.
        let sig = sign_header(&header, signing_key)?;
        let mut signed_header = header.clone();
        signed_header.signature = Some(sig);

        // Store VersionDEK in vault.
        let vault_key_id = format!("version_dek:{}", version_id);
        self.runtime.vault().store(&vault_key_id, &version_dek)?;

        Ok(UploadResult {
            version_id,
            chunk_plan_root,
            chunk_count: chunk_plan.chunks.len() as u64,
            manifest_ciphertext: manifest_ct,
            manifest_nonce,
            header: signed_header,
            ciphertexts,
            wrapped_dek,
            wrap_nonce,
        })
    }

    /// Downloads a file: decrypts manifest, then chunks.
    pub fn download(
        &self,
        version_dek: &[u8; 32],
        node_id: &NodeId,
        version_id: &VersionId,
        drive_id: &DriveId,
        domain_id: &DomainId,
        access_context_revision: u64,
        access_context_snapshot_hash: &[u8; 32],
        manifest_ciphertext: &[u8],
        manifest_nonce: &Nonce12,
        ciphertexts: &[Vec<u8>],
    ) -> Result<DownloadResult, DriveError> {
        // Decrypt manifest.
        let manifest = decrypt_manifest(
            version_dek,
            node_id,
            version_id,
            manifest_ciphertext,
            manifest_nonce,
        )?;

        // Decrypt file.
        let plaintext = decrypt_file(
            version_dek,
            node_id,
            version_id,
            drive_id.as_bytes(),
            domain_id,
            access_context_revision,
            access_context_snapshot_hash,
            &manifest.chunk_plan,
            ciphertexts,
        )?;

        Ok(DownloadResult { plaintext })
    }

    /// Retrieves a stored VersionDEK from the vault.
    pub fn get_version_dek(&self, version_id: &VersionId) -> Result<[u8; 32], DriveError> {
        let vault_key_id = format!("version_dek:{}", version_id);
        self.runtime.vault().load(&vault_key_id)
    }

    /// Creates a new encryption domain (Secured/Advanced).
    pub fn create_domain(&self, domain_id: DomainId) -> Result<Key256, DriveError> {
        let record = generate_domain_key(domain_id.clone());
        let vault_key_id = format!("domain_key:{}:{}", domain_id, record.generation);
        // Store the full CBOR-encoded record (including prev_envelope chain).
        let mut buf = Vec::new();
        minicbor::encode(&record, &mut buf)?;
        self.runtime.vault().store_bytes(&vault_key_id, &buf)?;
        Ok(record.key)
    }

    /// Rotates a domain key.
    pub fn rotate_domain(
        &self,
        domain_id: &DomainId,
        current_generation: u64,
    ) -> Result<Key256, DriveError> {
        let vault_key_id = format!("domain_key:{}:{}", domain_id, current_generation);
        // Load the full DomainKeyRecord from the vault (preserves backward chain).
        let record_bytes = self.runtime.vault().load_bytes(&vault_key_id)?;
        let current_record: kchat_drive_types::DomainKeyRecord =
            minicbor::decode(&record_bytes)?;
        let new_record = rotate_domain_key(&current_record)?;
        let new_vault_key_id = format!("domain_key:{}:{}", domain_id, new_record.generation);
        // Store the full new record (including prev_envelope for chain walking).
        let mut buf = Vec::new();
        minicbor::encode(&new_record, &mut buf)?;
        self.runtime.vault().store_bytes(&new_vault_key_id, &buf)?;
        Ok(new_record.key)
    }

    /// Creates a new share grant key (Max mode).
    pub fn create_share_grant(
        &self,
        grant_id: ShareGrantId,
        recipients: &[UserId],
        user_snapshot_hash: &Hash256,
        mls_epoch: u64,
        mls_tree_hash: &Hash256,
    ) -> Result<Key256, DriveError> {
        let record = generate_share_grant_key(
            grant_id.clone(),
            recipients,
            user_snapshot_hash,
            mls_epoch,
            mls_tree_hash,
        );
        let vault_key_id = format!("share_grant_key:{}:{}", grant_id, record.generation);
        // Store the full CBOR-encoded record.
        let mut buf = Vec::new();
        minicbor::encode(&record, &mut buf)?;
        self.runtime.vault().store_bytes(&vault_key_id, &buf)?;
        Ok(record.key)
    }

    /// Rotates a share grant key.
    pub fn rotate_share_grant(
        &self,
        grant_id: &ShareGrantId,
        current_generation: u64,
        recipients: &[UserId],
        user_snapshot_hash: &Hash256,
        mls_epoch: u64,
        mls_tree_hash: &Hash256,
    ) -> Result<Key256, DriveError> {
        let vault_key_id = format!("share_grant_key:{}:{}", grant_id, current_generation);
        // Load the full ShareGrantKeyRecord from the vault.
        let record_bytes = self.runtime.vault().load_bytes(&vault_key_id)?;
        let current_record: kchat_drive_types::ShareGrantKeyRecord =
            minicbor::decode(&record_bytes)?;
        let new_record = rotate_share_grant_key(
            &current_record,
            recipients,
            user_snapshot_hash,
            mls_epoch,
            mls_tree_hash,
        );
        let new_vault_key_id = format!("share_grant_key:{}:{}", grant_id, new_record.generation);
        // Store the full new record.
        let mut buf = Vec::new();
        minicbor::encode(&new_record, &mut buf)?;
        self.runtime.vault().store_bytes(&new_vault_key_id, &buf)?;
        Ok(new_record.key)
    }
}
