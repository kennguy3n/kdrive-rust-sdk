use kchat_drive_crypto::{
    compute_content_id, content_chunk_plan_root, decrypt_content_file, decrypt_file,
    decrypt_manifest, derive_content_key, encrypt_content_file, encrypt_file, encrypt_manifest,
    generate_domain_key, generate_key, generate_share_grant_key, plaintext_sha256,
    rotate_domain_key, rotate_share_grant_key, select_chunk_size, sign_header, unwrap_content_key,
    wrap_content_key, wrap_version_dek_under_domain_key, wrap_version_dek_under_share_grant_key,
};
use kchat_drive_transport_core::DedupTransport;
use kchat_drive_types::{
    DomainId, DriveError, DriveId, Ed25519PublicKey, Hash256, NodeId, Nonce12, PROTOCOL_KDRV1,
    PrivacyMode, PublicVersionHeader, SUITE_KDRV1, VersionId,
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

/// Result of a KDRV1 dedup upload operation.
#[derive(Debug, Clone)]
pub struct DedupUploadResult {
    pub version_id: VersionId,
    pub content_id: Hash256,
    pub chunk_plan_root: Hash256,
    pub chunk_count: u64,
    pub manifest_ciphertext: Vec<u8>,
    pub manifest_nonce: Nonce12,
    pub header: PublicVersionHeader,
    /// Ciphertexts that need to be uploaded (only new/missing chunks).
    pub new_ciphertexts: Vec<Vec<u8>>,
    /// Blob keys for all chunks (new + reused).
    pub all_blob_keys: Vec<String>,
    /// Blob keys for reused chunks (already exist on gateway).
    pub reused_blob_keys: Vec<String>,
    /// Blob keys for new chunks (need upload).
    pub new_blob_keys: Vec<String>,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Nonce12,
    pub wrapped_content_key: Vec<u8>,
    pub content_wrap_nonce: Nonce12,
    /// Whether the file was fully deduped (zero new chunks).
    pub fully_deduped: bool,
}

/// Result of a KDRV1 dedup download operation.
#[derive(Debug, Clone)]
pub struct DedupDownloadResult {
    pub plaintext: Vec<u8>,
    pub content_id: Hash256,
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
            content_id: None,
            wrapped_content_key: None,
            content_wrap_nonce: None,
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
            content_id: None,
        };

        // Sign the header.
        let sig = sign_header(&header, signing_key)?;
        let mut signed_header = header;
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

    /// Uploads a file with KDRV1 content deduplication.
    ///
    /// This is the dedup-aware upload path. It:
    /// 1. Computes plaintext hash + content_id
    /// 2. Derives ContentKey (convergent + tenant pepper)
    /// 3. Checks gateway for existing content (file-level dedup)
    /// 4. If not fully deduped, checks chunk-level dedup
    /// 5. Encrypts + uploads only new/missing chunks
    /// 6. Wraps ContentKey under a fresh VersionDEK
    /// 7. Wraps VersionDEK under the mode's wrapping key
    /// 8. Builds KDRV1 manifest + signed header
    pub fn upload_with_dedup(
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
        tenant_pepper: &[u8; 32],
        transport: &dyn DedupTransport,
    ) -> Result<DedupUploadResult, DriveError> {
        let version_id = VersionId::random();
        let version_dek = zeroize::Zeroizing::new(generate_key());

        // 1. Compute plaintext hash + content_id
        let pt_hash = plaintext_sha256(plaintext);
        let content_id = compute_content_id(&pt_hash, tenant_pepper);

        // 2. Derive ContentKey
        let content_key = derive_content_key(&pt_hash, tenant_pepper);

        // 3. Check gateway for existing content
        let mut content_check = transport.check_content(&content_id)?;

        let (chunk_plan, all_blob_keys, reused_blob_keys, new_blob_keys, new_ciphertexts);

        if content_check.exists
            && content_check.blob_keys.len() == content_check.chunk_count as usize
            && content_check.ciphertext_hashes.len() == content_check.chunk_count as usize
        {
            // Full dedup hit — reuse all blobs
            let cs = select_chunk_size(plaintext.len() as u64);
            let n = kchat_drive_crypto::chunk_count(plaintext.len() as u64, cs);

            // Validate gateway returned enough data for all chunks
            if content_check.blob_keys.len() != n as usize
                || content_check.ciphertext_hashes.len() != n as usize
            {
                return Err(DriveError::InvalidState(format!(
                    "gateway returned {} blob_keys / {} hashes for {} expected chunks",
                    content_check.blob_keys.len(),
                    content_check.ciphertext_hashes.len(),
                    n
                )));
            }

            let mut chunks = Vec::with_capacity(n as usize);
            // Use the original blob_keys for reused; clone for all_blob_keys after the loop.
            reused_blob_keys = std::mem::take(&mut content_check.blob_keys);
            new_blob_keys = Vec::new();
            new_ciphertexts = Vec::new();

            for i in 0..n {
                let start = (i * cs) as usize;
                let end = ((i + 1) * cs).min(plaintext.len() as u64) as usize;
                let plaintext_len = (end - start) as u64;
                let idx = i as usize;

                // Parse the ciphertext hash from the gateway response
                let ct_hash = Hash256::try_from_slice(
                    &hex::decode(&content_check.ciphertext_hashes[idx])
                        .map_err(|e| DriveError::Serialize(e.to_string()))?,
                )?;

                chunks.push(kchat_drive_types::ChunkDescriptor {
                    index: i,
                    plaintext_len,
                    ciphertext_len: 0, // Not needed for deduped chunks
                    ciphertext_sha256: ct_hash,
                    blob_key: reused_blob_keys[idx].clone(),
                });
            }
            chunk_plan = kchat_drive_types::ChunkPlan { chunks };
            all_blob_keys = reused_blob_keys.clone();
        } else {
            // No full dedup — encrypt all chunks with ContentKey
            let (plan, cts, _, _) = encrypt_content_file(plaintext, tenant_pepper)?;

            // 4. Check chunk-level dedup
            let chunk_hashes: Vec<Hash256> = plan
                .chunks
                .iter()
                .map(|c| c.ciphertext_sha256.clone())
                .collect();
            let chunk_check = transport.check_chunks(&content_id, &chunk_hashes)?;

            // Validate chunk check results match
            if chunk_check.results.len() != cts.len() {
                return Err(DriveError::InvalidState(format!(
                    "chunk check returned {} results for {} chunks",
                    chunk_check.results.len(),
                    cts.len()
                )));
            }

            // 5. Determine which chunks need upload
            let n = cts.len();
            let mut reused = Vec::with_capacity(n);
            let mut new_keys = Vec::with_capacity(n);
            let mut new_cts = Vec::with_capacity(n);
            let mut all_keys = Vec::with_capacity(n);

            for (i, ct) in cts.iter().enumerate() {
                let entry = &chunk_check.results[i];
                // Validate: if chunk exists, it must have a blob_key
                if entry.exists && entry.blob_key.is_none() {
                    return Err(DriveError::InvalidState(format!(
                        "chunk {} exists but has no blob_key",
                        i
                    )));
                }
                all_keys.push(
                    entry
                        .blob_key
                        .clone()
                        .unwrap_or_else(|| plan.chunks[i].blob_key.clone()),
                );
                if entry.exists {
                    reused.push(
                        entry
                            .blob_key
                            .clone()
                            .unwrap_or_else(|| plan.chunks[i].blob_key.clone()),
                    );
                } else {
                    new_keys.push(plan.chunks[i].blob_key.clone());
                    new_cts.push(ct.clone());
                }
            }

            chunk_plan = plan;
            all_blob_keys = all_keys;
            reused_blob_keys = reused;
            new_blob_keys = new_keys;
            new_ciphertexts = new_cts;
        }

        let chunk_plan_root = content_chunk_plan_root(&chunk_plan);
        let chunk_count = chunk_plan.chunks.len() as u64;
        let fully_deduped = new_ciphertexts.is_empty();

        // 6. Wrap ContentKey under VersionDEK
        let (wrapped_content_key, content_wrap_nonce) =
            wrap_content_key(&*version_dek, &version_id, &content_id, &content_key)?;

        // 7. Wrap VersionDEK under mode's wrapping key
        let (wrapped_dek, wrap_nonce) = match privacy_mode {
            PrivacyMode::Secured | PrivacyMode::Advanced => {
                wrap_version_dek_under_domain_key(wrapping_key, &*version_dek)?
            }
            PrivacyMode::Max => {
                wrap_version_dek_under_share_grant_key(wrapping_key, &*version_dek)?
            }
        };

        // 8. Build KDRV1 manifest (move chunk_plan to avoid clone)
        let manifest = kchat_drive_types::Manifest {
            version_id: version_id.clone(),
            node_id: node_id.clone(),
            chunk_plan,
            name_ciphertext: vec![],
            mime_type: None,
            plaintext_size: plaintext.len() as u64,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            parent_version_id: None,
            content_id: Some(content_id.clone()),
            wrapped_content_key: Some(wrapped_content_key.clone()),
            content_wrap_nonce: Some(Nonce12::new(content_wrap_nonce)),
        };

        let (manifest_ct, manifest_nonce) =
            encrypt_manifest(&*version_dek, node_id, &version_id, &manifest)?;

        let manifest_sha = kchat_drive_crypto::sha256(&manifest_ct);

        // Build KDRV1 public version header
        let header = PublicVersionHeader {
            protocol: PROTOCOL_KDRV1,
            suite: SUITE_KDRV1,
            drive_id: drive_id.clone(),
            node_id: node_id.clone(),
            version_id: version_id.clone(),
            domain_id: domain_id.clone(),
            privacy_mode,
            plaintext_size: plaintext.len() as u64,
            chunk_size: select_chunk_size(plaintext.len() as u64),
            chunk_count,
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
            content_id: Some(content_id.clone()),
        };

        let sig = sign_header(&header, signing_key)?;
        let mut signed_header = header;
        signed_header.signature = Some(sig);

        // Store VersionDEK in vault
        let vault_key_id = format!("version_dek:{}", version_id);
        self.runtime.vault().store(&vault_key_id, &*version_dek)?;

        // Store ContentKey in vault (keyed by content_id for reuse)
        let content_vault_key = format!("content_key:{}", content_id);
        self.runtime
            .vault()
            .store(&content_vault_key, &content_key)?;

        Ok(DedupUploadResult {
            version_id,
            content_id,
            chunk_plan_root,
            chunk_count,
            manifest_ciphertext: manifest_ct,
            manifest_nonce,
            header: signed_header,
            new_ciphertexts,
            all_blob_keys,
            reused_blob_keys,
            new_blob_keys,
            wrapped_dek,
            wrap_nonce,
            wrapped_content_key,
            content_wrap_nonce: Nonce12::new(content_wrap_nonce),
            fully_deduped,
        })
    }

    /// Performs a KDRV1 dedup upload AND commits the version in one call.
    ///
    /// This is the preferred API for bindings: it calls `upload_with_dedup`
    /// internally, then uploads new ciphertext blobs and commits the version
    /// via the transport — eliminating the need for each binding to duplicate
    /// the post-facade orchestration logic.
    ///
    /// # Flow
    /// 1. `upload_with_dedup` — encrypt, check dedup, build manifest + header
    /// 2. Upload new ciphertext blobs via `transport.upload_content_blob()`
    /// 3. Encode signed header as CBOR
    /// 4. Commit version via `transport.commit_version_dedup()`
    pub fn upload_and_commit(
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
        tenant_pepper: &[u8; 32],
        transport: &dyn DedupTransport,
    ) -> Result<DedupUploadResult, DriveError> {
        let result = self.upload_with_dedup(
            drive_id,
            node_id,
            domain_id,
            privacy_mode,
            plaintext,
            creator_device_key,
            signing_key,
            access_context_revision,
            access_context_snapshot_hash,
            wrapping_key,
            tenant_pepper,
            transport,
        )?;

        // Upload new ciphertext blobs
        for (ct, blob_key) in result
            .new_ciphertexts
            .iter()
            .zip(result.new_blob_keys.iter())
        {
            let ct_hash = kchat_drive_crypto::ciphertext_sha256(ct);
            transport.upload_content_blob(blob_key, ct, &ct_hash)?;
        }

        // Encode signed header as CBOR
        let header_cbor =
            minicbor::to_vec(&result.header).map_err(|e| DriveError::Serialize(e.to_string()))?;

        // Commit version
        transport.commit_version_dedup(
            &result.manifest_ciphertext,
            result.manifest_nonce.as_bytes(),
            &result.header.manifest_ciphertext_sha256,
            &header_cbor,
            &result.wrapped_dek,
            result.wrap_nonce.as_bytes(),
            &result.content_id,
            &result.wrapped_content_key,
            result.content_wrap_nonce.as_bytes(),
            &result.reused_blob_keys,
            &result.new_blob_keys,
        )?;

        Ok(result)
    }

    /// Downloads a KDRV1 file: decrypts manifest, unwraps ContentKey, decrypts chunks.
    pub fn download_dedup(
        &self,
        version_dek: &[u8; 32],
        node_id: &NodeId,
        version_id: &VersionId,
        manifest_ciphertext: &[u8],
        manifest_nonce: &Nonce12,
        ciphertexts: &[Vec<u8>],
    ) -> Result<DedupDownloadResult, DriveError> {
        // Decrypt manifest
        let manifest = decrypt_manifest(
            version_dek,
            node_id,
            version_id,
            manifest_ciphertext,
            manifest_nonce,
        )?;

        let content_id = manifest
            .content_id
            .as_ref()
            .ok_or(DriveError::InvalidState(
                "manifest is not KDRV1 (no content_id)".into(),
            ))?;
        let wrapped_content_key =
            manifest
                .wrapped_content_key
                .as_ref()
                .ok_or(DriveError::InvalidState(
                    "manifest is not KDRV1 (no wrapped_content_key)".into(),
                ))?;
        let content_wrap_nonce =
            manifest
                .content_wrap_nonce
                .as_ref()
                .ok_or(DriveError::InvalidState(
                    "manifest is not KDRV1 (no content_wrap_nonce)".into(),
                ))?;

        // Unwrap ContentKey from VersionDEK
        let content_key = unwrap_content_key(
            version_dek,
            version_id,
            content_id,
            wrapped_content_key,
            content_wrap_nonce.as_bytes(),
        )?;

        // Decrypt content chunks
        let plaintext =
            decrypt_content_file(&content_key, content_id, &manifest.chunk_plan, ciphertexts)?;

        Ok(DedupDownloadResult {
            plaintext,
            content_id: content_id.clone(),
        })
    }

    /// Stores a tenant pepper in the vault.
    pub fn store_tenant_pepper(
        &self,
        tenant_id: &kchat_drive_types::TenantId,
        pepper: &[u8; 32],
    ) -> Result<(), DriveError> {
        let vault_key = format!("tenant_pepper:{}", tenant_id);
        self.runtime.vault().store(&vault_key, pepper)
    }

    /// Loads a tenant pepper from the vault.
    pub fn load_tenant_pepper(
        &self,
        tenant_id: &kchat_drive_types::TenantId,
    ) -> Result<[u8; 32], DriveError> {
        let vault_key = format!("tenant_pepper:{}", tenant_id);
        self.runtime.vault().load(&vault_key)
    }

    /// Generates and stores a new tenant pepper.
    pub fn init_tenant_pepper(
        &self,
        tenant_id: &kchat_drive_types::TenantId,
    ) -> Result<[u8; 32], DriveError> {
        let pepper = kchat_drive_crypto::generate_tenant_pepper();
        self.store_tenant_pepper(tenant_id, &pepper)?;
        Ok(pepper)
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
        let current_record: kchat_drive_types::DomainKeyRecord = minicbor::decode(&record_bytes)?;
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
