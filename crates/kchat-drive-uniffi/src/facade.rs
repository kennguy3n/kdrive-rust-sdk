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
        content_id: None,
        wrapped_content_key: None,
        content_wrap_nonce: None,
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
        .map(|h| {
            hex::decode(h).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid ciphertext hex: {}", e),
            })
        })
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

// --- KDRV1 Drive Runtime (pepper management) ---

/// Persistent Drive runtime for iOS/Android.
///
/// Wraps `ClientRuntime` + `DriveFacade` so that the encrypted vault
/// (including the tenant pepper) persists across calls.
///
/// Production flow:
/// 1. Create `DriveRuntimeFfi()` once at app startup.
/// 2. Call `init_tenant_pepper(tenant_id_hex)` on first use per tenant.
/// 3. Use the pepper for dedup uploads via the facade.
/// 4. For multi-device sync, use `seal_pepper_for_mls` / `open_pepper_from_mls`.
#[derive(uniffi::Object)]
pub struct DriveRuntimeFfi {
    runtime: std::sync::Arc<kchat_client_runtime::runtime::ClientRuntime>,
    facade: kchat_client_runtime::facade::DriveFacade,
}

impl DriveRuntimeFfi {
    fn with_master_key_inner(master_key_hex: Option<&str>) -> Result<Self, DriveSdkError> {
        let master_key = if let Some(hex_str) = master_key_hex {
            if hex_str.is_empty() {
                use rand::RngCore;
                let mut key = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut key);
                key
            } else {
                let bytes = hex::decode(hex_str).map_err(|e| {
                    DriveSdkError::InvalidInput {
                        msg: format!("invalid master_key hex: {}", e),
                    }
                })?;
                if bytes.len() != 32 {
                    return Err(DriveSdkError::InvalidInput {
                        msg: format!(
                            "master_key must be 32 bytes (64 hex chars), got {} bytes",
                            bytes.len()
                        ),
                    });
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                key
            }
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            key
        };
        let runtime = std::sync::Arc::new(
            kchat_client_runtime::runtime::ClientRuntime::with_master_key(master_key),
        );
        let facade = kchat_client_runtime::facade::DriveFacade::new(runtime.clone());
        Ok(Self { runtime, facade })
    }
}

#[uniffi::export]
impl DriveRuntimeFfi {
    /// Creates a runtime with a fresh auto-generated master key.
    #[uniffi::constructor]
    pub fn new() -> Self {
        // None case cannot fail — random key generation only.
        Self::with_master_key_inner(None).expect("random key generation cannot fail")
    }

    /// Creates a runtime with a specific 32-byte master key (hex-encoded).
    /// If empty, a random key is generated.
    /// Returns `InvalidInput` if the hex is malformed or not exactly 32 bytes.
    #[uniffi::constructor(name = "with_master_key")]
    pub fn with_master_key(master_key_hex: String) -> Result<Self, DriveSdkError> {
        Self::with_master_key_inner(Some(&master_key_hex))
    }

    /// Generates and stores a new tenant pepper in the vault.
    pub fn init_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper = self
            .facade
            .init_tenant_pepper(&tenant_id)
            .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper from the vault.
    pub fn load_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper = self
            .facade
            .load_tenant_pepper(&tenant_id)
            .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper, auto-initializing if missing.
    pub fn ensure_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper = match self.facade.load_tenant_pepper(&tenant_id) {
            Ok(p) => p,
            Err(_) => self
                .facade
                .init_tenant_pepper(&tenant_id)
                .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })?,
        };
        Ok(hex::encode(pepper))
    }

    /// Stores an existing pepper into the vault (e.g. from MLS unwrap).
    pub fn store_tenant_pepper(
        &self,
        tenant_id_hex: String,
        pepper_hex: String,
    ) -> Result<(), DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper_bytes = hex::decode(&pepper_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid pepper: {}", e),
        })?;
        let pepper: [u8; 32] =
            pepper_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "pepper must be 32 bytes".into(),
                })?;
        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })
    }

    /// Checks whether a tenant pepper exists in the vault.
    pub fn has_tenant_pepper(&self, tenant_id_hex: String) -> bool {
        let Ok(tenant_id) = kchat_drive_types::TenantId::from_hex(&tenant_id_hex) else {
            return false;
        };
        self.facade.load_tenant_pepper(&tenant_id).is_ok()
    }

    /// Returns the master key hex (for persistence across app sessions).
    pub fn export_master_key(&self) -> Result<String, DriveSdkError> {
        let vault = self.runtime.vault();
        Ok(hex::encode(vault.master_key()))
    }

    /// Seals the tenant pepper using MLS exporter-derived transport key.
    /// Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
    pub fn seal_pepper_for_mls(
        &self,
        tenant_id_hex: String,
        mls_exporter_output_hex: String,
        transport_salt_hex: String,
        domain_id_hex: String,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash_hex: String,
        envelope_id_hex: String,
    ) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper = self.facade.load_tenant_pepper(&tenant_id).map_err(|e| {
            DriveSdkError::InvalidState {
                msg: format!("pepper not in vault: {}", e),
            }
        })?;

        let exporter_out =
            hex::decode(&mls_exporter_output_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid exporter output: {}", e),
            })?;
        let salt = hex::decode(&transport_salt_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid salt: {}", e),
        })?;
        let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)?;
        let tree_hash_bytes =
            hex::decode(&mls_tree_hash_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid tree_hash: {}", e),
            })?;
        let tree_hash = kchat_drive_types::Hash256::from_slice(&tree_hash_bytes);
        let envelope_id = kchat_drive_types::EnvelopeId::from_hex(&envelope_id_hex)?;

        let context = kchat_drive_mls_bridge::context::AdvancedTransportContext {
            domain_id,
            generation,
            mls_epoch,
            mls_tree_hash: tree_hash,
        };

        let (ct, nonce) = kchat_drive_mls_bridge::pepper::seal_pepper_via_mls(
            &exporter_out,
            &salt,
            &context,
            &envelope_id,
            &pepper,
        )?;

        let json = serde_json::json!({
            "ciphertext_hex": hex::encode(&ct),
            "nonce_hex": hex::encode(nonce.as_bytes()),
        });
        Ok(json.to_string())
    }

    /// Opens a pepper sealed via MLS and stores it in the vault.
    pub fn open_pepper_from_mls(
        &self,
        tenant_id_hex: String,
        ciphertext_hex: String,
        nonce_hex: String,
        mls_exporter_output_hex: String,
        transport_salt_hex: String,
        domain_id_hex: String,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash_hex: String,
        envelope_id_hex: String,
    ) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;

        let ct = hex::decode(&ciphertext_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid ciphertext: {}", e),
        })?;
        let nonce_bytes = hex::decode(&nonce_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid nonce: {}", e),
        })?;
        let nonce_bytes: [u8; 12] =
            nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "nonce must be 12 bytes".into(),
                })?;
        let nonce = kchat_drive_types::Nonce12::new(nonce_bytes);

        let exporter_out =
            hex::decode(&mls_exporter_output_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid exporter output: {}", e),
            })?;
        let salt = hex::decode(&transport_salt_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid salt: {}", e),
        })?;
        let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)?;
        let tree_hash_bytes =
            hex::decode(&mls_tree_hash_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid tree_hash: {}", e),
            })?;
        let tree_hash = kchat_drive_types::Hash256::from_slice(&tree_hash_bytes);
        let envelope_id = kchat_drive_types::EnvelopeId::from_hex(&envelope_id_hex)?;

        let context = kchat_drive_mls_bridge::context::AdvancedTransportContext {
            domain_id,
            generation,
            mls_epoch,
            mls_tree_hash: tree_hash,
        };

        let pepper = kchat_drive_mls_bridge::pepper::open_pepper_via_mls(
            &exporter_out,
            &salt,
            &context,
            &envelope_id,
            &ct,
            &nonce,
        )?;

        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })?;

        Ok(hex::encode(pepper))
    }

    /// Wraps the tenant pepper under a DomainKey (backup for non-MLS devices).
    pub fn wrap_pepper_under_domain_key(
        &self,
        tenant_id_hex: String,
        domain_key_hex: String,
    ) -> Result<String, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let pepper = self.facade.load_tenant_pepper(&tenant_id).map_err(|e| {
            DriveSdkError::InvalidState {
                msg: format!("pepper not in vault: {}", e),
            }
        })?;

        let dk_bytes = hex::decode(&domain_key_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid domain_key: {}", e),
        })?;
        let dk_arr: [u8; 32] =
            dk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "domain_key must be 32 bytes".into(),
                })?;
        let domain_key = kchat_drive_types::Key256::new(dk_arr);

        let (ct, nonce) = kchat_drive_crypto::wrap_pepper_under_domain_key(&domain_key, &pepper)?;

        let json = serde_json::json!({
            "ciphertext_hex": hex::encode(&ct),
            "nonce_hex": hex::encode(nonce.as_bytes()),
        });
        Ok(json.to_string())
    }

    /// Unwraps a pepper from a DomainKey-wrapped blob and stores it in the vault.
    pub fn unwrap_pepper_from_domain_key(
        &self,
        tenant_id_hex: String,
        ciphertext_hex: String,
        nonce_hex: String,
        domain_key_hex: String,
    ) -> Result<(), DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;

        let ct = hex::decode(&ciphertext_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid ciphertext: {}", e),
        })?;
        let nonce_bytes = hex::decode(&nonce_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid nonce: {}", e),
        })?;
        let nonce_bytes: [u8; 12] =
            nonce_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "nonce must be 12 bytes".into(),
                })?;
        let nonce = kchat_drive_types::Nonce12::new(nonce_bytes);

        let dk_bytes = hex::decode(&domain_key_hex).map_err(|e| DriveSdkError::InvalidState {
            msg: format!("invalid domain_key: {}", e),
        })?;
        let dk_arr: [u8; 32] =
            dk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "domain_key must be 32 bytes".into(),
                })?;
        let domain_key = kchat_drive_types::Key256::new(dk_arr);

        let pepper = kchat_drive_crypto::unwrap_pepper_from_domain_key(&domain_key, &ct, &nonce)?;

        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(|e| DriveSdkError::Crypto { msg: e.to_string() })
    }

    /// Performs a KDRV1 dedup upload with SDK-managed pepper.
    ///
    /// The tenant pepper is loaded from the vault internally — the caller never sees it.
    /// The caller provides a `DedupTransportFfi` implementation (Swift/Kotlin side)
    /// that handles gateway I/O (check_content, check_chunks, upload_blob, commit).
    ///
    /// Returns a `DedupUploadResultFfi` with all metadata for the uploaded version.
    #[uniffi::method]
    pub fn dedup_upload(
        &self,
        tenant_id_hex: String,
        drive_id_hex: String,
        node_id_hex: String,
        domain_id_hex: String,
        privacy_mode: u8,
        plaintext: Vec<u8>,
        creator_device_key_hex: String,
        signing_key_hex: String,
        access_context_revision: u64,
        access_context_snapshot_hash_hex: String,
        wrapping_key_hex: String,
        transport: std::sync::Arc<dyn DedupTransportFfi>,
    ) -> Result<DedupUploadResultFfi, DriveSdkError> {
        let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex)?;
        let drive_id = kchat_drive_types::DriveId::from_hex(&drive_id_hex)?;
        let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex)?;
        let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex)?;

        let privacy_mode = match privacy_mode {
            1 => kchat_drive_types::PrivacyMode::Secured,
            2 => kchat_drive_types::PrivacyMode::Advanced,
            3 => kchat_drive_types::PrivacyMode::Max,
            _ => {
                return Err(DriveSdkError::InvalidState {
                    msg: "privacy_mode must be 1, 2, or 3".into(),
                });
            }
        };

        let creator_pub_bytes =
            hex::decode(&creator_device_key_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid creator_device_key: {}", e),
            })?;
        let creator_pub: [u8; 32] =
            creator_pub_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "creator_device_key must be 32 bytes".into(),
                })?;
        let creator_device_key = kchat_drive_types::Ed25519PublicKey::new(creator_pub);

        let signing_bytes =
            hex::decode(&signing_key_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid signing_key: {}", e),
            })?;
        let signing_arr: [u8; 32] =
            signing_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "signing_key must be 32 bytes".into(),
                })?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_arr);

        let snapshot_bytes = hex::decode(&access_context_snapshot_hash_hex).map_err(|e| {
            DriveSdkError::InvalidState {
                msg: format!("invalid snapshot_hash: {}", e),
            }
        })?;
        let snapshot_hash: [u8; 32] =
            snapshot_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "snapshot_hash must be 32 bytes".into(),
                })?;

        let wrapping_bytes =
            hex::decode(&wrapping_key_hex).map_err(|e| DriveSdkError::InvalidState {
                msg: format!("invalid wrapping_key: {}", e),
            })?;
        let wrapping_arr: [u8; 32] =
            wrapping_bytes
                .as_slice()
                .try_into()
                .map_err(|_| DriveSdkError::InvalidState {
                    msg: "wrapping_key must be 32 bytes".into(),
                })?;
        let wrapping_key = kchat_drive_types::Key256::new(wrapping_arr);

        // Load pepper from vault — auto-initialize if missing
        let pepper = match self.facade.load_tenant_pepper(&tenant_id) {
            Ok(p) => p,
            Err(_) => self.facade.init_tenant_pepper(&tenant_id)?,
        };

        // Adapter: UniFFI trait → DedupTransport trait
        let transport_adapter = UniffiDedupTransport { inner: transport };

        // Call facade.upload_and_commit (pepper stays internal)
        // This handles: encrypt, dedup check, blob upload, header CBOR encode, and version commit
        let result = self.facade.upload_and_commit(
            &drive_id,
            &node_id,
            &domain_id,
            privacy_mode,
            &plaintext,
            &creator_device_key,
            &signing_key,
            access_context_revision,
            &snapshot_hash,
            &wrapping_key,
            &pepper,
            &transport_adapter,
        )?;

        // Encode signed header as CBOR for the result
        let header_cbor = minicbor::to_vec(&result.header).map_err(|e| DriveSdkError::Crypto {
            msg: format!("header encode: {}", e),
        })?;

        Ok(DedupUploadResultFfi {
            version_id_hex: result.version_id.to_hex(),
            content_id_hex: result.content_id.to_hex(),
            chunk_plan_root_hex: result.chunk_plan_root.to_hex(),
            chunk_count: result.chunk_count,
            manifest_ciphertext_hex: hex::encode(&result.manifest_ciphertext),
            manifest_nonce_hex: hex::encode(result.manifest_nonce.as_bytes()),
            header_cbor_hex: hex::encode(&header_cbor),
            new_ciphertexts_hex: result.new_ciphertexts.iter().map(hex::encode).collect(),
            all_blob_keys: result.all_blob_keys,
            reused_blob_keys: result.reused_blob_keys,
            new_blob_keys: result.new_blob_keys,
            wrapped_dek_hex: hex::encode(&result.wrapped_dek),
            wrap_nonce_hex: hex::encode(result.wrap_nonce.as_bytes()),
            wrapped_content_key_hex: hex::encode(&result.wrapped_content_key),
            content_wrap_nonce_hex: hex::encode(result.content_wrap_nonce.as_bytes()),
            fully_deduped: result.fully_deduped,
        })
    }
}

/// UniFFI-exposed result of a dedup upload.
#[derive(Debug, Clone, uniffi::Record)]
pub struct DedupUploadResultFfi {
    pub version_id_hex: String,
    pub content_id_hex: String,
    pub chunk_plan_root_hex: String,
    pub chunk_count: u64,
    pub manifest_ciphertext_hex: String,
    pub manifest_nonce_hex: String,
    pub header_cbor_hex: String,
    pub new_ciphertexts_hex: Vec<String>,
    pub all_blob_keys: Vec<String>,
    pub reused_blob_keys: Vec<String>,
    pub new_blob_keys: Vec<String>,
    pub wrapped_dek_hex: String,
    pub wrap_nonce_hex: String,
    pub wrapped_content_key_hex: String,
    pub content_wrap_nonce_hex: String,
    pub fully_deduped: bool,
}

/// UniFFI trait for dedup transport operations.
/// Swift/Kotlin implements this to handle gateway I/O.
#[uniffi::export(with_foreign)]
pub trait DedupTransportFfi: Send + Sync {
    /// Checks if content already exists. Returns JSON with exists/blob_keys/etc.
    fn check_content(&self, content_id_hex: String) -> Result<String, DriveSdkError>;
    /// Checks which chunks already exist. Returns JSON with results array.
    fn check_chunks(
        &self,
        content_id_hex: String,
        chunk_hashes_hex: Vec<String>,
    ) -> Result<String, DriveSdkError>;
    /// Uploads a single content blob. ciphertext is raw bytes.
    fn upload_blob(&self, blob_key: String, ciphertext_hex: String) -> Result<(), DriveSdkError>;
    /// Commits the version. Returns JSON with version_id/committed/deduped_chunks/new_chunks.
    fn commit_version(&self, commit_request_json: String) -> Result<String, DriveSdkError>;
}

/// Adapter: UniFFI trait → Rust DedupTransport trait
struct UniffiDedupTransport {
    inner: std::sync::Arc<dyn DedupTransportFfi>,
}

impl kchat_drive_transport_core::DedupTransport for UniffiDedupTransport {
    fn check_content(
        &self,
        content_id: &kchat_drive_types::Hash256,
    ) -> Result<kchat_drive_transport_core::ContentCheckResult, kchat_drive_types::DriveError> {
        let json = self
            .inner
            .check_content(content_id.to_hex())
            .map_err(|e| kchat_drive_types::DriveError::Transport(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| kchat_drive_types::DriveError::Transport(format!("parse: {}", e)))
    }

    fn check_chunks(
        &self,
        content_id: &kchat_drive_types::Hash256,
        chunk_hashes: &[kchat_drive_types::Hash256],
    ) -> Result<kchat_drive_transport_core::ChunkCheckResult, kchat_drive_types::DriveError> {
        let hashes: Vec<String> = chunk_hashes.iter().map(|h| h.to_hex()).collect();
        let json = self
            .inner
            .check_chunks(content_id.to_hex(), hashes)
            .map_err(|e| kchat_drive_types::DriveError::Transport(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| kchat_drive_types::DriveError::Transport(format!("parse: {}", e)))
    }

    fn upload_content_blob(
        &self,
        blob_key: &str,
        ciphertext: &[u8],
        _ciphertext_sha256: &kchat_drive_types::Hash256,
    ) -> Result<(), kchat_drive_types::DriveError> {
        self.inner
            .upload_blob(blob_key.to_string(), hex::encode(ciphertext))
            .map_err(|e| kchat_drive_types::DriveError::Transport(e.to_string()))
    }

    fn commit_version_dedup(
        &self,
        manifest_ciphertext: &[u8],
        manifest_nonce: &[u8; 12],
        manifest_ciphertext_sha256: &kchat_drive_types::Hash256,
        header: &[u8],
        wrapped_dek: &[u8],
        wrap_nonce: &[u8; 12],
        content_id: &kchat_drive_types::Hash256,
        wrapped_content_key: &[u8],
        content_wrap_nonce: &[u8; 12],
        reused_blob_keys: &[String],
        new_blob_keys: &[String],
    ) -> Result<kchat_drive_transport_core::DedupCommitResult, kchat_drive_types::DriveError> {
        let req = serde_json::json!({
            "manifest_ciphertext_hex": hex::encode(manifest_ciphertext),
            "manifest_nonce_hex": hex::encode(manifest_nonce),
            "manifest_ciphertext_sha256_hex": manifest_ciphertext_sha256.to_hex(),
            "header_hex": hex::encode(header),
            "wrapped_dek_hex": hex::encode(wrapped_dek),
            "wrap_nonce_hex": hex::encode(wrap_nonce),
            "content_id_hex": content_id.to_hex(),
            "wrapped_content_key_hex": hex::encode(wrapped_content_key),
            "content_wrap_nonce_hex": hex::encode(content_wrap_nonce),
            "reused_blob_keys": reused_blob_keys,
            "new_blob_keys": new_blob_keys,
        });
        let json = self
            .inner
            .commit_version(req.to_string())
            .map_err(|e| kchat_drive_types::DriveError::Transport(e.to_string()))?;
        serde_json::from_str(&json)
            .map_err(|e| kchat_drive_types::DriveError::Transport(format!("parse: {}", e)))
    }
}

impl Default for DriveRuntimeFfi {
    fn default() -> Self {
        Self::new()
    }
}
