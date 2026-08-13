// NAPI DriveRuntime — wraps ClientRuntime + DriveFacade.
//
// This is the NAPI equivalent of WASM's WasmDriveRuntime and UniFFI's
// DriveRuntimeFfi. It provides pepper management and serves as the
// entry point for facade-based operations (dedup_upload, etc.).
//
// JS usage:
//   const { DriveRuntime } = require('kchat-drive-napi');
//   const runtime = new DriveRuntime(masterKeyHex);
//   runtime.initTenantPepper(tenantIdHex);
//   const result = dedupUpload(runtime, tenantIdHex, ...);

use kchat_client_runtime::facade::DriveFacade;
use kchat_client_runtime::runtime::ClientRuntime;
use kchat_drive_types::TenantId;
use napi::bindgen_prelude::Function;
use napi_derive::napi;
use rand::RngCore;

use crate::error::{invalid_input, to_napi_error};

/// Persistent Drive runtime for NAPI (Electron native addon).
///
/// Wraps `ClientRuntime` + `DriveFacade` so that the encrypted vault
/// (including the tenant pepper) persists across calls within the
/// Electron process lifetime.
///
/// Production flow:
/// 1. JS creates `new DriveRuntime(masterKeyHex)` once at app startup.
/// 2. JS calls `initTenantPepper(tenantIdHex)` on first use per tenant.
/// 3. JS calls `dedupUpload(runtime, ...)` — the SDK loads the pepper
///    from the vault internally; JS never sees the pepper.
#[napi]
pub struct DriveRuntime {
    #[allow(dead_code)]
    runtime: std::sync::Arc<ClientRuntime>,
    pub(crate) facade: DriveFacade,
}

#[napi]
impl DriveRuntime {
    /// Creates a runtime with a fresh auto-generated master key.
    /// The vault is in-memory only — pepper is lost on process restart.
    /// For persistence, use `with_master_key` with a persisted key.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::with_master_key_hex(String::new()).unwrap_or_else(|_| {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let runtime = std::sync::Arc::new(ClientRuntime::with_master_key(key));
            let facade = DriveFacade::new(runtime.clone());
            Self { runtime, facade }
        })
    }

    /// Creates a runtime with a specific 32-byte master key (hex-encoded).
    /// If `master_key_hex` is empty, a random key is generated.
    /// In production, JS should derive this from a user passphrase and
    /// persist it (e.g. in Electron's safeStorage or keychain).
    #[napi(js_name = withMasterKey)]
    pub fn with_master_key_hex(master_key_hex: String) -> Result<Self, napi::Error> {
        let master_key = if master_key_hex.is_empty() {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            key
        } else {
            let bytes = hex::decode(&master_key_hex)
                .map_err(|e| invalid_input(format!("invalid master_key hex: {}", e)))?;
            if bytes.len() != 32 {
                return Err(invalid_input(format!(
                    "master_key must be 32 bytes (64 hex chars), got {} bytes",
                    bytes.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            key
        };
        let runtime = std::sync::Arc::new(ClientRuntime::with_master_key(master_key));
        let facade = DriveFacade::new(runtime.clone());
        Ok(Self { runtime, facade })
    }

    /// Generates and stores a new tenant pepper in the vault.
    /// Returns the pepper hex (for debugging/MLS sealing — JS should NOT
    /// store this; the SDK vault is the source of truth).
    #[napi(js_name = initTenantPepper)]
    pub fn init_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, napi::Error> {
        let tenant_id = TenantId::from_hex(&tenant_id_hex).map_err(to_napi_error)?;
        let pepper = self
            .facade
            .init_tenant_pepper(&tenant_id)
            .map_err(to_napi_error)?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper from the vault (without creating if missing).
    /// Returns the pepper hex, or throws if not found.
    #[napi(js_name = loadTenantPepper)]
    pub fn load_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, napi::Error> {
        let tenant_id = TenantId::from_hex(&tenant_id_hex).map_err(to_napi_error)?;
        let pepper = self
            .facade
            .load_tenant_pepper(&tenant_id)
            .map_err(to_napi_error)?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper from the vault, auto-initializing if missing.
    #[napi(js_name = ensureTenantPepper)]
    pub fn ensure_tenant_pepper(&self, tenant_id_hex: String) -> Result<String, napi::Error> {
        let tenant_id = TenantId::from_hex(&tenant_id_hex).map_err(to_napi_error)?;
        let pepper = match self.facade.load_tenant_pepper(&tenant_id) {
            Ok(p) => p,
            Err(_) => self
                .facade
                .init_tenant_pepper(&tenant_id)
                .map_err(to_napi_error)?,
        };
        Ok(hex::encode(pepper))
    }

    /// Stores an existing pepper into the vault (e.g. unwrapped from MLS).
    #[napi(js_name = storeTenantPepper)]
    pub fn store_tenant_pepper(
        &self,
        tenant_id_hex: String,
        pepper_hex: String,
    ) -> Result<(), napi::Error> {
        let tenant_id = TenantId::from_hex(&tenant_id_hex).map_err(to_napi_error)?;
        let pepper_bytes = hex::decode(&pepper_hex)
            .map_err(|e| invalid_input(format!("invalid pepper: {}", e)))?;
        let pepper: [u8; 32] = pepper_bytes
            .as_slice()
            .try_into()
            .map_err(|_| invalid_input("pepper must be 32 bytes".to_string()))?;
        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(to_napi_error)
    }

    /// Checks whether a tenant pepper exists in the vault.
    #[napi(js_name = hasTenantPepper)]
    pub fn has_tenant_pepper(&self, tenant_id_hex: String) -> bool {
        let Ok(tenant_id) = TenantId::from_hex(&tenant_id_hex) else {
            return false;
        };
        self.facade.load_tenant_pepper(&tenant_id).is_ok()
    }
}

// ---- NAPI dedup transport ----

use kchat_drive_transport_core::{
    ChunkCheckResult, ContentCheckResult, DedupCommitResult, DedupTransport,
};
use kchat_drive_types::{DriveError, Hash256};

/// Implements DedupTransport by calling JS functions via NAPI.
/// All dedup logic runs in the facade — JS only provides network I/O.
///
/// # Safety
///
/// `NapiDedupTransport` borrows `Function` handles for the duration of a
/// single `dedup_upload` call. The `Function` handles are only valid within
/// the scope of that call (they are borrowed from the NAPI arguments).
/// This struct MUST NOT be stored beyond the call scope — doing so would
/// cause a use-after-free. The `'a` lifetime enforces this at compile time.
#[allow(dead_code)]
pub(crate) struct NapiDedupTransport<'a> {
    pub(crate) check_content_fn: &'a Function<'a, String, String>,
    pub(crate) check_chunks_fn: &'a Function<'a, String, String>,
    pub(crate) upload_blob_fn: &'a Function<'a, String, String>,
    pub(crate) commit_version_fn: &'a Function<'a, String, String>,
}

impl<'a> DedupTransport for NapiDedupTransport<'a> {
    fn check_content(&self, content_id: &Hash256) -> Result<ContentCheckResult, DriveError> {
        let json = self
            .check_content_fn
            .call(content_id.to_hex())
            .map_err(|e| DriveError::Transport(format!("check_content callback: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| DriveError::Transport(format!("check_content parse: {}", e)))
    }

    fn check_chunks(
        &self,
        content_id: &Hash256,
        chunk_hashes: &[Hash256],
    ) -> Result<ChunkCheckResult, DriveError> {
        let req = serde_json::json!({
            "content_id": content_id.to_hex(),
            "chunk_hashes": chunk_hashes.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
        });
        let json = self
            .check_chunks_fn
            .call(req.to_string())
            .map_err(|e| DriveError::Transport(format!("check_chunks callback: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| DriveError::Transport(format!("check_chunks parse: {}", e)))
    }

    fn upload_content_blob(
        &self,
        blob_key: &str,
        ciphertext: &[u8],
        _ciphertext_sha256: &Hash256,
    ) -> Result<(), DriveError> {
        let req = serde_json::json!({
            "blob_key": blob_key,
            "ciphertext_hex": hex::encode(ciphertext),
        });
        self.upload_blob_fn
            .call(req.to_string())
            .map_err(|e| DriveError::Transport(format!("upload_blob callback: {}", e)))?;
        Ok(())
    }

    fn commit_version_dedup(
        &self,
        manifest_ciphertext: &[u8],
        manifest_nonce: &[u8; 12],
        manifest_ciphertext_sha256: &Hash256,
        header: &[u8],
        wrapped_dek: &[u8],
        wrap_nonce: &[u8; 12],
        content_id: &Hash256,
        wrapped_content_key: &[u8],
        content_wrap_nonce: &[u8; 12],
        reused_blob_keys: &[String],
        new_blob_keys: &[String],
    ) -> Result<DedupCommitResult, DriveError> {
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
            .commit_version_fn
            .call(req.to_string())
            .map_err(|e| DriveError::Transport(format!("commit_version callback: {}", e)))?;
        serde_json::from_str(&json)
            .map_err(|e| DriveError::Transport(format!("commit_version parse: {}", e)))
    }
}

/// NAPI-exposed dedup upload with SDK-managed pepper.
///
/// This is the NAPI equivalent of WASM's `dedup_upload`. The tenant pepper
/// is loaded from the SDK vault (not passed from JS). JS provides 4 callback
/// functions for gateway I/O (check_content, check_chunks, upload_blob,
/// commit_version).
///
/// # JS usage
///
/// ```js
/// const runtime = new DriveRuntime(masterKeyHex);
/// runtime.ensureTenantPepper(tenantIdHex);
///
/// const result = dedupUpload(
///   runtime, tenantIdHex, driveIdHex, nodeIdHex, ...,
///   (contentIdHex) => { ... return JSON },
///   (reqJson) => { ... return JSON },
///   (blobReqJson) => { ... return "" },
///   (commitReqJson) => { ... return JSON },
/// );
/// const parsed = JSON.parse(result);
/// if (parsed.fully_deduped) { showBadge("DEDUPED"); }
/// ```
#[napi(js_name = dedupUpload)]
#[allow(dead_code)]
pub fn dedup_upload(
    runtime: &DriveRuntime,
    tenant_id_hex: String,
    drive_id_hex: String,
    node_id_hex: String,
    domain_id_hex: String,
    privacy_mode: u8,
    plaintext_hex: String,
    creator_device_key_hex: String,
    signing_key_hex: String,
    access_context_revision: i64,
    access_context_snapshot_hash_hex: String,
    wrapping_key_hex: String,
    check_content_fn: Function<String, String>,
    check_chunks_fn: Function<String, String>,
    upload_blob_fn: Function<String, String>,
    commit_version_fn: Function<String, String>,
) -> Result<String, napi::Error> {
    let tenant_id = kchat_drive_types::TenantId::from_hex(&tenant_id_hex).map_err(to_napi_error)?;
    let drive_id = kchat_drive_types::DriveId::from_hex(&drive_id_hex).map_err(to_napi_error)?;
    let node_id = kchat_drive_types::NodeId::from_hex(&node_id_hex).map_err(to_napi_error)?;
    let domain_id = kchat_drive_types::DomainId::from_hex(&domain_id_hex).map_err(to_napi_error)?;

    let privacy_mode = match privacy_mode {
        1 => kchat_drive_types::PrivacyMode::Secured,
        2 => kchat_drive_types::PrivacyMode::Advanced,
        3 => kchat_drive_types::PrivacyMode::Max,
        _ => {
            return Err(invalid_input("privacy_mode must be 1, 2, or 3".to_string()));
        }
    };

    let plaintext = hex::decode(&plaintext_hex)
        .map_err(|e| invalid_input(format!("invalid plaintext_hex: {}", e)))?;

    let creator_pub_bytes = hex::decode(&creator_device_key_hex)
        .map_err(|e| invalid_input(format!("invalid creator_device_key: {}", e)))?;
    let creator_pub: [u8; 32] = creator_pub_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("creator_device_key must be 32 bytes".to_string()))?;
    let creator_device_key = kchat_drive_types::Ed25519PublicKey::new(creator_pub);

    let signing_bytes = hex::decode(&signing_key_hex)
        .map_err(|e| invalid_input(format!("invalid signing_key: {}", e)))?;
    let signing_arr: [u8; 32] = signing_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("signing_key must be 32 bytes".to_string()))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_arr);

    let snapshot_hash = hex::decode(&access_context_snapshot_hash_hex)
        .map_err(|e| invalid_input(format!("invalid snapshot_hash: {}", e)))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("snapshot_hash must be 32 bytes".to_string()))?;

    let wrapping_bytes = hex::decode(&wrapping_key_hex)
        .map_err(|e| invalid_input(format!("invalid wrapping_key: {}", e)))?;
    let wrapping_arr: [u8; 32] = wrapping_bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_input("wrapping_key must be 32 bytes".to_string()))?;
    let wrapping_key = kchat_drive_types::Key256::new(wrapping_arr);

    // Load pepper from SDK vault — auto-initialize if missing.
    let pepper = match runtime.facade.load_tenant_pepper(&tenant_id) {
        Ok(p) => p,
        Err(_) => runtime
            .facade
            .init_tenant_pepper(&tenant_id)
            .map_err(to_napi_error)?,
    };

    // Build transport adapter that calls the JS callbacks
    let transport = NapiDedupTransport {
        check_content_fn: &check_content_fn,
        check_chunks_fn: &check_chunks_fn,
        upload_blob_fn: &upload_blob_fn,
        commit_version_fn: &commit_version_fn,
    };

    // Call facade.upload_and_commit
    let result = runtime
        .facade
        .upload_and_commit(
            &drive_id,
            &node_id,
            &domain_id,
            privacy_mode,
            &plaintext,
            &creator_device_key,
            &signing_key,
            access_context_revision as u64,
            &snapshot_hash,
            &wrapping_key,
            &pepper,
            &transport,
        )
        .map_err(to_napi_error)?;

    // Encode signed header as CBOR for the result JSON
    let header_cbor = minicbor::to_vec(&result.header)
        .map_err(|e| to_napi_error(kchat_drive_types::DriveError::Serialize(e.to_string())))?;

    // Build result JSON
    let json = serde_json::json!({
        "version_id_hex": result.version_id.to_hex(),
        "content_id_hex": result.content_id.to_hex(),
        "chunk_plan_root_hex": result.chunk_plan_root.to_hex(),
        "chunk_count": result.chunk_count,
        "manifest_ciphertext_hex": hex::encode(&result.manifest_ciphertext),
        "manifest_nonce_hex": hex::encode(result.manifest_nonce.as_bytes()),
        "header_cbor_hex": hex::encode(&header_cbor),
        "new_ciphertexts_hex": result.new_ciphertexts.iter().map(hex::encode).collect::<Vec<_>>(),
        "all_blob_keys": result.all_blob_keys,
        "reused_blob_keys": result.reused_blob_keys,
        "new_blob_keys": result.new_blob_keys,
        "wrapped_dek_hex": hex::encode(&result.wrapped_dek),
        "wrap_nonce_hex": hex::encode(result.wrap_nonce.as_bytes()),
        "wrapped_content_key_hex": hex::encode(&result.wrapped_content_key),
        "content_wrap_nonce_hex": hex::encode(result.content_wrap_nonce.as_bytes()),
        "fully_deduped": result.fully_deduped,
    });
    Ok(json.to_string())
}
