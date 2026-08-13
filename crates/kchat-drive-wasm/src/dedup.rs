use wasm_bindgen::prelude::*;

use kchat_drive_transport_core::{
    ChunkCheckResult, ContentCheckResult, DedupCommitResult, DedupTransport,
};
use kchat_drive_types::{DriveError, Hash256};

use crate::api::WasmDriveRuntime;

/// JS callbacks for dedup transport operations.
/// Each callback is a JS function that receives a JSON string and returns a JSON string.
/// Callbacks must be synchronous — if you need async I/O, pre-fetch the data before
/// calling dedup_upload.
#[wasm_bindgen]
pub struct DedupCallbacks {
    pub(crate) check_content_fn: js_sys::Function,
    pub(crate) check_chunks_fn: js_sys::Function,
    pub(crate) upload_blob_fn: js_sys::Function,
    pub(crate) commit_version_fn: js_sys::Function,
}

#[wasm_bindgen]
impl DedupCallbacks {
    #[wasm_bindgen(constructor)]
    pub fn new(
        check_content_fn: js_sys::Function,
        check_chunks_fn: js_sys::Function,
        upload_blob_fn: js_sys::Function,
        commit_version_fn: js_sys::Function,
    ) -> Self {
        Self {
            check_content_fn,
            check_chunks_fn,
            upload_blob_fn,
            commit_version_fn,
        }
    }
}

fn call_js(fn_ref: &js_sys::Function, arg: &str) -> Result<String, DriveError> {
    let this = JsValue::NULL;
    let js_arg = JsValue::from_str(arg);
    let result = fn_ref
        .call1(&this, &js_arg)
        .map_err(|e| DriveError::Transport(format!("JS callback error: {:?}", e)))?;
    result.as_string().ok_or(DriveError::Transport(
        "JS callback did not return a string".into(),
    ))
}

fn call_js_void(fn_ref: &js_sys::Function, arg: &str) -> Result<(), DriveError> {
    let this = JsValue::NULL;
    let js_arg = JsValue::from_str(arg);
    fn_ref
        .call1(&this, &js_arg)
        .map_err(|e| DriveError::Transport(format!("JS callback error: {:?}", e)))?;
    Ok(())
}

/// Implements DedupTransport by calling JS callbacks.
/// All dedup logic (content check, chunk check, encryption, manifest building)
/// runs in the facade — JS only provides the network I/O via callbacks.
pub(crate) struct WasmDedupTransport<'a> {
    pub(crate) check_content_fn: &'a js_sys::Function,
    pub(crate) check_chunks_fn: &'a js_sys::Function,
    pub(crate) upload_blob_fn: &'a js_sys::Function,
    pub(crate) commit_version_fn: &'a js_sys::Function,
}

impl<'a> DedupTransport for WasmDedupTransport<'a> {
    fn check_content(&self, content_id: &Hash256) -> Result<ContentCheckResult, DriveError> {
        let json = call_js(self.check_content_fn, &content_id.to_hex())?;
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
        let json = call_js(self.check_chunks_fn, &req.to_string())?;
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
        call_js_void(self.upload_blob_fn, &req.to_string())
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
        let json = call_js(self.commit_version_fn, &req.to_string())?;
        serde_json::from_str(&json)
            .map_err(|e| DriveError::Transport(format!("commit_version parse: {}", e)))
    }
}

/// WASM-exposed dedup upload with SDK-managed pepper.
///
/// The tenant pepper is loaded from the SDK vault (not passed from JS).
/// The SDK handles pepper generation, storage, and retrieval internally.
/// JS only provides the tenant ID and 4 callback functions for gateway I/O.
///
/// # Pepper distribution model
///
/// - **B2B**: One pepper per tenant. Each tenant's pepper is isolated.
/// - **B2C**: One shared pepper for all B2C users (use the shared B2C tenant ID).
///
/// # Multi-device sync
///
/// When a user adds a new device, the pepper must be distributed to that device.
/// Use `WasmDriveRuntime.sealPepperForMls()` on an existing device and
/// `WasmDriveRuntime.openPepperFromMls()` on the new device.
///
/// # JS usage
///
/// ```js
/// const runtime = new WasmDriveRuntime();
/// // or: const runtime = WasmDriveRuntime.withMasterKey(masterKeyHex);
///
/// // Ensure pepper exists (auto-creates on first call)
/// runtime.ensureTenantPepper(tenantIdHex);
///
/// const callbacks = new DedupCallbacks(
///   (contentIdHex) => { ... return JSON },
///   (reqJson) => { ... return JSON },
///   (blobReqJson) => { ... return "" },
///   (commitReqJson) => { ... return JSON },
/// );
/// const result = dedup_upload(
///   runtime, tenantIdHex, driveIdHex, nodeIdHex, ...,
///   callbacks,
/// );
/// const parsed = JSON.parse(result);
/// if (parsed.fully_deduped) { showBadge("DEDUPED"); }
/// ```
#[wasm_bindgen]
pub fn dedup_upload(
    runtime: &WasmDriveRuntime,
    tenant_id_hex: &str,
    drive_id_hex: &str,
    node_id_hex: &str,
    domain_id_hex: &str,
    privacy_mode: u8,
    plaintext_hex: &str,
    creator_device_key_hex: &str,
    signing_key_hex: &str,
    access_context_revision: u64,
    access_context_snapshot_hash_hex: &str,
    wrapping_key_hex: &str,
    callbacks: &DedupCallbacks,
) -> Result<String, JsValue> {
    let tenant_id =
        kchat_drive_types::TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;

    let drive_id =
        kchat_drive_types::DriveId::from_hex(drive_id_hex).map_err(crate::error::to_js_error)?;

    let node_id =
        kchat_drive_types::NodeId::from_hex(node_id_hex).map_err(crate::error::to_js_error)?;
    let domain_id =
        kchat_drive_types::DomainId::from_hex(domain_id_hex).map_err(crate::error::to_js_error)?;

    let privacy_mode = match privacy_mode {
        1 => kchat_drive_types::PrivacyMode::Secured,
        2 => kchat_drive_types::PrivacyMode::Advanced,
        3 => kchat_drive_types::PrivacyMode::Max,
        _ => {
            return Err(crate::error::js_error(
                "InvalidInput",
                "privacy_mode must be 1, 2, or 3",
            ));
        }
    };

    let plaintext = hex::decode(plaintext_hex).map_err(|e| {
        crate::error::js_error("InvalidInput", format!("invalid plaintext_hex: {}", e))
    })?;

    let creator_pub_bytes = hex::decode(creator_device_key_hex).map_err(|e| {
        crate::error::js_error("InvalidInput", format!("invalid creator_device_key: {}", e))
    })?;
    let creator_pub: [u8; 32] = creator_pub_bytes.as_slice().try_into().map_err(|_| {
        crate::error::js_error("InvalidInput", "creator_device_key must be 32 bytes")
    })?;
    let creator_device_key = kchat_drive_types::Ed25519PublicKey::new(creator_pub);

    let signing_bytes = hex::decode(signing_key_hex).map_err(|e| {
        crate::error::js_error("InvalidInput", format!("invalid signing_key: {}", e))
    })?;
    let signing_arr: [u8; 32] = signing_bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::error::js_error("InvalidInput", "signing_key must be 32 bytes"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_arr);

    let snapshot_hash = hex::decode(access_context_snapshot_hash_hex).map_err(|e| {
        crate::error::js_error("InvalidInput", format!("invalid snapshot_hash: {}", e))
    })?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| crate::error::js_error("InvalidInput", "snapshot_hash must be 32 bytes"))?;

    let wrapping_bytes = hex::decode(wrapping_key_hex).map_err(|e| {
        crate::error::js_error("InvalidInput", format!("invalid wrapping_key: {}", e))
    })?;
    let wrapping_arr: [u8; 32] = wrapping_bytes
        .as_slice()
        .try_into()
        .map_err(|_| crate::error::js_error("InvalidInput", "wrapping_key must be 32 bytes"))?;
    let wrapping_key = kchat_drive_types::Key256::new(wrapping_arr);

    // Load pepper from SDK vault — auto-initialize if missing.
    let pepper = match runtime.facade.load_tenant_pepper(&tenant_id) {
        Ok(p) => p,
        Err(_) => runtime
            .facade
            .init_tenant_pepper(&tenant_id)
            .map_err(crate::error::to_js_error)?,
    };

    // Build transport adapter that calls the JS callbacks
    let transport = WasmDedupTransport {
        check_content_fn: &callbacks.check_content_fn,
        check_chunks_fn: &callbacks.check_chunks_fn,
        upload_blob_fn: &callbacks.upload_blob_fn,
        commit_version_fn: &callbacks.commit_version_fn,
    };

    // Call facade.upload_and_commit (pepper stays internal, created_at generated by facade)
    // This handles: encrypt, dedup check, blob upload, header CBOR encode, and version commit
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
            access_context_revision,
            &snapshot_hash,
            &wrapping_key,
            &pepper,
            &transport,
        )
        .map_err(crate::error::to_js_error)?;

    // Encode signed header as CBOR for the result JSON
    let header_cbor = minicbor::to_vec(&result.header)
        .map_err(|e| crate::error::to_js_error(DriveError::Serialize(e.to_string())))?;

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
