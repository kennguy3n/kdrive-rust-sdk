use rand::RngCore;
use wasm_bindgen::prelude::*;

use kchat_client_runtime::facade::DriveFacade;
use kchat_client_runtime::runtime::ClientRuntime;
use kchat_drive_types::TenantId;

/// Persistent WASM Drive runtime.
///
/// Wraps `ClientRuntime` + `DriveFacade` so that the encrypted vault
/// (including the tenant pepper) persists across calls within a single
/// page session. The master key can be provided from JS (e.g. derived
/// from WebCrypto PBKDF2 over a user passphrase) or auto-generated.
///
/// Production flow:
/// 1. JS creates `new WasmDriveRuntime(masterKeyHex)` once at app startup.
/// 2. JS calls `init_tenant_pepper(tenantIdHex)` on first use per tenant.
///    The pepper is generated inside the SDK and stored in the encrypted vault.
/// 3. JS calls `dedup_upload(runtime, tenantIdHex, ...)` — the SDK loads
///    the pepper from the vault internally; JS never sees the pepper.
/// 4. For multi-device sync, JS calls `seal_pepper_for_mls(...)` to get
///    an MLS-encrypted pepper blob to send via MLS group messages.
/// 5. New devices call `open_pepper_from_mls(...)` to unwrap and store.
#[wasm_bindgen]
pub struct WasmDriveRuntime {
    #[allow(dead_code)]
    runtime: std::sync::Arc<ClientRuntime>,
    pub(crate) facade: DriveFacade,
}

#[wasm_bindgen]
impl WasmDriveRuntime {
    /// Creates a runtime with a fresh auto-generated master key.
    /// The vault is in-memory only — pepper is lost on page reload.
    /// For persistence, use `with_master_key` with a WebCrypto-derived key.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        // Empty key → generate random (always succeeds)
        Self::with_master_key_hex("").unwrap_or_else(|_| {
            // Fallback: direct construction with random key (never fails)
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let runtime = std::sync::Arc::new(ClientRuntime::with_master_key(key));
            let facade = DriveFacade::new(runtime.clone());
            Self { runtime, facade }
        })
    }

    /// Creates a runtime with a specific 32-byte master key (hex-encoded).
    /// If `master_key_hex` is empty, a random key is generated.
    /// In production, JS should derive this from a user passphrase via
    /// WebCrypto PBKDF2 and persist it (e.g. in IndexedDB or via
    /// the WebAuthn platform authenticator).
    #[wasm_bindgen(js_name = withMasterKey)]
    pub fn with_master_key_hex(master_key_hex: &str) -> Result<Self, JsValue> {
        let master_key = if master_key_hex.is_empty() {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            key
        } else {
            let bytes = hex::decode(master_key_hex).map_err(|e| {
                crate::error::js_error("InvalidInput", format!("invalid master_key hex: {}", e))
            })?;
            if bytes.len() != 32 {
                return Err(crate::error::js_error(
                    "InvalidState",
                    format!(
                        "master_key must be 32 bytes (64 hex chars), got {} bytes",
                        bytes.len()
                    ),
                ));
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
    ///
    /// B2B: call once per tenant (each tenant gets its own pepper).
    /// B2C: call once with the shared B2C tenant ID (all B2C users share it).
    #[wasm_bindgen(js_name = initTenantPepper)]
    pub fn init_tenant_pepper(&self, tenant_id_hex: &str) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper = self
            .facade
            .init_tenant_pepper(&tenant_id)
            .map_err(crate::error::to_js_error)?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper from the vault (without creating if missing).
    /// Returns the pepper hex, or throws if not found.
    #[wasm_bindgen(js_name = loadTenantPepper)]
    pub fn load_tenant_pepper(&self, tenant_id_hex: &str) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper = self
            .facade
            .load_tenant_pepper(&tenant_id)
            .map_err(crate::error::to_js_error)?;
        Ok(hex::encode(pepper))
    }

    /// Loads the tenant pepper from the vault, auto-initializing if missing.
    /// This is the convenience method for the common case: first upload
    /// auto-generates the pepper, subsequent uploads reuse it.
    #[wasm_bindgen(js_name = ensureTenantPepper)]
    pub fn ensure_tenant_pepper(&self, tenant_id_hex: &str) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper = match self.facade.load_tenant_pepper(&tenant_id) {
            Ok(p) => p,
            Err(_) => self
                .facade
                .init_tenant_pepper(&tenant_id)
                .map_err(crate::error::to_js_error)?,
        };
        Ok(hex::encode(pepper))
    }

    /// Stores an existing pepper into the vault (e.g. unwrapped from MLS).
    /// Used when a new device receives the pepper via MLS distribution.
    #[wasm_bindgen(js_name = storeTenantPepper)]
    pub fn store_tenant_pepper(
        &self,
        tenant_id_hex: &str,
        pepper_hex: &str,
    ) -> Result<(), JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper_bytes = hex::decode(pepper_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid pepper: {}", e))
        })?;
        let pepper: [u8; 32] = pepper_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::js_error("InvalidInput", "pepper must be 32 bytes"))?;
        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(crate::error::to_js_error)
    }

    /// Checks whether a tenant pepper exists in the vault.
    #[wasm_bindgen(js_name = hasTenantPepper)]
    pub fn has_tenant_pepper(&self, tenant_id_hex: &str) -> bool {
        let Ok(tenant_id) = TenantId::from_hex(tenant_id_hex) else {
            return false;
        };
        self.facade.load_tenant_pepper(&tenant_id).is_ok()
    }

    /// Seals the tenant pepper using an MLS exporter-derived transport key.
    ///
    /// This produces an encrypted blob that can be sent via MLS group messages
    /// to other group members. Recipients call `open_pepper_from_mls` to unwrap.
    ///
    /// Parameters:
    /// - `mls_exporter_output_hex`: MLS exporter output (from `export_secret`)
    /// - `transport_salt_hex`: Random salt for HKDF key derivation
    /// - `domain_id_hex`: Domain ID (binds to MLS context)
    /// - `generation`: Key generation number
    /// - `mls_epoch`: MLS epoch number
    /// - `mls_tree_hash_hex`: MLS tree hash (binds to group state)
    /// - `envelope_id_hex`: Unique envelope ID for this seal
    ///
    /// Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
    #[wasm_bindgen(js_name = sealPepperForMls)]
    pub fn seal_pepper_for_mls(
        &self,
        tenant_id_hex: &str,
        mls_exporter_output_hex: &str,
        transport_salt_hex: &str,
        domain_id_hex: &str,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash_hex: &str,
        envelope_id_hex: &str,
    ) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper = self.facade.load_tenant_pepper(&tenant_id).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("pepper not in vault: {}", e))
        })?;

        let exporter_out = hex::decode(mls_exporter_output_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid exporter output: {}", e))
        })?;
        let salt = hex::decode(transport_salt_hex)
            .map_err(|e| crate::error::js_error("InvalidInput", format!("invalid salt: {}", e)))?;
        let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
            .map_err(crate::error::to_js_error)?;
        let tree_hash_bytes = hex::decode(mls_tree_hash_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid tree_hash: {}", e))
        })?;
        let tree_hash = kchat_drive_types::Hash256::from_slice(&tree_hash_bytes);
        let envelope_id = kchat_drive_types::EnvelopeId::from_hex(envelope_id_hex)
            .map_err(crate::error::to_js_error)?;

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
        )
        .map_err(crate::error::to_js_error)?;

        let json = serde_json::json!({
            "ciphertext_hex": hex::encode(&ct),
            "nonce_hex": hex::encode(nonce.as_bytes()),
        });
        Ok(json.to_string())
    }

    /// Opens a tenant pepper sealed via MLS and stores it in the vault.
    ///
    /// Called by a new device that received the sealed pepper via MLS.
    /// The device must be a member of the same MLS group at the same epoch
    /// to derive the same transport key.
    ///
    /// Parameters match `seal_pepper_for_mls`, plus:
    /// - `ciphertext_hex`: The sealed pepper ciphertext
    /// - `nonce_hex`: The nonce from the seal operation
    ///
    /// Returns the pepper hex (for verification), or throws on error.
    #[wasm_bindgen(js_name = openPepperFromMls)]
    pub fn open_pepper_from_mls(
        &self,
        tenant_id_hex: &str,
        ciphertext_hex: &str,
        nonce_hex: &str,
        mls_exporter_output_hex: &str,
        transport_salt_hex: &str,
        domain_id_hex: &str,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash_hex: &str,
        envelope_id_hex: &str,
    ) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;

        let ct = hex::decode(ciphertext_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid ciphertext: {}", e))
        })?;
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|e| crate::error::js_error("InvalidInput", format!("invalid nonce: {}", e)))?;
        let nonce_bytes: [u8; 12] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::js_error("InvalidInput", "nonce must be 12 bytes"))?;
        let nonce = kchat_drive_types::Nonce12::new(nonce_bytes);

        let exporter_out = hex::decode(mls_exporter_output_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid exporter output: {}", e))
        })?;
        let salt = hex::decode(transport_salt_hex)
            .map_err(|e| crate::error::js_error("InvalidInput", format!("invalid salt: {}", e)))?;
        let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
            .map_err(crate::error::to_js_error)?;
        let tree_hash_bytes = hex::decode(mls_tree_hash_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid tree_hash: {}", e))
        })?;
        let tree_hash = kchat_drive_types::Hash256::from_slice(&tree_hash_bytes);
        let envelope_id = kchat_drive_types::EnvelopeId::from_hex(envelope_id_hex)
            .map_err(crate::error::to_js_error)?;

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
        )
        .map_err(crate::error::to_js_error)?;

        // Store in vault for future use
        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(crate::error::to_js_error)?;

        Ok(hex::encode(pepper))
    }

    /// Wraps the tenant pepper under a DomainKey (Secured/Advanced mode).
    ///
    /// This produces a backup copy of the pepper encrypted under the domain key,
    /// which can be stored in gateway metadata. New devices that have the domain
    /// key can unwrap the pepper without MLS.
    ///
    /// Returns JSON: `{ "ciphertext_hex": "...", "nonce_hex": "..." }`
    #[wasm_bindgen(js_name = wrapPepperUnderDomainKey)]
    pub fn wrap_pepper_under_domain_key(
        &self,
        tenant_id_hex: &str,
        domain_key_hex: &str,
    ) -> Result<String, JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;
        let pepper = self.facade.load_tenant_pepper(&tenant_id).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("pepper not in vault: {}", e))
        })?;

        let dk_bytes = hex::decode(domain_key_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid domain_key: {}", e))
        })?;
        let dk_arr: [u8; 32] = dk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::js_error("InvalidInput", "domain_key must be 32 bytes"))?;
        let domain_key = kchat_drive_types::Key256::new(dk_arr);

        let (ct, nonce) = kchat_drive_crypto::wrap_pepper_under_domain_key(&domain_key, &pepper)
            .map_err(crate::error::to_js_error)?;

        let json = serde_json::json!({
            "ciphertext_hex": hex::encode(&ct),
            "nonce_hex": hex::encode(nonce.as_bytes()),
        });
        Ok(json.to_string())
    }

    /// Unwraps a pepper from a DomainKey-wrapped blob and stores it in the vault.
    ///
    /// Used when a new device has the domain key but no MLS access.
    #[wasm_bindgen(js_name = unwrapPepperFromDomainKey)]
    pub fn unwrap_pepper_from_domain_key(
        &self,
        tenant_id_hex: &str,
        ciphertext_hex: &str,
        nonce_hex: &str,
        domain_key_hex: &str,
    ) -> Result<(), JsValue> {
        let tenant_id = TenantId::from_hex(tenant_id_hex).map_err(crate::error::to_js_error)?;

        let ct = hex::decode(ciphertext_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid ciphertext: {}", e))
        })?;
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|e| crate::error::js_error("InvalidInput", format!("invalid nonce: {}", e)))?;
        let nonce_bytes: [u8; 12] = nonce_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::js_error("InvalidInput", "nonce must be 12 bytes"))?;
        let nonce = kchat_drive_types::Nonce12::new(nonce_bytes);

        let dk_bytes = hex::decode(domain_key_hex).map_err(|e| {
            crate::error::js_error("InvalidInput", format!("invalid domain_key: {}", e))
        })?;
        let dk_arr: [u8; 32] = dk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::error::js_error("InvalidInput", "domain_key must be 32 bytes"))?;
        let domain_key = kchat_drive_types::Key256::new(dk_arr);

        let pepper = kchat_drive_crypto::unwrap_pepper_from_domain_key(&domain_key, &ct, &nonce)
            .map_err(crate::error::to_js_error)?;

        self.facade
            .store_tenant_pepper(&tenant_id, &pepper)
            .map_err(crate::error::to_js_error)
    }

    /// Returns the master key hex (for JS to persist across sessions).
    /// In production, JS should store this securely (e.g. WebCrypto + IndexedDB).
    #[wasm_bindgen(js_name = exportMasterKey)]
    pub fn export_master_key(&self) -> Result<String, JsValue> {
        let vault = self.runtime.vault();
        Ok(hex::encode(vault.master_key()))
    }

    /// Creates a domain key and stores it in the vault.
    #[wasm_bindgen(js_name = createDomain)]
    pub fn create_domain(&self, domain_id_hex: &str) -> Result<String, JsValue> {
        let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
            .map_err(crate::error::to_js_error)?;
        let record = kchat_drive_crypto::generate_domain_key(domain_id.clone());
        // Store in vault
        let vault_key = format!("domain_key:{}", domain_id);
        self.runtime
            .vault()
            .store(&vault_key, record.key.as_bytes())
            .map_err(crate::error::to_js_error)?;
        Ok(hex::encode(record.key.as_bytes()))
    }
}

impl Default for WasmDriveRuntime {
    fn default() -> Self {
        Self::new()
    }
}
