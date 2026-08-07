use wasm_bindgen::prelude::*;

/// WASM-exposed high-level Drive API.
/// These functions wrap the crypto operations and return JSON for JS consumption.

#[wasm_bindgen]
pub struct WasmDriveRuntime {
    #[allow(dead_code)]
    master_key: [u8; 32],
}

#[wasm_bindgen]
impl WasmDriveRuntime {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { master_key: key }
    }

    pub fn create_domain(&self, domain_id_hex: &str) -> Result<String, JsValue> {
        let domain_id = kchat_drive_types::DomainId::from_hex(domain_id_hex)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let record = kchat_drive_crypto::generate_domain_key(domain_id);
        Ok(hex::encode(record.key.as_bytes()))
    }
}

impl Default for WasmDriveRuntime {
    fn default() -> Self {
        Self::new()
    }
}
