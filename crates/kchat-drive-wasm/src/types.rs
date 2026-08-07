use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// WASM type conversions for Drive types.

#[derive(Serialize, Deserialize)]
pub struct PublicKeyPair {
    pub private_key_hex: String,
    pub public_key_hex: String,
}

#[wasm_bindgen]
pub fn generate_hpke_keypair() -> Result<JsValue, JsValue> {
    let (priv_key, pub_key) = kchat_drive_crypto::hpke::generate_keypair();
    let result = PublicKeyPair {
        private_key_hex: hex::encode(priv_key),
        public_key_hex: hex::encode(pub_key),
    };
    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

#[wasm_bindgen]
pub fn generate_ed25519_keypair() -> Result<JsValue, JsValue> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let result = PublicKeyPair {
        private_key_hex: hex::encode(signing_key.to_bytes()),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
    };
    Ok(JsValue::from_str(&serde_json::to_string(&result).unwrap()))
}

#[wasm_bindgen]
pub fn random_id_hex() -> String {
    kchat_drive_types::OpaqueId::random().to_hex()
}

#[wasm_bindgen]
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}
