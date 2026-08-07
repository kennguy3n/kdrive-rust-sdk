use ed25519_dalek::SigningKey;

use kchat_drive_types::{DeviceId, Ed25519PublicKey};

/// Per-device signing key material, kept secret.
/// The `SigningKey` from `ed25519-dalek` zeroizes itself on drop
/// when the `zeroize` feature is enabled.
#[derive(Debug)]
pub struct DeviceKeyPair {
    pub device_id: DeviceId,
    signing_key: SigningKey,
    public_key: Ed25519PublicKey,
}

impl DeviceKeyPair {
    /// Generates a new device keypair.
    pub fn generate(device_id: DeviceId) -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            device_id,
            signing_key,
            public_key: Ed25519PublicKey::new(verifying_key.to_bytes()),
        }
    }

    /// Returns the public key.
    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// Returns a reference to the signing key.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Serializes the private key to bytes (for encrypted storage).
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Deserializes from private key bytes.
    pub fn from_private_bytes(device_id: DeviceId, bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            device_id,
            signing_key,
            public_key: Ed25519PublicKey::new(verifying_key.to_bytes()),
        }
    }
}
