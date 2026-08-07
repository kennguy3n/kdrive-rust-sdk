use hpke::kem::X25519HkdfSha256;
use hpke::{Kem, Serializable};

use kchat_drive_types::X25519PublicKey;

/// Generates an X25519 keypair for HPKE.
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let (priv_key, pub_key) = X25519HkdfSha256::gen_keypair(&mut rand::rngs::OsRng);

    let priv_bytes = priv_key.to_bytes();
    let pub_bytes = pub_key.to_bytes();
    let mut priv_arr = [0u8; 32];
    let mut pub_arr = [0u8; 32];
    priv_arr.copy_from_slice(priv_bytes.as_slice());
    pub_arr.copy_from_slice(pub_bytes.as_slice());
    (priv_arr, pub_arr)
}

/// Wraps an X25519PublicKey from raw bytes.
pub fn make_public_key(bytes: [u8; 32]) -> X25519PublicKey {
    X25519PublicKey::new(bytes)
}
