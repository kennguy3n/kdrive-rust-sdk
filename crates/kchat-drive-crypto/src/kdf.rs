use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use kchat_drive_types::{Hash256, NodeId, PROTOCOL_VERSION, VersionId};

// Re-export centralized labels for backward compatibility.
pub use crate::labels::{
    CHUNK_KEY_INFO, CHUNK_NONCE_INFO, MANIFEST_KEY_INFO, MANIFEST_NONCE_INFO, VERSION_SALT,
};

/// Extracts the PRK from version salt + VersionDEK.
/// PRK = HKDF-Extract(version_salt, VersionDEK)
pub fn extract_prk(version_dek: &[u8; 32]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(VERSION_SALT), version_dek);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(prk.as_slice());
    arr
}

/// Derives a chunk key:
/// HKDF-Expand(PRK, "kchat-drive/chunk-key/v1" || node_id || version_id || u64be(i), 32)
pub fn derive_chunk_key(
    prk: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    chunk_index: u64,
) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(CHUNK_KEY_INFO.as_bytes());
    info.extend_from_slice(node_id.as_bytes());
    info.extend_from_slice(version_id.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm).expect("32 bytes is valid");
    okm
}

/// Derives a chunk nonce:
/// HKDF-Expand(PRK, "kchat-drive/chunk-nonce/v1" || node_id || version_id || u64be(i), 12)
pub fn derive_chunk_nonce(
    prk: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    chunk_index: u64,
) -> [u8; 12] {
    let mut info = Vec::new();
    info.extend_from_slice(CHUNK_NONCE_INFO.as_bytes());
    info.extend_from_slice(node_id.as_bytes());
    info.extend_from_slice(version_id.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm).expect("12 bytes is valid");
    okm
}

/// Derives the manifest key:
/// HKDF-Expand(PRK, "kchat-drive/manifest-key/v1" || node_id || version_id, 32)
pub fn derive_manifest_key(prk: &[u8; 32], node_id: &NodeId, version_id: &VersionId) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(MANIFEST_KEY_INFO.as_bytes());
    info.extend_from_slice(node_id.as_bytes());
    info.extend_from_slice(version_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm).expect("32 bytes is valid");
    okm
}

/// Derives the manifest nonce:
/// HKDF-Expand(PRK, "kchat-drive/manifest-nonce/v1" || node_id || version_id, 12)
pub fn derive_manifest_nonce(prk: &[u8; 32], node_id: &NodeId, version_id: &VersionId) -> [u8; 12] {
    let mut info = Vec::new();
    info.extend_from_slice(MANIFEST_NONCE_INFO.as_bytes());
    info.extend_from_slice(node_id.as_bytes());
    info.extend_from_slice(version_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm).expect("12 bytes is valid");
    okm
}

/// Derives a transport key from MLS exporter output:
/// HKDF-Extract(transport_salt, MLSExporterOutput) → expand with purpose-specific info.
pub fn derive_transport_key(
    transport_salt: &[u8],
    mls_exporter_output: &[u8],
    purpose: &str,
    context_hash: &[u8; 32],
    envelope_id: &[u8; 16],
) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(transport_salt), mls_exporter_output);
    let mut prk_bytes = [0u8; 32];
    prk_bytes.copy_from_slice(prk.as_slice());
    let mut info = Vec::new();
    info.extend_from_slice(format!("kchat-drive/{}/transport-key/v1", purpose).as_bytes());
    info.extend_from_slice(context_hash);
    info.extend_from_slice(envelope_id);

    let hkdf = Hkdf::<Sha256>::from_prk(&prk_bytes).expect("valid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm).expect("32 bytes is valid");
    prk_bytes.zeroize();
    okm
}

/// Derives a transport nonce from MLS exporter output.
pub fn derive_transport_nonce(
    transport_salt: &[u8],
    mls_exporter_output: &[u8],
    purpose: &str,
    context_hash: &[u8; 32],
    envelope_id: &[u8; 16],
) -> [u8; 12] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(transport_salt), mls_exporter_output);
    let mut prk_bytes = [0u8; 32];
    prk_bytes.copy_from_slice(prk.as_slice());
    let mut info = Vec::new();
    info.extend_from_slice(format!("kchat-drive/{}/transport-nonce/v1", purpose).as_bytes());
    info.extend_from_slice(context_hash);
    info.extend_from_slice(envelope_id);

    let hkdf = Hkdf::<Sha256>::from_prk(&prk_bytes).expect("valid PRK");
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm).expect("12 bytes is valid");
    prk_bytes.zeroize();
    okm
}

/// Generates a random 32-byte key (VersionDEK, DomainKey, ShareGrantKey).
#[must_use]
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generates a random 16-byte salt.
#[must_use]
pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

/// Selects chunk size based on file size (architecture §9.2).
/// < 64 MiB → 4 MiB, < 512 MiB → 8 MiB, >= 512 MiB → 16 MiB.
#[must_use]
pub fn select_chunk_size(file_size: u64) -> u64 {
    const MIB: u64 = 1024 * 1024;
    if file_size < 64 * MIB {
        4 * MIB
    } else if file_size < 512 * MIB {
        8 * MIB
    } else {
        16 * MIB
    }
}

/// Computes the number of chunks for a given file size and chunk size.
#[must_use]
pub fn chunk_count(file_size: u64, chunk_size: u64) -> u64 {
    if file_size == 0 {
        1 // At least one chunk (empty file)
    } else {
        file_size.div_ceil(chunk_size)
    }
}

/// Protocol version as used in AAD construction.
pub fn aad_protocol() -> u16 {
    PROTOCOL_VERSION
}

// ---------------------------------------------------------------------------
// KDRV — Content deduplication KDF labels
// ---------------------------------------------------------------------------

// Protocol/suite constants are re-exported from kchat_drive_types to avoid
// duplication. Use `kchat_drive_types::PROTOCOL_KDRV1` etc.
pub use kchat_drive_types::{PROTOCOL_KDRV1, SUITE_KDRV1};

// Re-export content-layer labels for backward compatibility.
pub use crate::labels::{
    CONTENT_CHUNK_KEY_INFO, CONTENT_CHUNK_NONCE_INFO, CONTENT_KEY_SALT, CONTENT_WRAP_KEY_INFO,
    CONTENT_WRAP_NONCE_INFO, PEPPER_WRAP_SALT,
};

/// Derives the ContentKey from plaintext hash + tenant pepper.
/// ContentKey = HKDF-Extract("kchat-drive/content-key/v1", plaintext_sha256 || tenant_pepper)
#[must_use]
pub fn derive_content_key(plaintext_sha256: &Hash256, tenant_pepper: &[u8; 32]) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(plaintext_sha256.as_bytes());
    ikm.extend_from_slice(tenant_pepper);

    let (prk, _) = Hkdf::<Sha256>::extract(Some(CONTENT_KEY_SALT), &ikm);
    ikm.zeroize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(prk.as_slice());
    arr
}

/// Computes the content_id = HMAC-SHA256(tenant_pepper, plaintext_sha256).
/// This is the tenant-scoped content identifier used for gateway dedup checks.
#[must_use]
pub fn compute_content_id(plaintext_sha256: &Hash256, tenant_pepper: &[u8; 32]) -> Hash256 {
    use sha2::digest::Mac;
    type HmacSha256 = hmac::Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(tenant_pepper).expect("32-byte key is valid for HMAC");
    mac.update(plaintext_sha256.as_bytes());
    let result = mac.finalize();
    Hash256::from_slice(&result.into_bytes())
}

/// Derives a content chunk key:
/// HKDF-Expand(ContentKey, "kchat-drive/chunk-content-key/v1" || u64be(i), 32)
#[must_use]
pub fn derive_content_chunk_key(content_key: &[u8; 32], chunk_index: u64) -> [u8; 32] {
    let mut info = Vec::new();
    info.extend_from_slice(CONTENT_CHUNK_KEY_INFO.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(content_key.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm).expect("32 bytes is valid");
    okm
}

/// Derives a content chunk nonce:
/// HKDF-Expand(ContentKey, "kchat-drive/chunk-content-nonce/v1" || u64be(i), 12)
#[must_use]
pub fn derive_content_chunk_nonce(content_key: &[u8; 32], chunk_index: u64) -> [u8; 12] {
    let mut info = Vec::new();
    info.extend_from_slice(CONTENT_CHUNK_NONCE_INFO.as_bytes());
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(content_key.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm).expect("12 bytes is valid");
    okm
}

/// Derives the content-wrap key from VersionDEK + version_id:
/// WrapKey = HKDF-Expand(PRK, "kchat-drive/content-wrap-key/v1" || version_id, 32)
/// where PRK = HKDF-Extract(version_salt, VersionDEK) (same as KDRV1).
#[must_use]
pub fn derive_content_wrap_key(version_dek: &[u8; 32], version_id: &VersionId) -> [u8; 32] {
    let mut prk = extract_prk(version_dek);
    let mut info = Vec::new();
    info.extend_from_slice(CONTENT_WRAP_KEY_INFO.as_bytes());
    info.extend_from_slice(version_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 32];
    hkdf.expand(&info, &mut okm).expect("32 bytes is valid");
    prk.zeroize();
    okm
}

/// Derives the content-wrap nonce from VersionDEK + version_id:
/// WrapNonce = HKDF-Expand(PRK, "kchat-drive/content-wrap-nonce/v1" || version_id, 12)
#[must_use]
pub fn derive_content_wrap_nonce(version_dek: &[u8; 32], version_id: &VersionId) -> [u8; 12] {
    let mut prk = extract_prk(version_dek);
    let mut info = Vec::new();
    info.extend_from_slice(CONTENT_WRAP_NONCE_INFO.as_bytes());
    info.extend_from_slice(version_id.as_bytes());

    let hkdf = Hkdf::<Sha256>::from_prk(prk.as_slice()).expect("valid PRK");
    let mut okm = [0u8; 12];
    hkdf.expand(&info, &mut okm).expect("12 bytes is valid");
    prk.zeroize();
    okm
}

/// Generates a random 32-byte tenant pepper.
#[must_use]
pub fn generate_tenant_pepper() -> [u8; 32] {
    generate_key()
}
