//! Centralized KDF labels, AAD strings, and domain-separation tags.
//!
//! All cryptographic domain-separation strings used in KDRV1 are defined here
//! as constants. This ensures:
//! - No typos or accidental label collisions
//! - Easy auditing of domain separation
//! - Single source of truth for all protocol labels

// ---------------------------------------------------------------------------
// KDF info strings (HKDF-Expand "info" parameter)
// ---------------------------------------------------------------------------

/// Info prefix for chunk key derivation.
pub const CHUNK_KEY_INFO: &str = "kchat-drive/chunk-key/v1";

/// Info prefix for chunk nonce derivation.
pub const CHUNK_NONCE_INFO: &str = "kchat-drive/chunk-nonce/v1";

/// Info prefix for manifest key derivation.
pub const MANIFEST_KEY_INFO: &str = "kchat-drive/manifest-key/v1";

/// Info prefix for manifest nonce derivation.
pub const MANIFEST_NONCE_INFO: &str = "kchat-drive/manifest-nonce/v1";

/// Info prefix for content chunk key derivation.
pub const CONTENT_CHUNK_KEY_INFO: &str = "kchat-drive/chunk-content-key/v1";

/// Info prefix for content chunk nonce derivation.
pub const CONTENT_CHUNK_NONCE_INFO: &str = "kchat-drive/chunk-content-nonce/v1";

/// Info prefix for content key wrapping under VersionDEK.
pub const CONTENT_WRAP_KEY_INFO: &str = "kchat-drive/content-wrap-key/v1";

/// Info prefix for content key wrap nonce derivation.
pub const CONTENT_WRAP_NONCE_INFO: &str = "kchat-drive/content-wrap-nonce/v1";

// ---------------------------------------------------------------------------
// HKDF-Extract salts
// ---------------------------------------------------------------------------

/// Version salt for KDRV1 KDF: HKDF-Extract salt = "kchat-drive/v1".
pub const VERSION_SALT: &[u8] = b"kchat-drive/v1";

/// HKDF-Extract salt for content key derivation.
pub const CONTENT_KEY_SALT: &[u8] = b"kchat-drive/content-key/v1";

/// HKDF-Extract salt for tenant pepper wrapping.
pub const PEPPER_WRAP_SALT: &[u8] = b"kchat-drive/pepper-wrap/v1";

// ---------------------------------------------------------------------------
// AAD strings for AEAD operations
// ---------------------------------------------------------------------------

/// AAD for content key wrapping.
pub const CONTENT_WRAP_AAD: &[u8] = b"kchat-drive/content-wrap/v1";

/// AAD for pepper wrapping (domain key mode).
/// Same value as PEPPER_WRAP_SALT — used as AEAD AAD, not HKDF salt.
pub const PEPPER_WRAP_AAD: &[u8] = b"kchat-drive/pepper-wrap/v1";

/// AAD for pepper wrapping (share grant key mode / Max mode).
pub const PEPPER_WRAP_MAX_AAD: &[u8] = b"kchat-drive/pepper-wrap-max/v1";

/// AAD for domain key chain operations.
pub const DOMAIN_KEY_CHAIN_AAD: &[u8] = b"kchat-drive/domain-key-chain/v1";

/// AAD for domain key wrapping.
pub const DOMAIN_WRAP_AAD: &[u8] = b"kchat-drive/domain-wrap/v1";

/// AAD for HPKE envelope operations.
pub const ENVELOPE_AAD: &[u8] = b"kchat-drive/envelope/v1";

/// AAD for recovery envelope operations.
pub const RECOVERY_AAD: &[u8] = b"kchat-drive/recovery/v1";

/// AAD for share grant key wrapping.
pub const SHARE_GRANT_WRAP_AAD: &[u8] = b"kchat-drive/share-grant-wrap/v1";

/// HPKE info string for envelope operations.
/// Same value as VERSION_SALT — used as HPKE info, not HKDF salt.
pub const HPKE_INFO: &[u8] = b"kchat-drive/v1";

// ---------------------------------------------------------------------------
// Signing domain-separation tags
// ---------------------------------------------------------------------------

/// Domain-separation tag for version header signing.
pub const HEADER_SIGNATURE_TAG: &[u8] = b"kchat-drive/version-header-signature/v1";

/// Domain-separation tag for pepper hash (audit only).
pub const PEPPER_HASH_TAG: &[u8] = b"kchat-drive/pepper-hash/v1";

// ---------------------------------------------------------------------------
// Merkle tree domain-separation tags
// ---------------------------------------------------------------------------

// Re-exported from kchat_drive_types to ensure both crates use the same tags.
pub use kchat_drive_types::{CHUNK_PLAN_LEAF_TAG, CHUNK_PLAN_NODE_TAG};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn info_strings_are_unique() {
        let infos: Vec<&[u8]> = vec![
            CHUNK_KEY_INFO.as_bytes(),
            CHUNK_NONCE_INFO.as_bytes(),
            MANIFEST_KEY_INFO.as_bytes(),
            MANIFEST_NONCE_INFO.as_bytes(),
            CONTENT_CHUNK_KEY_INFO.as_bytes(),
            CONTENT_CHUNK_NONCE_INFO.as_bytes(),
            CONTENT_WRAP_KEY_INFO.as_bytes(),
            CONTENT_WRAP_NONCE_INFO.as_bytes(),
        ];
        let set: HashSet<&[u8]> = infos.iter().copied().collect();
        assert_eq!(set.len(), infos.len(), "HKDF info strings must be unique");
    }

    #[test]
    fn aad_strings_are_unique() {
        let aads: Vec<&[u8]> = vec![
            CONTENT_WRAP_AAD,
            PEPPER_WRAP_AAD,
            PEPPER_WRAP_MAX_AAD,
            DOMAIN_KEY_CHAIN_AAD,
            DOMAIN_WRAP_AAD,
            ENVELOPE_AAD,
            RECOVERY_AAD,
            SHARE_GRANT_WRAP_AAD,
        ];
        let set: HashSet<&[u8]> = aads.iter().copied().collect();
        assert_eq!(set.len(), aads.len(), "AAD strings must be unique");
    }

    #[test]
    fn salts_are_unique() {
        let salts: Vec<&[u8]> = vec![VERSION_SALT, CONTENT_KEY_SALT, PEPPER_WRAP_SALT];
        let set: HashSet<&[u8]> = salts.iter().copied().collect();
        assert_eq!(set.len(), salts.len(), "HKDF salts must be unique");
    }

    #[test]
    fn all_labels_start_with_kchat_drive() {
        let all: Vec<&[u8]> = vec![
            CHUNK_KEY_INFO.as_bytes(),
            CHUNK_NONCE_INFO.as_bytes(),
            MANIFEST_KEY_INFO.as_bytes(),
            MANIFEST_NONCE_INFO.as_bytes(),
            CONTENT_CHUNK_KEY_INFO.as_bytes(),
            CONTENT_CHUNK_NONCE_INFO.as_bytes(),
            CONTENT_WRAP_KEY_INFO.as_bytes(),
            CONTENT_WRAP_NONCE_INFO.as_bytes(),
            VERSION_SALT,
            CONTENT_KEY_SALT,
            PEPPER_WRAP_SALT,
            CONTENT_WRAP_AAD,
            PEPPER_WRAP_AAD,
            PEPPER_WRAP_MAX_AAD,
            DOMAIN_KEY_CHAIN_AAD,
            DOMAIN_WRAP_AAD,
            ENVELOPE_AAD,
            RECOVERY_AAD,
            SHARE_GRANT_WRAP_AAD,
            HPKE_INFO,
            HEADER_SIGNATURE_TAG,
            PEPPER_HASH_TAG,
            CHUNK_PLAN_LEAF_TAG,
            CHUNK_PLAN_NODE_TAG,
        ];
        for label in &all {
            assert!(
                label.starts_with(b"kchat-drive/"),
                "label {:?} does not start with 'kchat-drive/'",
                String::from_utf8_lossy(label)
            );
        }
    }
}
