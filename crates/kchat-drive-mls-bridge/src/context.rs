use sha2::{Digest, Sha256};

use kchat_drive_types::{DomainId, DriveError, EnvelopeId, Hash256, ShareGrantId};

/// MLS exporter label for Advanced mode domain key transport.
pub const ADVANCED_DOMAIN_LABEL: &str = "org.kchat.drive.advanced-domain-transport.v1";

/// MLS exporter label for Max mode share grant key transport.
pub const MAX_SHARE_GRANT_LABEL: &str = "org.kchat.drive.max-share-grant-transport.v1";

/// Purpose string for Advanced mode transport key derivation.
pub const ADVANCED_PURPOSE: &str = "advanced-domain";

/// Purpose string for Max mode transport key derivation.
pub const MAX_PURPOSE: &str = "max-share-grant";

/// Transport context for Advanced mode domain key seal/open.
#[derive(Debug, Clone)]
pub struct AdvancedTransportContext {
    pub domain_id: DomainId,
    pub generation: u64,
    pub mls_epoch: u64,
    pub mls_tree_hash: Hash256,
    /// Pre-computed context bytes (domain_id || generation || mls_epoch || mls_tree_hash).
    context: [u8; 64],
}

impl AdvancedTransportContext {
    /// Creates a new Advanced transport context, pre-computing the context bytes.
    pub fn new(
        domain_id: DomainId,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash: Hash256,
    ) -> Self {
        let mut context = [0u8; 64];
        context[0..16].copy_from_slice(domain_id.as_bytes());
        context[16..24].copy_from_slice(&generation.to_be_bytes());
        context[24..32].copy_from_slice(&mls_epoch.to_be_bytes());
        context[32..64].copy_from_slice(mls_tree_hash.as_bytes());
        Self {
            domain_id,
            generation,
            mls_epoch,
            mls_tree_hash,
            context,
        }
    }

    /// Returns the context bytes passed to MLS export_secret.
    /// context = CBOR-encoded (domain_id, generation, mls_epoch, mls_tree_hash)
    pub fn context_bytes(&self) -> &[u8] {
        &self.context
    }

    /// Returns SHA-256 of the context bytes (used in transport key derivation).
    pub fn context_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.context_bytes());
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }
}

/// Transport context for Max mode share grant key seal/open.
#[derive(Debug, Clone)]
pub struct MaxTransportContext {
    pub grant_id: ShareGrantId,
    pub generation: u64,
    pub mls_epoch: u64,
    pub mls_tree_hash: Hash256,
    pub recipient_user_set_root: Hash256,
    pub user_snapshot_hash: Hash256,
    /// Pre-computed context bytes.
    context: [u8; 128],
}

impl MaxTransportContext {
    /// Creates a new Max transport context, pre-computing the context bytes.
    pub fn new(
        grant_id: ShareGrantId,
        generation: u64,
        mls_epoch: u64,
        mls_tree_hash: Hash256,
        recipient_user_set_root: Hash256,
        user_snapshot_hash: Hash256,
    ) -> Self {
        let mut context = [0u8; 128];
        context[0..16].copy_from_slice(grant_id.as_bytes());
        context[16..24].copy_from_slice(&generation.to_be_bytes());
        context[24..32].copy_from_slice(&mls_epoch.to_be_bytes());
        context[32..64].copy_from_slice(mls_tree_hash.as_bytes());
        context[64..96].copy_from_slice(recipient_user_set_root.as_bytes());
        context[96..128].copy_from_slice(user_snapshot_hash.as_bytes());
        Self {
            grant_id,
            generation,
            mls_epoch,
            mls_tree_hash,
            recipient_user_set_root,
            user_snapshot_hash,
            context,
        }
    }

    /// Returns the context bytes passed to MLS export_secret.
    pub fn context_bytes(&self) -> &[u8] {
        &self.context
    }

    /// Returns SHA-256 of the context bytes.
    pub fn context_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.context_bytes());
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }
}

/// Returns the MLS exporter label for the given purpose.
pub fn exporter_label(purpose: &str) -> Result<&'static str, DriveError> {
    match purpose {
        ADVANCED_PURPOSE => Ok(ADVANCED_DOMAIN_LABEL),
        MAX_PURPOSE => Ok(MAX_SHARE_GRANT_LABEL),
        _ => Err(DriveError::InvalidState(format!(
            "unknown purpose: {}",
            purpose
        ))),
    }
}

/// Derives transport key + nonce from MLS exporter output.
pub fn derive_transport_key_and_nonce(
    transport_salt: &[u8],
    mls_exporter_output: &[u8],
    purpose: &str,
    context_hash: &[u8; 32],
    envelope_id: &EnvelopeId,
) -> Result<([u8; 32], [u8; 12]), DriveError> {
    let key = kchat_drive_crypto::derive_transport_key(
        transport_salt,
        mls_exporter_output,
        purpose,
        context_hash,
        envelope_id.as_bytes(),
    )?;
    let nonce = kchat_drive_crypto::derive_transport_nonce(
        transport_salt,
        mls_exporter_output,
        purpose,
        context_hash,
        envelope_id.as_bytes(),
    )?;
    Ok((key, nonce))
}
