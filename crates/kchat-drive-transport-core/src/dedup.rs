#![allow(clippy::too_many_arguments)]

use kchat_drive_types::{DriveError, Hash256};
use serde::{Deserialize, Serialize};

/// Result of a content dedup check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentCheckResult {
    /// Whether the content already exists in the tenant.
    pub exists: bool,
    /// Blob keys for the existing content (if exists).
    #[serde(default)]
    pub blob_keys: Vec<String>,
    /// Ciphertext hashes for the existing content (if exists).
    #[serde(default)]
    pub ciphertext_hashes: Vec<String>,
    /// Number of chunks in the existing content.
    #[serde(default)]
    pub chunk_count: u64,
    /// Plaintext size of the existing content.
    #[serde(default)]
    pub plaintext_size: u64,
}

/// Result of a per-chunk dedup check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkCheckResult {
    pub results: Vec<ChunkCheckEntry>,
}

/// Single chunk dedup check result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkCheckEntry {
    pub hash: String,
    pub exists: bool,
    pub blob_key: Option<String>,
}

/// Request for content check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentCheckRequest {
    pub content_id: String,
}

/// Request for chunk-level check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkCheckRequest {
    pub content_id: String,
    pub chunk_hashes: Vec<String>,
}

/// Result of a KDRV1 version commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupCommitResult {
    pub version_id: String,
    pub committed: bool,
    pub deduped_chunks: u64,
    pub new_chunks: u64,
}

/// Trait for transport-layer dedup operations.
/// Implementations make HTTP calls to the gateway's dedup endpoints.
pub trait DedupTransport {
    /// Checks if content already exists in the tenant.
    fn check_content(&self, content_id: &Hash256) -> Result<ContentCheckResult, DriveError>;

    /// Checks which chunks already exist (for partial dedup).
    fn check_chunks(
        &self,
        content_id: &Hash256,
        chunk_hashes: &[Hash256],
    ) -> Result<ChunkCheckResult, DriveError>;

    /// Uploads a single content blob (skipped if already exists).
    fn upload_content_blob(
        &self,
        blob_key: &str,
        ciphertext: &[u8],
        ciphertext_sha256: &Hash256,
    ) -> Result<(), DriveError>;

    /// Commits a KDRV1 version with dedup information.
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
    ) -> Result<DedupCommitResult, DriveError>;
}
