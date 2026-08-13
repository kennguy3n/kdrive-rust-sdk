use crate::ids::*;
use crate::roles::PrivacyMode;
use minicbor::{Decode, Encode};

/// Public version header (architecture §9.1).
/// This is the canonical public metadata for a file version. It is
/// signed with Ed25519 by the creating device.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct PublicVersionHeader {
    /// KDRV1 protocol version (currently 1).
    #[n(0)]
    pub protocol: u16,

    /// Crypto suite (currently 1 = KDRV1).
    #[n(1)]
    pub suite: u16,

    /// Drive ID this version belongs to.
    #[n(2)]
    pub drive_id: DriveId,

    /// Node (file) ID.
    #[n(3)]
    pub node_id: NodeId,

    /// Version ID (unique per version).
    #[n(4)]
    pub version_id: VersionId,

    /// Encryption domain ID.
    #[n(5)]
    pub domain_id: DomainId,

    /// Privacy mode governing this version.
    #[n(6)]
    pub privacy_mode: PrivacyMode,

    /// Total plaintext size in bytes.
    #[n(7)]
    pub plaintext_size: u64,

    /// Chunk size used (bytes).
    #[n(8)]
    pub chunk_size: u64,

    /// Number of chunks.
    #[n(9)]
    pub chunk_count: u64,

    /// Chunk plan Merkle root (SHA-256).
    #[n(10)]
    pub chunk_plan_root: Hash256,

    /// SHA-256 of the encrypted manifest.
    #[n(11)]
    pub manifest_ciphertext_sha256: Hash256,

    /// Manifest ciphertext length (bytes).
    #[n(12)]
    pub manifest_ciphertext_len: u64,

    /// Manifest nonce (12 bytes).
    #[n(13)]
    pub manifest_nonce: Nonce12,

    /// Access-context revision number.
    #[n(14)]
    pub access_context_revision: u64,

    /// Access-context snapshot hash (SHA-256).
    #[n(15)]
    pub access_context_snapshot_hash: Hash256,

    /// Creating device's Ed25519 public key.
    #[n(16)]
    pub creator_device_key: Ed25519PublicKey,

    /// Creation timestamp (Unix epoch seconds).
    #[n(17)]
    pub created_at: u64,

    /// Ed25519 signature over the canonical header (excluding this field).
    #[n(18)]
    pub signature: Option<Ed25519Signature>,

    /// KDRV1: content ID for dedup (HMAC of plaintext hash with tenant pepper).
    /// None for KDRV1 headers.
    #[n(19)]
    pub content_id: Option<Hash256>,
}

impl PublicVersionHeader {
    /// Returns the canonical bytes that are signed (everything except
    /// the signature field). Used for signature verification and
    /// VersionHeaderHash computation.
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>, super::DriveError> {
        let mut clone = self.clone();
        clone.signature = None;
        let mut buf = Vec::new();
        minicbor::encode(&clone, &mut buf)
            .map_err(|e| super::DriveError::CborEncode(e.to_string()))?;
        Ok(buf)
    }

    /// Returns the SHA-256 hash of the canonical header (with signature
    /// if present, or without if not). Used for re-share wrap lookups.
    pub fn version_header_hash(&self) -> Result<Hash256, super::DriveError> {
        use sha2::{Digest, Sha256};
        let mut buf = Vec::new();
        minicbor::encode(self, &mut buf)
            .map_err(|e| super::DriveError::CborEncode(e.to_string()))?;
        let hash = Sha256::digest(&buf);
        Ok(Hash256::from_slice(&hash))
    }
}

/// Chunk descriptor: metadata for a single chunk.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ChunkDescriptor {
    /// Chunk index (0-based).
    #[n(0)]
    pub index: u64,

    /// Plaintext length of this chunk.
    #[n(1)]
    pub plaintext_len: u64,

    /// Ciphertext length (plaintext_len + 16 for GCM tag).
    #[n(2)]
    pub ciphertext_len: u64,

    /// SHA-256 of the ciphertext.
    #[n(3)]
    pub ciphertext_sha256: Hash256,

    /// Blob key in the BlobStore (opaque).
    #[n(4)]
    pub blob_key: String,
}

/// Chunk plan: the full list of chunk descriptors for a version.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ChunkPlan {
    #[n(0)]
    pub chunks: Vec<ChunkDescriptor>,
}

impl ChunkPlan {
    /// Computes the Merkle root over chunk plan leaves:
    /// SHA-256("kchat-drive/chunk-plan-leaf/v1" || u64be(i) || u64be(len) || sha256)
    pub fn merkle_root(&self) -> Hash256 {
        use sha2::{Digest, Sha256};
        let mut leaves: Vec<[u8; 32]> = self
            .chunks
            .iter()
            .map(|c| {
                let mut hasher = Sha256::new();
                hasher.update(crate::CHUNK_PLAN_LEAF_TAG);
                hasher.update(c.index.to_be_bytes());
                hasher.update(c.plaintext_len.to_be_bytes());
                hasher.update(c.ciphertext_sha256.as_bytes());
                let result = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                arr
            })
            .collect();

        if leaves.is_empty() {
            return Hash256::new([0u8; 32]);
        }

        while leaves.len() > 1 {
            let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
            for pair in leaves.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(crate::CHUNK_PLAN_NODE_TAG);
                hasher.update(pair[0]);
                if pair.len() == 2 {
                    hasher.update(pair[1]);
                } else {
                    hasher.update(pair[0]);
                }
                let result = hasher.finalize();
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&result);
                next.push(arr);
            }
            leaves = next;
        }
        Hash256::new(leaves[0])
    }
}
