use crate::header::ChunkPlan;
use crate::ids::*;
use minicbor::{Decode, Encode};

/// File manifest (architecture §9.3).
/// Encrypted with ManifestKey and stored alongside the version header.
/// The manifest contains the chunk plan and file metadata.
///
/// KDRV1 fields (content_id, wrapped_content_key, content_wrap_nonce) are
/// None for KDRV1 manifests and Some for KDRV1 manifests.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Manifest {
    /// Version ID this manifest belongs to.
    #[n(0)]
    pub version_id: VersionId,

    /// Node ID.
    #[n(1)]
    pub node_id: NodeId,

    /// Chunk plan (list of chunk descriptors).
    #[n(2)]
    pub chunk_plan: ChunkPlan,

    /// Original file name (encrypted separately, stored as opaque bytes).
    #[n(3)]
    pub name_ciphertext: Vec<u8>,

    /// File MIME type (if known).
    #[n(4)]
    pub mime_type: Option<String>,

    /// Total plaintext size.
    #[n(5)]
    pub plaintext_size: u64,

    /// Version creation timestamp.
    #[n(6)]
    pub created_at: u64,

    /// Optional parent version ID (for version chains).
    #[n(7)]
    pub parent_version_id: Option<VersionId>,

    /// KDRV1: content ID (HMAC of plaintext hash with tenant pepper).
    /// None for KDRV1 manifests.
    #[n(8)]
    pub content_id: Option<Hash256>,

    /// KDRV1: ContentKey wrapped under VersionDEK.
    /// None for KDRV1 manifests.
    #[n(9)]
    pub wrapped_content_key: Option<Vec<u8>>,

    /// KDRV1: nonce used for ContentKey wrapping.
    /// None for KDRV1 manifests.
    #[n(10)]
    pub content_wrap_nonce: Option<Nonce12>,
}

impl Manifest {
    /// Returns true if this is a KDRV1 manifest (has content dedup fields).
    pub fn is_kdrv2(&self) -> bool {
        self.content_id.is_some()
    }
}

/// Domain key record (for Secured/Advanced backward chain, architecture §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DomainKeyRecord {
    /// Domain ID.
    #[n(0)]
    pub domain_id: DomainId,

    /// Generation number (monotonic).
    #[n(1)]
    pub generation: u64,

    /// The domain key itself (32 bytes). Stored encrypted in the vault.
    #[n(2)]
    pub key: Key256,

    /// Previous generation envelope: AEAD(DomainKey[g], DomainKey[g-1]).
    /// None for generation 0.
    #[n(3)]
    pub prev_envelope: Option<Vec<u8>>,

    /// Previous envelope nonce.
    #[n(4)]
    pub prev_envelope_nonce: Option<Nonce12>,

    /// Checkpoint flag — true every 32 generations.
    #[n(5)]
    pub is_checkpoint: bool,
}

/// Share grant key record (for Max mode, architecture §8.1).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct ShareGrantKeyRecord {
    /// Share grant ID.
    #[n(0)]
    pub grant_id: ShareGrantId,

    /// Generation number (monotonic per grant).
    #[n(1)]
    pub generation: u64,

    /// The share grant key (32 bytes). Stored encrypted in the vault.
    #[n(2)]
    pub key: Key256,

    /// Recipient user set root (immutable proof of who this grant covers).
    #[n(3)]
    pub recipient_user_set_root: Hash256,

    /// User snapshot hash (immutable).
    #[n(4)]
    pub user_snapshot_hash: Hash256,

    /// MLS epoch when this grant key was sealed.
    #[n(5)]
    pub mls_epoch: u64,

    /// MLS tree hash at seal time.
    #[n(6)]
    pub mls_tree_hash: Hash256,
}

/// Durable key receipt — returned by open-and-store operations.
/// Contains no key material, only proof of storage.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DurableKeyReceipt {
    /// Envelope ID that was opened.
    #[n(0)]
    pub envelope_id: EnvelopeId,

    /// Domain or grant ID.
    #[n(1)]
    pub domain_id: Option<DomainId>,

    /// Grant ID (Max mode).
    #[n(2)]
    pub grant_id: Option<ShareGrantId>,

    /// Generation number.
    #[n(3)]
    pub generation: u64,

    /// MLS epoch at open time.
    #[n(4)]
    pub mls_epoch: u64,

    /// SHA-256 of the stored key (for audit, not the key itself).
    #[n(5)]
    pub key_hash: Hash256,

    /// MLS exporter label used.
    #[n(6)]
    pub exporter_label: String,
}
