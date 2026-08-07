use crate::ids::*;
use minicbor::{Decode, Encode};

/// Key envelope variant (architecture §9.4).
/// Label 1–50 for HPKE; labels 13–17 null + label 18 nonce for MLS transport.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct KeyEnvelope {
    /// Envelope ID (unique per envelope).
    #[n(0)]
    pub envelope_id: EnvelopeId,

    /// Version ID this envelope wraps the key for.
    #[n(1)]
    pub version_id: VersionId,

    /// Domain ID (for Secured/Advanced) or zero for Max.
    #[n(2)]
    pub domain_id: DomainId,

    /// Envelope variant.
    #[n(3)]
    pub variant: EnvelopeVariant,

    /// Wrapped key ciphertext.
    #[n(4)]
    pub ciphertext: Vec<u8>,

    /// HPKE encapsulated key (for HPKE variant, empty for MLS transport).
    #[n(5)]
    pub encapsulated_key: Vec<u8>,

    /// Nonce for the HPKE AEAD (12 bytes, for HPKE variant).
    #[n(6)]
    pub nonce: Option<Nonce12>,

    /// MLS transport salt (label 32, for MLS transport variant).
    #[n(7)]
    pub transport_salt: Option<Vec<u8>>,

    /// MLS transport nonce (label 18, for MLS transport variant).
    #[n(8)]
    pub transport_nonce: Option<Nonce12>,

    /// Recipient user principal (for per-user wrapping).
    #[n(9)]
    pub recipient_user: Option<UserId>,

    /// Recipient device public key (for HPKE to specific device).
    #[n(10)]
    pub recipient_device_key: Option<X25519PublicKey>,

    /// User snapshot hash (for Max mode — immutable recipient set proof).
    #[n(11)]
    pub user_snapshot_hash: Option<Hash256>,

    /// Domain key generation (for Secured/Advanced backward chain).
    #[n(12)]
    pub generation: Option<u64>,
}

/// Envelope delivery variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum EnvelopeVariant {
    /// HPKE SetupBaseS to a specific device's X25519 public key.
    #[n(1)]
    Hpke,
    /// MLS exporter-derived transport key (symmetric).
    #[n(2)]
    MlsTransport,
    /// Tenant recovery envelope (Secured mode only, demo KMS stub).
    #[n(3)]
    Recovery,
}

/// Initial wrap-set root: SHA-256 over sorted wrap hashes.
/// Computed as: SHA-256("kchat-drive/wrap-set-root/v1" || sorted_hash_0 || ... || sorted_hash_n)
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct WrapSetRoot {
    /// SHA-256 of the sorted concatenation of all envelope hashes.
    #[n(0)]
    pub root: Hash256,

    /// Number of envelopes in the wrap set.
    #[n(1)]
    pub count: u64,
}

impl WrapSetRoot {
    /// Computes the wrap-set root from a list of envelope hashes.
    /// Hashes are sorted lexicographically before hashing.
    pub fn compute(envelope_hashes: &[Hash256]) -> Self {
        use sha2::{Digest, Sha256};
        let mut sorted: Vec<&[u8; 32]> = envelope_hashes.iter().map(|h| h.as_bytes()).collect();
        sorted.sort();
        let mut hasher = Sha256::new();
        hasher.update(b"kchat-drive/wrap-set-root/v1");
        for h in &sorted {
            hasher.update(*h);
        }
        let result = hasher.finalize();
        Self {
            root: Hash256::from_slice(&result),
            count: envelope_hashes.len() as u64,
        }
    }
}

/// Recipient user set root: SHA-256 over sorted recipient user principals
/// + immutable user_snapshot_hash (for Max mode).
pub fn recipient_user_set_root(recipients: &[UserId], snapshot_hash: &Hash256) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&[u8; 16]> = recipients.iter().map(|r| r.as_bytes()).collect();
    sorted.sort();
    let mut hasher = Sha256::new();
    hasher.update(b"kchat-drive/recipient-user-set-root/v1");
    for r in &sorted {
        hasher.update(*r);
    }
    hasher.update(snapshot_hash.as_bytes());
    let result = hasher.finalize();
    Hash256::from_slice(&result)
}
