use minicbor::{Decode, Encode};

/// 16-byte opaque identifier used for drives, nodes, versions, domains, etc.
/// Carries no tenant/user/folder identifiers (architecture invariant 14).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct OpaqueId(#[n(0)] pub [u8; 16]);

impl OpaqueId {
    pub fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, super::DriveError> {
        let bytes = hex::decode(s).map_err(|e| super::DriveError::InvalidId(e.to_string()))?;
        if bytes.len() != 16 {
            return Err(super::DriveError::InvalidId("expected 16 bytes".into()));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn random() -> Self {
        use rand::RngCore;
        let mut arr = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut arr);
        Self(arr)
    }
}

impl std::fmt::Display for OpaqueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::str::FromStr for OpaqueId {
    type Err = super::DriveError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// Type aliases for domain-specific IDs.
pub type DriveId = OpaqueId;
pub type NodeId = OpaqueId;
pub type VersionId = OpaqueId;
pub type DomainId = OpaqueId;
pub type ShareGrantId = OpaqueId;
pub type EnvelopeId = OpaqueId;
pub type UserId = OpaqueId;
pub type DeviceId = OpaqueId;
pub type TenantId = OpaqueId;

/// 32-byte hash output (SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Hash256(#[n(0)] pub [u8; 32]);

impl Hash256 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_slice(s: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = s.len().min(32);
        arr[..len].copy_from_slice(&s[..len]);
        Self(arr)
    }

    pub fn try_from_slice(s: &[u8]) -> Result<Self, super::DriveError> {
        if s.len() != 32 {
            return Err(super::DriveError::InvalidId(format!(
                "expected 32 bytes, got {}",
                s.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// 32-byte symmetric key material.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Key256(#[n(0)] pub [u8; 32]);

impl Key256 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_slice(s: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = s.len().min(32);
        arr[..len].copy_from_slice(&s[..len]);
        Self(arr)
    }

    pub fn try_from_slice(s: &[u8]) -> Result<Self, super::DriveError> {
        if s.len() != 32 {
            return Err(super::DriveError::InvalidId(format!(
                "expected 32 bytes, got {}",
                s.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(s);
        Ok(Self(arr))
    }
}

/// 12-byte AEAD nonce.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Nonce12(#[n(0)] pub [u8; 12]);

impl Nonce12 {
    pub fn new(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    pub fn from_slice(s: &[u8]) -> Self {
        let mut arr = [0u8; 12];
        let len = s.len().min(12);
        arr[..len].copy_from_slice(&s[..len]);
        Self(arr)
    }

    pub fn try_from_slice(s: &[u8]) -> Result<Self, super::DriveError> {
        if s.len() != 12 {
            return Err(super::DriveError::InvalidId(format!(
                "expected 12 bytes, got {}",
                s.len()
            )));
        }
        let mut arr = [0u8; 12];
        arr.copy_from_slice(s);
        Ok(Self(arr))
    }
}

/// 32-byte Ed25519 public key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct Ed25519PublicKey(#[n(0)] pub [u8; 32]);

impl Ed25519PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// 64-byte Ed25519 signature.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct Ed25519Signature(#[n(0)] pub [u8; 64]);

impl Ed25519Signature {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// 32-byte X25519 public key (for HPKE).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Encode, Decode)]
pub struct X25519PublicKey(#[n(0)] pub [u8; 32]);

impl X25519PublicKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
