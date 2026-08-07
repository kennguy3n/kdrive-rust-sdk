use ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use minicbor::{Decode, Encode};
use sha2::{Digest, Sha256};

use kchat_drive_types::{DeviceId, DriveError, Ed25519PublicKey, Ed25519Signature, UserId};

/// Account authority record: binds a user to their authorized device set.
/// Signed by the account's root key (which is generated at enrollment).
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct AccountAuthorityRecord {
    /// User ID this account belongs to.
    #[n(0)]
    pub user_id: UserId,

    /// Account root public key (Ed25519).
    #[n(1)]
    pub root_public_key: Ed25519PublicKey,

    /// Authorized device set (public keys).
    #[n(2)]
    pub devices: Vec<DeviceCertificate>,

    /// Creation timestamp.
    #[n(3)]
    pub created_at: u64,

    /// Last updated timestamp.
    #[n(4)]
    pub updated_at: u64,

    /// Account root signature over the canonical record (excluding this field).
    #[n(5)]
    pub signature: Option<Ed25519Signature>,
}

impl AccountAuthorityRecord {
    /// Returns the canonical bytes that are signed.
    pub fn canonical_bytes_for_signature(&self) -> Result<Vec<u8>, DriveError> {
        let mut clone = self.clone();
        clone.signature = None;
        let mut buf = zeroize::Zeroizing::new(Vec::new());
        minicbor::encode(&clone, &mut *buf)?;
        Ok(buf.to_vec())
    }

    /// Signs the record with the account root signing key.
    pub fn sign(&mut self, signing_key: &SigningKey) -> Result<(), DriveError> {
        let canonical = self.canonical_bytes_for_signature()?;
        let mut hasher = Sha256::new();
        hasher.update(b"kchat-drive/account-authority/v1");
        hasher.update(&canonical);
        let digest = hasher.finalize();
        let sig = signing_key.sign(&digest);
        self.signature = Some(Ed25519Signature::new(sig.to_bytes()));
        Ok(())
    }

    /// Verifies the account authority signature.
    pub fn verify(&self) -> Result<bool, DriveError> {
        let sig = self
            .signature
            .as_ref()
            .ok_or(DriveError::InvalidState("no signature".into()))?;
        let canonical = self.canonical_bytes_for_signature()?;
        let mut hasher = Sha256::new();
        hasher.update(b"kchat-drive/account-authority/v1");
        hasher.update(&canonical);
        let digest = hasher.finalize();

        let pk = VerifyingKey::from_bytes(self.root_public_key.as_bytes())
            .map_err(|e| DriveError::Crypto(e.to_string()))?;
        let signature = Signature::from_bytes(sig.as_bytes());
        Ok(pk.verify(&digest, &signature).is_ok())
    }
}

/// Device certificate: binds a device ID to a device public key.
/// Signed by the account root key.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct DeviceCertificate {
    /// Device ID.
    #[n(0)]
    pub device_id: DeviceId,

    /// Device Ed25519 public key.
    #[n(1)]
    pub device_public_key: Ed25519PublicKey,

    /// Device human-readable name (optional).
    #[n(2)]
    pub device_name: Option<String>,

    /// Enrollment timestamp.
    #[n(3)]
    pub enrolled_at: u64,

    /// Whether this device is currently active.
    #[n(4)]
    pub active: bool,
}
