use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ed25519::signature::{Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use kchat_drive_types::{
    DriveError, Ed25519PublicKey, Ed25519Signature, Hash256, Manifest, NodeId, Nonce12,
    PublicVersionHeader, VersionId,
};

use crate::kdf::{derive_manifest_key, derive_manifest_nonce, extract_prk};

/// Encrypts a manifest with AES-256-GCM using the manifest key derived from VersionDEK.
pub fn encrypt_manifest(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    manifest: &Manifest,
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    let prk = extract_prk(version_dek);
    let key_bytes = derive_manifest_key(&prk, node_id, version_id);
    let nonce_bytes = derive_manifest_nonce(&prk, node_id, version_id);

    let mut plaintext = zeroize::Zeroizing::new(Vec::new());
    minicbor::encode(manifest, &mut *plaintext)?;

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad: &[],
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok((ct, Nonce12::new(nonce_bytes)))
}

/// Decrypts a manifest.
pub fn decrypt_manifest(
    version_dek: &[u8; 32],
    node_id: &NodeId,
    version_id: &VersionId,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<Manifest, DriveError> {
    let prk = extract_prk(version_dek);
    let key_bytes = derive_manifest_key(&prk, node_id, version_id);

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    let manifest: Manifest = minicbor::decode(&plaintext)?;
    plaintext.zeroize();
    Ok(manifest)
}

/// Signs a public version header with Ed25519.
/// The signature covers: SHA-256("kchat-drive/version-header-signature/v1" || CanonicalHeaderWithoutSignature)
pub fn sign_header(
    header: &PublicVersionHeader,
    signing_key: &SigningKey,
) -> Result<Ed25519Signature, DriveError> {
    let canonical = header.canonical_bytes_for_signature()?;
    let mut hasher = Sha256::new();
    hasher.update(crate::labels::HEADER_SIGNATURE_TAG);
    hasher.update(&canonical);
    let digest = hasher.finalize();

    let sig = signing_key.sign(&digest);
    Ok(Ed25519Signature::new(sig.to_bytes()))
}

/// Verifies a public version header signature.
pub fn verify_header(
    header: &PublicVersionHeader,
    public_key: &Ed25519PublicKey,
) -> Result<bool, DriveError> {
    let sig = header
        .signature
        .as_ref()
        .ok_or(DriveError::InvalidState("header has no signature".into()))?;

    let canonical = header.canonical_bytes_for_signature()?;
    let mut hasher = Sha256::new();
    hasher.update(crate::labels::HEADER_SIGNATURE_TAG);
    hasher.update(&canonical);
    let digest = hasher.finalize();

    let pk = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|e| DriveError::Crypto(e.to_string()))?;
    let signature = Signature::from_bytes(sig.as_bytes());

    Ok(pk.verify(&digest, &signature).is_ok())
}

/// Computes the SHA-256 of ciphertext (for manifest_ciphertext_sha256).
pub fn sha256(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Hash256::from_slice(&hasher.finalize())
}
