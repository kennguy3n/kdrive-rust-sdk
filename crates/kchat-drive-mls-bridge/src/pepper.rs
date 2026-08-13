use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use kchat_drive_types::{DriveError, EnvelopeId, Hash256, Nonce12};
use zeroize::Zeroize;

use crate::context::{AdvancedTransportContext, derive_transport_key_and_nonce};

/// MLS exporter label for tenant pepper transport (cross-mode dedup).
pub const PEPPER_TRANSPORT_LABEL: &str = "org.kchat.drive.pepper-transport.v1";

/// Purpose string for pepper transport key derivation.
pub const PEPPER_PURPOSE: &str = "tenant-pepper";

/// Seals a tenant pepper using an MLS exporter-derived transport key.
///
/// This is used to distribute the tenant pepper to MLS group members so
/// that all members can compute the same content_id for the same plaintext,
/// enabling cross-mode dedup (Secured/Advanced/Max all use the same pepper).
///
/// The pepper is sealed with AES-256-GCM using a key derived from:
///   HKDF(MLS_exporter(PEPPER_TRANSPORT_LABEL), context_hash, envelope_id)
///
/// All group members who can call MLS export_secret with the same label
/// and context can derive the same transport key and unwrap the pepper.
pub fn seal_pepper_via_mls(
    mls_exporter_output: &[u8],
    transport_salt: &[u8],
    context: &AdvancedTransportContext,
    envelope_id: &EnvelopeId,
    pepper: &[u8; 32],
) -> Result<(Vec<u8>, Nonce12), DriveError> {
    let (mut key_bytes, mut nonce_bytes) = derive_transport_key_and_nonce(
        transport_salt,
        mls_exporter_output,
        PEPPER_PURPOSE,
        &context.context_hash(),
        envelope_id,
    );

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // AAD binds the seal to the MLS context (domain_id, generation, epoch, tree_hash)
    let aad = context.context_bytes();

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: pepper,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    key_bytes.zeroize();
    let nonce_out = Nonce12::new(nonce_bytes);
    nonce_bytes.zeroize();

    Ok((ct, nonce_out))
}

/// Opens a tenant pepper sealed via MLS exporter.
///
/// The recipient must be a member of the same MLS group at the same epoch
/// to derive the same transport key.
pub fn open_pepper_via_mls(
    mls_exporter_output: &[u8],
    transport_salt: &[u8],
    context: &AdvancedTransportContext,
    envelope_id: &EnvelopeId,
    ciphertext: &[u8],
    nonce: &Nonce12,
) -> Result<[u8; 32], DriveError> {
    let (mut key_bytes, mut nonce_bytes) = derive_transport_key_and_nonce(
        transport_salt,
        mls_exporter_output,
        PEPPER_PURPOSE,
        &context.context_hash(),
        envelope_id,
    );

    let cipher =
        Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = context.context_bytes();

    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    key_bytes.zeroize();
    nonce_bytes.zeroize();

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Crypto(format!(
            "expected 32-byte pepper, got {}",
            len
        )));
    }

    let mut pepper = [0u8; 32];
    pepper.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(pepper)
}

/// Computes a pepper envelope receipt hash for audit purposes.
/// This does NOT reveal the pepper itself.
pub fn pepper_envelope_hash(
    context: &AdvancedTransportContext,
    envelope_id: &EnvelopeId,
    ciphertext: &[u8],
) -> Hash256 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kchat-drive/pepper-envelope/v1");
    hasher.update(context.context_bytes());
    hasher.update(envelope_id.as_bytes());
    hasher.update(ciphertext);
    Hash256::from_slice(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kchat_drive_types::{DomainId, EnvelopeId, Hash256};

    #[test]
    fn pepper_seal_open_roundtrip() {
        let domain_id = DomainId::new([1; 16]);
        let context = AdvancedTransportContext {
            domain_id,
            generation: 1,
            mls_epoch: 5,
            mls_tree_hash: Hash256::new([0xAA; 32]),
        };
        let envelope_id = EnvelopeId::new([2; 16]);
        let pepper = [0xBB; 32];
        let mls_output = [0xCC; 64];
        let salt = [0xDD; 32];

        let (ct, nonce) =
            seal_pepper_via_mls(&mls_output, &salt, &context, &envelope_id, &pepper).unwrap();
        let opened =
            open_pepper_via_mls(&mls_output, &salt, &context, &envelope_id, &ct, &nonce).unwrap();

        assert_eq!(opened, pepper, "opened pepper matches original");
    }

    #[test]
    fn pepper_seal_wrong_mls_output_fails() {
        let domain_id = DomainId::new([1; 16]);
        let context = AdvancedTransportContext {
            domain_id,
            generation: 1,
            mls_epoch: 5,
            mls_tree_hash: Hash256::new([0xAA; 32]),
        };
        let envelope_id = EnvelopeId::new([2; 16]);
        let pepper = [0xBB; 32];
        let mls_output = [0xCC; 64];
        let wrong_output = [0xEE; 64];
        let salt = [0xDD; 32];

        let (ct, nonce) =
            seal_pepper_via_mls(&mls_output, &salt, &context, &envelope_id, &pepper).unwrap();
        let result = open_pepper_via_mls(&wrong_output, &salt, &context, &envelope_id, &ct, &nonce);

        assert!(result.is_err(), "wrong MLS output should fail to open");
    }

    #[test]
    fn pepper_seal_wrong_epoch_fails() {
        let domain_id = DomainId::new([1; 16]);
        let context1 = AdvancedTransportContext {
            domain_id: domain_id.clone(),
            generation: 1,
            mls_epoch: 5,
            mls_tree_hash: Hash256::new([0xAA; 32]),
        };
        let context2 = AdvancedTransportContext {
            domain_id,
            generation: 1,
            mls_epoch: 6, // different epoch
            mls_tree_hash: Hash256::new([0xAA; 32]),
        };
        let envelope_id = EnvelopeId::new([2; 16]);
        let pepper = [0xBB; 32];
        let mls_output = [0xCC; 64];
        let salt = [0xDD; 32];

        let (ct, nonce) =
            seal_pepper_via_mls(&mls_output, &salt, &context1, &envelope_id, &pepper).unwrap();
        let result = open_pepper_via_mls(&mls_output, &salt, &context2, &envelope_id, &ct, &nonce);

        assert!(result.is_err(), "wrong epoch should fail to open");
    }

    #[test]
    fn pepper_envelope_hash_is_deterministic() {
        let context = AdvancedTransportContext {
            domain_id: DomainId::new([1; 16]),
            generation: 1,
            mls_epoch: 5,
            mls_tree_hash: Hash256::new([0xAA; 32]),
        };
        let envelope_id = EnvelopeId::new([2; 16]);
        let ct = vec![0xFF; 48];

        let h1 = pepper_envelope_hash(&context, &envelope_id, &ct);
        let h2 = pepper_envelope_hash(&context, &envelope_id, &ct);

        assert_eq!(h1, h2, "envelope hash is deterministic");
    }
}
