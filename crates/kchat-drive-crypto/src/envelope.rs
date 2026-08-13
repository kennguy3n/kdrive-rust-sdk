use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::AesGcm256 as HpkeAesGcm256,
    kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
};
use rand::rngs::OsRng;
use zeroize::Zeroize;

use kchat_drive_types::{
    DomainId, DriveError, EnvelopeId, EnvelopeVariant, Hash256, KeyEnvelope, Nonce12, UserId,
    VersionId, X25519PublicKey,
};

/// Seals a VersionDEK under an HPKE recipient envelope (SetupBaseS).
/// Returns the complete KeyEnvelope with variant = Hpke.
pub fn seal_hpke_envelope(
    envelope_id: EnvelopeId,
    version_id: VersionId,
    domain_id: DomainId,
    recipient_public_key: &X25519PublicKey,
    recipient_user: UserId,
    version_dek: &[u8; 32],
    generation: Option<u64>,
) -> Result<KeyEnvelope, DriveError> {
    let recipient_pk =
        <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(recipient_public_key.as_bytes())
            .map_err(|e| DriveError::Crypto(format!("invalid HPKE public key: {}", e)))?;

    let (encapped_key, mut context) =
        setup_sender::<HpkeAesGcm256, HkdfSha256, X25519HkdfSha256, _>(
            &OpModeS::Base,
            &recipient_pk,
            crate::labels::HPKE_INFO,
            &mut OsRng,
        )
        .map_err(|e| DriveError::Crypto(format!("HPKE setup_sender: {}", e)))?;

    let aad = crate::labels::ENVELOPE_AAD;
    let ciphertext = context
        .seal(version_dek, aad)
        .map_err(|e| DriveError::Crypto(format!("HPKE seal: {}", e)))?;

    // Serialize encapped key.
    let encapped_bytes = encapped_key.to_bytes();
    let encapped_vec = encapped_bytes.to_vec();

    Ok(KeyEnvelope {
        envelope_id,
        version_id,
        domain_id,
        variant: EnvelopeVariant::Hpke,
        ciphertext,
        encapsulated_key: encapped_vec,
        nonce: None, // HPKE context manages nonce internally
        transport_salt: None,
        transport_nonce: None,
        recipient_user: Some(recipient_user),
        recipient_device_key: Some(recipient_public_key.clone()),
        user_snapshot_hash: None,
        generation,
    })
}

/// Opens an HPKE recipient envelope to recover the VersionDEK.
pub fn open_hpke_envelope(
    envelope: &KeyEnvelope,
    recipient_private_key: &[u8; 32],
) -> Result<[u8; 32], DriveError> {
    let priv_key = <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(recipient_private_key)
        .map_err(|e| DriveError::Crypto(format!("invalid HPKE private key: {}", e)))?;

    let encapped = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&envelope.encapsulated_key)
        .map_err(|e| DriveError::Crypto(format!("invalid encapped key: {}", e)))?;

    let mut context = setup_receiver::<HpkeAesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &priv_key,
        &encapped,
        crate::labels::HPKE_INFO,
    )
    .map_err(|e| DriveError::Crypto(format!("HPKE setup_receiver: {}", e)))?;

    let aad = crate::labels::ENVELOPE_AAD;
    let mut plaintext = context
        .open(&envelope.ciphertext, aad)
        .map_err(|e| DriveError::Crypto(format!("HPKE open: {}", e)))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Envelope(format!(
            "expected 32-byte key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Seals a VersionDEK under an MLS transport envelope (symmetric).
/// The transport key is derived from the MLS exporter output.
/// This function creates the envelope structure; the actual sealing
/// is done by the MLS bridge crate which has access to the exporter.
pub fn create_mls_transport_envelope(
    envelope_id: EnvelopeId,
    version_id: VersionId,
    domain_id: DomainId,
    transport_key: &[u8; 32],
    transport_nonce: &Nonce12,
    transport_salt: &[u8],
    version_dek: &[u8; 32],
    recipient_user: Option<UserId>,
    generation: Option<u64>,
) -> Result<KeyEnvelope, DriveError> {
    let cipher =
        Aes256Gcm::new_from_slice(transport_key).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(transport_nonce.as_bytes());

    let aad = crate::labels::ENVELOPE_AAD;
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: version_dek,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok(KeyEnvelope {
        envelope_id,
        version_id,
        domain_id,
        variant: EnvelopeVariant::MlsTransport,
        ciphertext,
        encapsulated_key: Vec::new(),
        nonce: None,
        transport_salt: Some(transport_salt.to_vec()),
        transport_nonce: Some(transport_nonce.clone()),
        recipient_user,
        recipient_device_key: None,
        user_snapshot_hash: None,
        generation,
    })
}

/// Opens an MLS transport envelope to recover the VersionDEK.
pub fn open_mls_transport_envelope(
    envelope: &KeyEnvelope,
    transport_key: &[u8; 32],
) -> Result<[u8; 32], DriveError> {
    let transport_nonce = envelope
        .transport_nonce
        .as_ref()
        .ok_or(DriveError::Envelope(
            "missing transport_nonce for MLS transport envelope".into(),
        ))?;

    let cipher =
        Aes256Gcm::new_from_slice(transport_key).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(transport_nonce.as_bytes());

    let aad = crate::labels::ENVELOPE_AAD;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope.ciphertext,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Envelope(format!(
            "expected 32-byte key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Creates a recovery envelope (Secured mode, demo KMS stub).
/// Uses a simple AES-256-GCM seal under a recovery key.
pub fn create_recovery_envelope(
    envelope_id: EnvelopeId,
    version_id: VersionId,
    domain_id: DomainId,
    recovery_key: &[u8; 32],
    recovery_nonce: &Nonce12,
    version_dek: &[u8; 32],
    generation: Option<u64>,
) -> Result<KeyEnvelope, DriveError> {
    let cipher =
        Aes256Gcm::new_from_slice(recovery_key).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(recovery_nonce.as_bytes());

    let aad = crate::labels::RECOVERY_AAD;
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: version_dek,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    Ok(KeyEnvelope {
        envelope_id,
        version_id,
        domain_id,
        variant: EnvelopeVariant::Recovery,
        ciphertext,
        encapsulated_key: Vec::new(),
        nonce: Some(recovery_nonce.clone()),
        transport_salt: None,
        transport_nonce: None,
        recipient_user: None,
        recipient_device_key: None,
        user_snapshot_hash: None,
        generation,
    })
}

/// Opens a recovery envelope.
pub fn open_recovery_envelope(
    envelope: &KeyEnvelope,
    recovery_key: &[u8; 32],
) -> Result<[u8; 32], DriveError> {
    let nonce = envelope.nonce.as_ref().ok_or(DriveError::Envelope(
        "missing nonce for recovery envelope".into(),
    ))?;

    let cipher =
        Aes256Gcm::new_from_slice(recovery_key).map_err(|e| DriveError::Crypto(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());

    let aad = crate::labels::RECOVERY_AAD;
    let mut plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope.ciphertext,
                aad,
            },
        )
        .map_err(|e| DriveError::Crypto(e.to_string()))?;

    if plaintext.len() != 32 {
        let len = plaintext.len();
        plaintext.zeroize();
        return Err(DriveError::Envelope(format!(
            "expected 32-byte key, got {}",
            len
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Computes the hash of an envelope (for wrap-set root computation).
pub fn envelope_hash(envelope: &KeyEnvelope) -> Result<Hash256, DriveError> {
    let mut buf = Vec::new();
    minicbor::encode(envelope, &mut buf)?;
    Ok(crate::manifest::sha256(&buf))
}
