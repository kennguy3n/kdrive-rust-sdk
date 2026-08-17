use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use sha2::Digest;
use zeroize::Zeroize;

use kchat_drive_types::{DriveError, DurableKeyReceipt, EnvelopeId, Hash256, Key256, Nonce12};

use kchat_drive_crypto::{
    create_mls_transport_envelope, generate_salt, open_mls_transport_envelope,
};

use crate::context::{MAX_PURPOSE, MaxTransportContext, derive_transport_key_and_nonce};

/// Seals a ShareGrantKey under an MLS exporter-derived transport key (Max mode).
///
/// This function:
/// 1. Calls MlsGroup::export_secret with the Max share-grant label + context.
/// 2. Derives a transport key + nonce from the exporter output.
/// 3. Seals the ShareGrantKey under the transport key using AES-256-GCM.
/// 4. Returns the sealed envelope.
pub fn seal_max_share_grant_key<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    envelope_id: EnvelopeId,
    share_grant_key: &Key256,
    ctx: &MaxTransportContext,
) -> Result<kchat_drive_types::KeyEnvelope, DriveError> {
    let label = crate::context::exporter_label(MAX_PURPOSE)?;
    let context_bytes = ctx.context_bytes();

    // Call the MLS exporter.
    let exporter_output = zeroize::Zeroizing::new(
        group
            .export_secret(provider.crypto(), label, context_bytes, 32)
            .map_err(|e| DriveError::MlsBridge(format!("export_secret: {}", e)))?,
    );

    // Generate a random transport salt.
    let transport_salt = generate_salt();

    // Derive transport key + nonce.
    let context_hash = ctx.context_hash();
    let (mut transport_key, mut transport_nonce) = derive_transport_key_and_nonce(
        &transport_salt,
        &exporter_output,
        MAX_PURPOSE,
        &context_hash,
        &envelope_id,
    )?;

    // Seal the ShareGrantKey under the transport key.
    let envelope = create_mls_transport_envelope(
        envelope_id,
        kchat_drive_types::VersionId::new([0u8; 16]),
        kchat_drive_types::DomainId::new([0u8; 16]),
        &transport_key,
        &Nonce12::new(transport_nonce),
        &transport_salt,
        share_grant_key.as_bytes(),
        None,
        Some(ctx.generation),
    )?;

    transport_key.zeroize();
    transport_nonce.zeroize();

    Ok(envelope)
}

/// Opens a Max mode share grant key envelope and returns the recovered ShareGrantKey.
///
/// This function:
/// 1. Calls MlsGroup::export_secret with the same label + context.
/// 2. Derives the transport key + nonce.
/// 3. Opens the envelope to recover the ShareGrantKey.
/// 4. Returns the ShareGrantKey + a DurableKeyReceipt.
pub fn open_max_share_grant_key_and_store<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    envelope: &kchat_drive_types::KeyEnvelope,
    ctx: &MaxTransportContext,
) -> Result<(Key256, DurableKeyReceipt), DriveError> {
    let label = crate::context::exporter_label(MAX_PURPOSE)?;
    let context_bytes = ctx.context_bytes();

    // Call the MLS exporter.
    let exporter_output = zeroize::Zeroizing::new(
        group
            .export_secret(provider.crypto(), label, context_bytes, 32)
            .map_err(|e| DriveError::MlsBridge(format!("export_secret: {}", e)))?,
    );

    // Extract transport salt from the envelope.
    let transport_salt = envelope
        .transport_salt
        .as_ref()
        .ok_or(DriveError::Envelope("missing transport_salt".into()))?;

    // Derive transport key + nonce.
    let context_hash = ctx.context_hash();
    let (mut transport_key, mut transport_nonce) = derive_transport_key_and_nonce(
        transport_salt,
        &exporter_output,
        MAX_PURPOSE,
        &context_hash,
        &envelope.envelope_id,
    )?;

    // Open the envelope.
    let key_bytes = open_mls_transport_envelope(envelope, &transport_key)?;

    // Compute key hash for the receipt.
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_bytes);
    let key_hash = Hash256::from_slice(&hasher.finalize());

    let receipt = DurableKeyReceipt {
        envelope_id: envelope.envelope_id.clone(),
        domain_id: None,
        grant_id: Some(ctx.grant_id.clone()),
        generation: ctx.generation,
        mls_epoch: ctx.mls_epoch,
        key_hash,
        exporter_label: label.to_string(),
    };

    transport_key.zeroize();
    transport_nonce.zeroize();

    // Key256 has ZeroizeOnDrop, so key_bytes are zeroized when the Key256 is dropped.
    Ok((Key256::new(key_bytes), receipt))
}
