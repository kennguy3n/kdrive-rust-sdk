use openmls::group::MlsGroup;
use openmls_traits::OpenMlsProvider;
use sha2::Digest;

use kchat_drive_types::{
    DriveError, DurableKeyReceipt, EnvelopeId, Hash256, Key256, Nonce12,
};

use kchat_drive_crypto::{
    create_mls_transport_envelope, generate_salt, open_mls_transport_envelope,
};

use crate::context::{ADVANCED_PURPOSE, AdvancedTransportContext, derive_transport_key_and_nonce};

/// Seals a DomainKey under an MLS exporter-derived transport key (Advanced mode).
///
/// This function:
/// 1. Calls MlsGroup::export_secret with the Advanced domain label + context.
/// 2. Derives a transport key + nonce from the exporter output.
/// 3. Seals the DomainKey under the transport key using AES-256-GCM.
/// 4. Returns the sealed envelope (ciphertext + transport metadata).
///
/// The exporter output never crosses FFI — only the sealed envelope is returned.
pub fn seal_advanced_domain_key<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    envelope_id: EnvelopeId,
    domain_key: &Key256,
    ctx: &AdvancedTransportContext,
) -> Result<kchat_drive_types::KeyEnvelope, DriveError> {
    let label = crate::context::exporter_label(ADVANCED_PURPOSE)?;
    let context_bytes = ctx.context_bytes();

    // Call the MLS exporter.
    let exporter_output = group
        .export_secret(provider.crypto(), label, &context_bytes, 32)
        .map_err(|e| DriveError::MlsBridge(format!("export_secret: {}", e)))?;

    // Generate a random transport salt.
    let transport_salt = generate_salt();

    // Derive transport key + nonce.
    let context_hash = ctx.context_hash();
    let (transport_key, transport_nonce) = derive_transport_key_and_nonce(
        &transport_salt,
        &exporter_output,
        ADVANCED_PURPOSE,
        &context_hash,
        &envelope_id,
    );

    // Seal the DomainKey under the transport key.
    let envelope = create_mls_transport_envelope(
        envelope_id,
        // VersionId is not relevant for domain key transport; use a zero ID.
        kchat_drive_types::VersionId::new([0u8; 16]),
        ctx.domain_id.clone(),
        &transport_key,
        &Nonce12::new(transport_nonce),
        &transport_salt,
        domain_key.as_bytes(),
        None,
        Some(ctx.generation),
    )?;

    Ok(envelope)
}

/// Opens an Advanced mode domain key envelope and returns the recovered DomainKey.
///
/// This function:
/// 1. Calls MlsGroup::export_secret with the same label + context.
/// 2. Derives the transport key + nonce.
/// 3. Opens the envelope to recover the DomainKey.
/// 4. Returns the DomainKey + a DurableKeyReceipt (no key bytes in the receipt).
///
/// In production, the key is stored in the encrypted DriveKeyVault and only the
/// receipt is returned. For the demo, we return the key directly.
pub fn open_advanced_domain_key_and_store<Provider: OpenMlsProvider>(
    group: &MlsGroup,
    provider: &Provider,
    envelope: &kchat_drive_types::KeyEnvelope,
    ctx: &AdvancedTransportContext,
) -> Result<(Key256, DurableKeyReceipt), DriveError> {
    let label = crate::context::exporter_label(ADVANCED_PURPOSE)?;
    let context_bytes = ctx.context_bytes();

    // Call the MLS exporter.
    let exporter_output = group
        .export_secret(provider.crypto(), label, &context_bytes, 32)
        .map_err(|e| DriveError::MlsBridge(format!("export_secret: {}", e)))?;

    // Extract transport salt from the envelope.
    let transport_salt = envelope
        .transport_salt
        .as_ref()
        .ok_or(DriveError::Envelope("missing transport_salt".into()))?;

    // Derive transport key + nonce.
    let context_hash = ctx.context_hash();
    let (transport_key, _) = derive_transport_key_and_nonce(
        transport_salt,
        &exporter_output,
        ADVANCED_PURPOSE,
        &context_hash,
        &envelope.envelope_id,
    );

    // Open the envelope.
    let key_bytes = open_mls_transport_envelope(envelope, &transport_key)?;

    // Compute key hash for the receipt (audit only, not the key itself).
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_bytes);
    let key_hash = Hash256::from_slice(&hasher.finalize());

    let receipt = DurableKeyReceipt {
        envelope_id: envelope.envelope_id.clone(),
        domain_id: Some(ctx.domain_id.clone()),
        grant_id: None,
        generation: ctx.generation,
        mls_epoch: ctx.mls_epoch,
        key_hash,
        exporter_label: label.to_string(),
    };

    Ok((Key256::new(key_bytes), receipt))
}
