use kchat_drive_crypto::*;
use kchat_drive_types::*;

#[test]
fn hpke_envelope_roundtrip() {
    let (priv_key, pub_key) = hpke::generate_keypair();

    let version_dek = generate_key();
    let envelope = seal_hpke_envelope(
        EnvelopeId::new([1; 16]),
        VersionId::new([2; 16]),
        DomainId::new([3; 16]),
        &hpke::make_public_key(pub_key),
        UserId::new([5; 16]),
        &version_dek,
        Some(1),
    )
    .unwrap();

    let recovered = open_hpke_envelope(&envelope, &priv_key).unwrap();
    assert_eq!(recovered, version_dek);
}

#[test]
fn hpke_wrong_key_fails() {
    let (priv_key, pub_key) = hpke::generate_keypair();
    let (_wrong_priv, _wrong_pub) = hpke::generate_keypair();

    let version_dek = generate_key();
    let envelope = seal_hpke_envelope(
        EnvelopeId::new([1; 16]),
        VersionId::new([2; 16]),
        DomainId::new([3; 16]),
        &hpke::make_public_key(pub_key),
        UserId::new([5; 16]),
        &version_dek,
        Some(1),
    )
    .unwrap();

    // Use wrong private key — but we need a different wrong key, not the same one.
    let wrong_key = [0x99u8; 32];
    let result = open_hpke_envelope(&envelope, &wrong_key);
    assert!(result.is_err());

    // Verify correct key works.
    let recovered = open_hpke_envelope(&envelope, &priv_key).unwrap();
    assert_eq!(recovered, version_dek);
}

#[test]
fn mls_transport_envelope_roundtrip() {
    let transport_key = generate_key();
    let transport_nonce = Nonce12::new([0xAB; 12]);
    let transport_salt = generate_salt();
    let version_dek = generate_key();

    let envelope = create_mls_transport_envelope(
        EnvelopeId::new([1; 16]),
        VersionId::new([2; 16]),
        DomainId::new([3; 16]),
        &transport_key,
        &transport_nonce,
        &transport_salt,
        &version_dek,
        Some(UserId::new([5; 16])),
        Some(1),
    )
    .unwrap();

    let recovered = open_mls_transport_envelope(&envelope, &transport_key).unwrap();
    assert_eq!(recovered, version_dek);
}

#[test]
fn recovery_envelope_roundtrip() {
    let recovery_key = generate_key();
    let recovery_nonce = Nonce12::new([0xCD; 12]);
    let version_dek = generate_key();

    let envelope = create_recovery_envelope(
        EnvelopeId::new([1; 16]),
        VersionId::new([2; 16]),
        DomainId::new([3; 16]),
        &recovery_key,
        &recovery_nonce,
        &version_dek,
        Some(1),
    )
    .unwrap();

    let recovered = open_recovery_envelope(&envelope, &recovery_key).unwrap();
    assert_eq!(recovered, version_dek);
}

#[test]
fn domain_key_chain_walk_backward() {
    let domain_id = DomainId::new([1; 16]);

    // Create generation 0.
    let gen0 = generate_domain_key(domain_id);

    // Rotate to generation 1.
    let gen1 = rotate_domain_key(&gen0).unwrap();

    // Walk backward from gen1 to recover gen0's key.
    let recovered_gen0_key = walk_backward(&gen1).unwrap();
    assert_eq!(recovered_gen0_key, gen0.key);

    // Rotate to generation 2.
    let gen2 = rotate_domain_key(&gen1).unwrap();
    let recovered_gen1_key = walk_backward(&gen2).unwrap();
    assert_eq!(recovered_gen1_key, gen1.key);
}

#[test]
fn domain_key_wrap_unwrap() {
    let domain_id = DomainId::new([1; 16]);
    let record = generate_domain_key(domain_id);
    let version_dek = generate_key();

    let (ct, nonce) = wrap_version_dek_under_domain_key(&record.key, &version_dek).unwrap();
    let recovered = unwrap_version_dek_from_domain_key(&record.key, &ct, &nonce).unwrap();

    assert_eq!(recovered, version_dek);
}

#[test]
fn share_grant_key_wrap_unwrap() {
    let grant_id = ShareGrantId::new([1; 16]);
    let recipients = vec![UserId::new([2; 16]), UserId::new([3; 16])];
    let snapshot_hash = Hash256::new([0xAA; 32]);
    let tree_hash = Hash256::new([0xBB; 32]);

    let record = generate_share_grant_key(grant_id, &recipients, &snapshot_hash, 1, &tree_hash);
    let version_dek = generate_key();

    let (ct, nonce) = wrap_version_dek_under_share_grant_key(&record.key, &version_dek).unwrap();
    let recovered = unwrap_version_dek_from_share_grant_key(&record.key, &ct, &nonce).unwrap();

    assert_eq!(recovered, version_dek);
}

#[test]
fn share_grant_key_rotation() {
    let grant_id = ShareGrantId::new([1; 16]);
    let recipients = vec![UserId::new([2; 16]), UserId::new([3; 16])];
    let snapshot_hash = Hash256::new([0xAA; 32]);
    let tree_hash = Hash256::new([0xBB; 32]);

    let gen0 = generate_share_grant_key(grant_id, &recipients, &snapshot_hash, 1, &tree_hash);
    let gen1 = rotate_share_grant_key(&gen0, &recipients, &snapshot_hash, 2, &tree_hash);

    assert_eq!(gen1.generation, 1);
    assert_ne!(gen0.key, gen1.key);
    assert_eq!(gen1.grant_id, gen0.grant_id);
}
