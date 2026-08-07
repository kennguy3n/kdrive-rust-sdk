use ed25519_dalek::SigningKey;
use kchat_drive_crypto::*;
use kchat_drive_types::*;

#[test]
fn manifest_encrypt_decrypt_roundtrip() {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([1; 16]);
    let version_id = VersionId::new([2; 16]);

    let manifest = Manifest {
        version_id: version_id.clone(),
        node_id: node_id.clone(),
        chunk_plan: ChunkPlan {
            chunks: vec![ChunkDescriptor {
                index: 0,
                plaintext_len: 100,
                ciphertext_len: 116,
                ciphertext_sha256: Hash256::new([0xAA; 32]),
                blob_key: "blob_001".to_string(),
            }],
        },
        name_ciphertext: vec![0xBB; 32],
        mime_type: Some("text/plain".to_string()),
        plaintext_size: 100,
        created_at: 1700000000,
        parent_version_id: None,
    };

    let (ct, nonce) = encrypt_manifest(&version_dek, &node_id, &version_id, &manifest).unwrap();
    let decrypted = decrypt_manifest(&version_dek, &node_id, &version_id, &ct, &nonce).unwrap();

    assert_eq!(manifest, decrypted);
}

#[test]
fn header_sign_and_verify() {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let header = PublicVersionHeader {
        protocol: 1,
        suite: 1,
        drive_id: DriveId::new([1; 16]),
        node_id: NodeId::new([2; 16]),
        version_id: VersionId::new([3; 16]),
        domain_id: DomainId::new([4; 16]),
        privacy_mode: PrivacyMode::Advanced,
        plaintext_size: 1024,
        chunk_size: 4 * 1024 * 1024,
        chunk_count: 1,
        chunk_plan_root: Hash256::new([0xaa; 32]),
        manifest_ciphertext_sha256: Hash256::new([0xbb; 32]),
        manifest_ciphertext_len: 512,
        manifest_nonce: Nonce12::new([0xcc; 12]),
        access_context_revision: 1,
        access_context_snapshot_hash: Hash256::new([0xdd; 32]),
        creator_device_key: Ed25519PublicKey::new(verifying_key.to_bytes()),
        created_at: 1700000000,
        signature: None,
    };

    let sig = sign_header(&header, &signing_key).unwrap();
    let mut signed_header = header.clone();
    signed_header.signature = Some(sig);

    assert!(
        verify_header(
            &signed_header,
            &Ed25519PublicKey::new(verifying_key.to_bytes())
        )
        .unwrap()
    );
}

#[test]
fn header_tampered_signature_fails() {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();

    let mut header = PublicVersionHeader {
        protocol: 1,
        suite: 1,
        drive_id: DriveId::new([1; 16]),
        node_id: NodeId::new([2; 16]),
        version_id: VersionId::new([3; 16]),
        domain_id: DomainId::new([4; 16]),
        privacy_mode: PrivacyMode::Advanced,
        plaintext_size: 1024,
        chunk_size: 4 * 1024 * 1024,
        chunk_count: 1,
        chunk_plan_root: Hash256::new([0xaa; 32]),
        manifest_ciphertext_sha256: Hash256::new([0xbb; 32]),
        manifest_ciphertext_len: 512,
        manifest_nonce: Nonce12::new([0xcc; 12]),
        access_context_revision: 1,
        access_context_snapshot_hash: Hash256::new([0xdd; 32]),
        creator_device_key: Ed25519PublicKey::new(verifying_key.to_bytes()),
        created_at: 1700000000,
        signature: None,
    };

    let sig = sign_header(&header, &signing_key).unwrap();
    header.signature = Some(sig);

    // Tamper with a field.
    header.plaintext_size = 2048;

    assert!(!verify_header(&header, &Ed25519PublicKey::new(verifying_key.to_bytes())).unwrap());
}
