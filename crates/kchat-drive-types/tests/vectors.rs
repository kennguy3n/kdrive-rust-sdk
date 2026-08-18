use kchat_drive_types::*;

#[test]
fn opaque_id_hex_roundtrip() {
    let id = OpaqueId::new([0xab; 16]);
    let hex = id.to_hex();
    let id2 = OpaqueId::from_hex(&hex).unwrap();
    assert_eq!(id, id2);
}

#[test]
fn opaque_id_random_is_unique() {
    let a = OpaqueId::random();
    let b = OpaqueId::random();
    assert_ne!(a, b);
}

#[test]
fn privacy_mode_roundtrip() {
    for mode in [
        PrivacyMode::Secured,
        PrivacyMode::Advanced,
        PrivacyMode::Max,
    ] {
        let v = mode.as_u8();
        let mode2 = PrivacyMode::from_u8(v).unwrap();
        assert_eq!(mode, mode2);
    }
}

#[test]
fn cbor_header_roundtrip() {
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
        creator_device_key: Ed25519PublicKey::new([0xee; 32]),
        created_at: 1700000000,
        signature: None,
        content_id: None,
    };

    let mut buf = Vec::new();
    minicbor::encode(&header, &mut buf).unwrap();
    let decoded: PublicVersionHeader = minicbor::decode(&buf).unwrap();
    assert_eq!(header, decoded);
}

#[test]
fn cbor_envelope_roundtrip() {
    let env = KeyEnvelope {
        envelope_id: EnvelopeId::new([1; 16]),
        version_id: VersionId::new([2; 16]),
        domain_id: DomainId::new([3; 16]),
        variant: EnvelopeVariant::Hpke,
        ciphertext: vec![0xAB; 48],
        encapsulated_key: vec![0xCD; 32],
        nonce: Some(Nonce12::new([0xEF; 12])),
        transport_salt: None,
        transport_nonce: None,
        recipient_user: Some(UserId::new([5; 16])),
        recipient_device_key: Some(X25519PublicKey::new([6; 32])),
        user_snapshot_hash: None,
        generation: Some(1),
    };

    let mut buf = Vec::new();
    minicbor::encode(&env, &mut buf).unwrap();
    let decoded: KeyEnvelope = minicbor::decode(&buf).unwrap();
    assert_eq!(env, decoded);
}

#[test]
fn cbor_manifest_roundtrip() {
    let manifest = Manifest {
        version_id: VersionId::new([1; 16]),
        node_id: NodeId::new([2; 16]),
        chunk_plan: ChunkPlan {
            chunks: vec![ChunkDescriptor {
                index: 0,
                plaintext_len: 1024,
                ciphertext_len: 1040,
                ciphertext_sha256: Hash256::new([0xAA; 32]),
                blob_key: "blob_001".to_string(), plaintext_sha256: None,
            }],
        },
        name_ciphertext: vec![0xBB; 32],
        mime_type: Some("text/plain".to_string()),
        plaintext_size: 1024,
        created_at: 1700000000,
        parent_version_id: None,
        content_id: None,
        wrapped_content_key: None,
        content_wrap_nonce: None,
    };

    let mut buf = Vec::new();
    minicbor::encode(&manifest, &mut buf).unwrap();
    let decoded: Manifest = minicbor::decode(&buf).unwrap();
    assert_eq!(manifest, decoded);
}

#[test]
fn wrap_set_root_deterministic() {
    let hashes = vec![
        Hash256::new([3; 32]),
        Hash256::new([1; 32]),
        Hash256::new([2; 32]),
    ];
    let root1 = WrapSetRoot::compute(&hashes);
    let root2 = WrapSetRoot::compute(&hashes);
    assert_eq!(root1, root2);
    assert_eq!(root1.count, 3);
}

#[test]
fn wrap_set_root_order_independent() {
    let h1 = vec![
        Hash256::new([3; 32]),
        Hash256::new([1; 32]),
        Hash256::new([2; 32]),
    ];
    let h2 = vec![
        Hash256::new([1; 32]),
        Hash256::new([2; 32]),
        Hash256::new([3; 32]),
    ];
    let r1 = WrapSetRoot::compute(&h1);
    let r2 = WrapSetRoot::compute(&h2);
    assert_eq!(r1.root, r2.root);
}

#[test]
fn chunk_plan_merkle_root_single_chunk() {
    let plan = ChunkPlan {
        chunks: vec![ChunkDescriptor {
            index: 0,
            plaintext_len: 1024,
            ciphertext_len: 1040,
            ciphertext_sha256: Hash256::new([0xAA; 32]),
            blob_key: "blob_001".to_string(), plaintext_sha256: None,
        }],
    };
    let root = plan.merkle_root();
    // Single leaf: root = leaf hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"kchat-drive/chunk-plan-leaf/v1");
    hasher.update(0u64.to_be_bytes());
    hasher.update(1024u64.to_be_bytes());
    hasher.update([0xAA; 32]);
    let expected = hasher.finalize();
    assert_eq!(root.as_bytes(), expected.as_slice());
}

#[test]
fn domain_key_record_roundtrip() {
    let record = DomainKeyRecord {
        domain_id: DomainId::new([1; 16]),
        generation: 5,
        key: Key256::new([0xAB; 32]),
        prev_envelope: Some(vec![0xCD; 48]),
        prev_envelope_nonce: Some(Nonce12::new([0xEF; 12])),
        is_checkpoint: false,
    };
    let mut buf = Vec::new();
    minicbor::encode(&record, &mut buf).unwrap();
    let decoded: DomainKeyRecord = minicbor::decode(&buf).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn share_grant_key_record_roundtrip() {
    let record = ShareGrantKeyRecord {
        grant_id: ShareGrantId::new([1; 16]),
        generation: 2,
        key: Key256::new([0xAB; 32]),
        recipient_user_set_root: Hash256::new([0xCD; 32]),
        user_snapshot_hash: Hash256::new([0xEF; 32]),
        mls_epoch: 10,
        mls_tree_hash: Hash256::new([0x12; 32]),
    };
    let mut buf = Vec::new();
    minicbor::encode(&record, &mut buf).unwrap();
    let decoded: ShareGrantKeyRecord = minicbor::decode(&buf).unwrap();
    assert_eq!(record, decoded);
}

#[test]
fn durable_key_receipt_roundtrip() {
    let receipt = DurableKeyReceipt {
        envelope_id: EnvelopeId::new([1; 16]),
        domain_id: Some(DomainId::new([2; 16])),
        grant_id: None,
        generation: 3,
        mls_epoch: 5,
        key_hash: Hash256::new([0xAA; 32]),
        exporter_label: "org.kchat.drive.advanced-domain-transport.v1".to_string(),
    };
    let mut buf = Vec::new();
    minicbor::encode(&receipt, &mut buf).unwrap();
    let decoded: DurableKeyReceipt = minicbor::decode(&buf).unwrap();
    assert_eq!(receipt, decoded);
}
