use kchat_drive_crypto::*;
use kchat_drive_types::*;

#[test]
fn content_id_is_deterministic() {
    let plaintext = b"Hello, KChat Drive dedup!";
    let pepper = [0xAA; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let id1 = compute_content_id(&pt_hash, &pepper);
    let id2 = compute_content_id(&pt_hash, &pepper);

    assert_eq!(id1, id2, "same plaintext + same pepper → same content_id");
}

#[test]
fn content_id_differs_across_tenants() {
    let plaintext = b"same content, different tenant";
    let pepper_a = [0xAA; 32];
    let pepper_b = [0xBB; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let id_a = compute_content_id(&pt_hash, &pepper_a);
    let id_b = compute_content_id(&pt_hash, &pepper_b);

    assert_ne!(id_a, id_b, "different peppers → different content_ids");
}

#[test]
fn content_key_is_deterministic() {
    let plaintext = b"dedup test content";
    let pepper = [0xCC; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let key1 = derive_content_key(&pt_hash, &pepper);
    let key2 = derive_content_key(&pt_hash, &pepper);

    assert_eq!(key1, key2, "same plaintext + same pepper → same ContentKey");
}

#[test]
fn content_chunk_encrypt_decrypt_roundtrip() {
    let plaintext = b"chunk dedup test data";
    let pepper = [0xDD; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let content_id = compute_content_id(&pt_hash, &pepper);
    let content_key = derive_content_key(&pt_hash, &pepper);

    let ct = encrypt_content_chunk(&content_key, &content_id, 0, plaintext).unwrap();
    let pt = decrypt_content_chunk(&content_key, &content_id, 0, &ct).unwrap();

    assert_eq!(pt, plaintext);
}

#[test]
fn content_chunk_ciphertext_is_deterministic() {
    let plaintext = b"deterministic ciphertext test";
    let pepper = [0xEE; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let content_id = compute_content_id(&pt_hash, &pepper);
    let content_key = derive_content_key(&pt_hash, &pepper);

    let ct1 = encrypt_content_chunk(&content_key, &content_id, 0, plaintext).unwrap();
    let ct2 = encrypt_content_chunk(&content_key, &content_id, 0, plaintext).unwrap();

    assert_eq!(ct1, ct2, "same content → same ciphertext (deterministic)");
}

#[test]
fn content_file_encrypt_decrypt_roundtrip() {
    let plaintext = b"Full file dedup test - this content should round-trip correctly.".to_vec();
    let pepper = [0xFF; 32];

    let (chunk_plan, ciphertexts, content_id, content_key) =
        encrypt_content_file(&plaintext, &pepper).unwrap();

    let decrypted =
        decrypt_content_file(&content_key, &content_id, &chunk_plan, &ciphertexts, &pepper).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn content_file_dedup_produces_same_ciphertext() {
    let plaintext = b"Same content uploaded twice should produce identical ciphertext".to_vec();
    let pepper = [0x11; 32];

    let (plan1, ct1, id1, _key1) = encrypt_content_file(&plaintext, &pepper).unwrap();
    let (plan2, ct2, id2, _key2) = encrypt_content_file(&plaintext, &pepper).unwrap();

    assert_eq!(id1, id2, "content_id matches");
    assert_eq!(ct1, ct2, "ciphertexts match (dedup eligible)");
    assert_eq!(
        plan1.chunks.len(),
        plan2.chunks.len(),
        "chunk count matches"
    );
    for (c1, c2) in plan1.chunks.iter().zip(plan2.chunks.iter()) {
        assert_eq!(
            c1.blob_key, c2.blob_key,
            "blob keys match (content-addressed)"
        );
    }
}

#[test]
fn content_blob_key_is_content_addressed() {
    let plaintext = b"content-addressed blob key test";
    let pepper = [0x22; 32];

    let pt_hash = plaintext_sha256(plaintext);
    let content_id = compute_content_id(&pt_hash, &pepper);
    let content_key = derive_content_key(&pt_hash, &pepper);

    let ct = encrypt_content_chunk(&content_key, &content_id, 0, plaintext).unwrap();
    let ct_hash = ciphertext_sha256(&ct);
    let blob_key = content_blob_key(&content_id, &ct_hash);

    assert!(
        blob_key.starts_with("blob_"),
        "blob key starts with blob_ prefix"
    );
    assert!(
        blob_key.contains(&content_id.to_hex()),
        "blob key contains content_id"
    );
    assert!(
        blob_key.contains(&ct_hash.to_hex()),
        "blob key contains ciphertext hash"
    );
}

#[test]
fn content_key_wrap_unwrap_roundtrip() {
    let plaintext = b"wrap test";
    let pepper = [0x33; 32];
    let version_dek = generate_key();
    let version_id = VersionId::random();

    let pt_hash = plaintext_sha256(plaintext);
    let content_id = compute_content_id(&pt_hash, &pepper);
    let content_key = derive_content_key(&pt_hash, &pepper);

    let (wrapped, nonce) =
        wrap_content_key(&version_dek, &version_id, &content_id, &content_key).unwrap();
    let unwrapped =
        unwrap_content_key(&version_dek, &version_id, &content_id, &wrapped, &nonce).unwrap();

    assert_eq!(
        unwrapped, content_key,
        "unwrapped ContentKey matches original"
    );
}

#[test]
fn content_key_wrap_wrong_dek_fails() {
    let pepper = [0x44; 32];
    let version_dek = generate_key();
    let wrong_dek = generate_key();
    let version_id = VersionId::random();

    let pt_hash = plaintext_sha256(b"test");
    let content_id = compute_content_id(&pt_hash, &pepper);
    let content_key = derive_content_key(&pt_hash, &pepper);

    let (wrapped, nonce) =
        wrap_content_key(&version_dek, &version_id, &content_id, &content_key).unwrap();
    let result = unwrap_content_key(&wrong_dek, &version_id, &content_id, &wrapped, &nonce);

    assert!(result.is_err(), "wrong VersionDEK should fail to unwrap");
}

#[test]
fn pepper_wrap_unwrap_domain_key_roundtrip() {
    let pepper = generate_pepper();
    let domain_key = Key256::new(generate_key());

    let (wrapped, nonce) = wrap_pepper_under_domain_key(&domain_key, &pepper).unwrap();
    let unwrapped = unwrap_pepper_from_domain_key(&domain_key, &wrapped, &nonce).unwrap();

    assert_eq!(unwrapped, pepper, "unwrapped pepper matches original");
}

#[test]
fn pepper_wrap_unwrap_share_grant_key_roundtrip() {
    let pepper = generate_pepper();
    let sgk = Key256::new(generate_key());

    let (wrapped, nonce) = wrap_pepper_under_share_grant_key(&sgk, &pepper).unwrap();
    let unwrapped = unwrap_pepper_from_share_grant_key(&sgk, &wrapped, &nonce).unwrap();

    assert_eq!(unwrapped, pepper, "unwrapped pepper matches original");
}

#[test]
fn pepper_wrap_wrong_key_fails() {
    let pepper = generate_pepper();
    let domain_key = Key256::new(generate_key());
    let wrong_key = Key256::new(generate_key());

    let (wrapped, nonce) = wrap_pepper_under_domain_key(&domain_key, &pepper).unwrap();
    let result = unwrap_pepper_from_domain_key(&wrong_key, &wrapped, &nonce);

    assert!(result.is_err(), "wrong key should fail to unwrap pepper");
}

#[test]
fn cross_mode_dedup_simulation() {
    // Simulate: upload in Secured mode, then re-upload same file in Max mode.
    // Both should produce identical content_id and ciphertext.
    let plaintext = b"cross-mode dedup test content".to_vec();
    let pepper = [0x55; 32];

    // Secured mode upload
    let (plan1, ct1, id1, key1) = encrypt_content_file(&plaintext, &pepper).unwrap();

    // Max mode upload (same tenant → same pepper)
    let (plan2, ct2, id2, key2) = encrypt_content_file(&plaintext, &pepper).unwrap();

    assert_eq!(id1, id2, "content_id matches across modes");
    assert_eq!(key1, key2, "ContentKey matches across modes");
    assert_eq!(ct1, ct2, "ciphertexts match across modes");

    // Blob keys are identical → gateway can dedup
    for (c1, c2) in plan1.chunks.iter().zip(plan2.chunks.iter()) {
        assert_eq!(c1.blob_key, c2.blob_key, "blob keys match across modes");
    }
}

// ---------------------------------------------------------------------------
// Tamper detection tests
// ---------------------------------------------------------------------------

#[test]
fn content_chunk_tamper_detection() {
    let plaintext = b"tamper detection test content".to_vec();
    let pepper = [0x77; 32];

    let (_plan, ciphertexts, content_id, content_key) =
        encrypt_content_file(&plaintext, &pepper).unwrap();

    // Tamper with the first ciphertext
    let mut tampered = ciphertexts[0].clone();
    tampered[0] ^= 0xFF; // flip a bit

    // Attempt to decrypt — should fail
    let result = decrypt_content_chunk(&content_key, &content_id, 0, &tampered);
    assert!(
        result.is_err(),
        "tampered ciphertext should fail to decrypt"
    );
}

#[test]
fn content_file_tamper_detection() {
    let plaintext = b"file-level tamper detection test".to_vec();
    let pepper = [0x88; 32];

    let (plan, ciphertexts, content_id, content_key) =
        encrypt_content_file(&plaintext, &pepper).unwrap();

    // Tamper with a ciphertext (clone first to avoid borrow issue)
    let mut tampered_cts = ciphertexts.clone();
    let mid = tampered_cts[0].len() / 2;
    tampered_cts[0][mid] ^= 0x01;

    // Attempt to decrypt the full file — should fail
    let result = decrypt_content_file(&content_key, &content_id, &plan, &tampered_cts, &pepper);
    assert!(result.is_err(), "tampered file should fail to decrypt");
}

#[test]
fn content_chunk_aad_tamper_detection() {
    // Using wrong chunk_index in AAD should cause decryption to fail
    let plaintext = b"AAD tamper test".to_vec();
    let pepper = [0x99; 32];

    let (_plan, ciphertexts, content_id, content_key) =
        encrypt_content_file(&plaintext, &pepper).unwrap();

    // Decrypt with wrong chunk index (999 instead of 0)
    let result = decrypt_content_chunk(&content_key, &content_id, 999, &ciphertexts[0]);
    assert!(
        result.is_err(),
        "wrong AAD (chunk index) should fail to decrypt"
    );
}

// ---------------------------------------------------------------------------
// Merkle tree odd/even leaf count tests
// ---------------------------------------------------------------------------

#[test]
fn merkle_root_two_chunks() {
    use kchat_drive_types::{ChunkDescriptor, ChunkPlan, Hash256};
    let chunks = vec![
        ChunkDescriptor {
            index: 0,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([0xAA; 32]),
            blob_key: "key-0".into(), plaintext_sha256: None,
        },
        ChunkDescriptor {
            index: 1,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([0xBB; 32]),
            blob_key: "key-1".into(), plaintext_sha256: None,
        },
    ];
    let plan = ChunkPlan { chunks };

    // Both functions should produce the same root
    let root_types = plan.merkle_root();
    let root_crypto = content_chunk_plan_root(&plan);
    assert_eq!(
        root_types, root_crypto,
        "types::merkle_root and crypto::content_chunk_plan_root must match for 2 chunks"
    );
}

#[test]
fn merkle_root_three_chunks_odd() {
    use kchat_drive_types::{ChunkDescriptor, ChunkPlan, Hash256};
    let chunks = vec![
        ChunkDescriptor {
            index: 0,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([0xA1; 32]),
            blob_key: "key-0".into(), plaintext_sha256: None,
        },
        ChunkDescriptor {
            index: 1,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([0xA2; 32]),
            blob_key: "key-1".into(), plaintext_sha256: None,
        },
        ChunkDescriptor {
            index: 2,
            plaintext_len: 50,
            ciphertext_len: 66,
            ciphertext_sha256: Hash256::new([0xA3; 32]),
            blob_key: "key-2".into(), plaintext_sha256: None,
        },
    ];
    let plan = ChunkPlan { chunks };

    let root_types = plan.merkle_root();
    let root_crypto = content_chunk_plan_root(&plan);
    assert_eq!(
        root_types, root_crypto,
        "types::merkle_root and crypto::content_chunk_plan_root must match for 3 chunks (odd)"
    );
}

#[test]
fn merkle_root_five_chunks_odd() {
    use kchat_drive_types::{ChunkDescriptor, ChunkPlan, Hash256};
    let chunks: Vec<_> = (0..5)
        .map(|i| ChunkDescriptor {
            index: i,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([(i as u8 + 1); 32]),
            blob_key: format!("key-{}", i), plaintext_sha256: None,
        })
        .collect();
    let plan = ChunkPlan { chunks };

    let root_types = plan.merkle_root();
    let root_crypto = content_chunk_plan_root(&plan);
    assert_eq!(
        root_types, root_crypto,
        "types::merkle_root and crypto::content_chunk_plan_root must match for 5 chunks (odd)"
    );
}

#[test]
fn merkle_root_seven_chunks_odd() {
    use kchat_drive_types::{ChunkDescriptor, ChunkPlan, Hash256};
    let chunks: Vec<_> = (0..7)
        .map(|i| ChunkDescriptor {
            index: i,
            plaintext_len: 100,
            ciphertext_len: 116,
            ciphertext_sha256: Hash256::new([(i as u8 + 10); 32]),
            blob_key: format!("key-{}", i), plaintext_sha256: None,
        })
        .collect();
    let plan = ChunkPlan { chunks };

    let root_types = plan.merkle_root();
    let root_crypto = content_chunk_plan_root(&plan);
    assert_eq!(
        root_types, root_crypto,
        "types::merkle_root and crypto::content_chunk_plan_root must match for 7 chunks (odd)"
    );
}

#[test]
fn merkle_root_single_chunk() {
    use kchat_drive_types::{ChunkDescriptor, ChunkPlan, Hash256};
    let chunks = vec![ChunkDescriptor {
        index: 0,
        plaintext_len: 100,
        ciphertext_len: 116,
        ciphertext_sha256: Hash256::new([0xFF; 32]),
        blob_key: "key-0".into(), plaintext_sha256: None,
    }];
    let plan = ChunkPlan { chunks };

    let root_types = plan.merkle_root();
    let root_crypto = content_chunk_plan_root(&plan);
    assert_eq!(
        root_types, root_crypto,
        "types::merkle_root and crypto::content_chunk_plan_root must match for 1 chunk"
    );
}
