use kchat_drive_crypto::*;
use kchat_drive_types::*;

#[test]
fn chunk_encrypt_decrypt_roundtrip() {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([1; 16]);
    let version_id = VersionId::new([2; 16]);
    let plaintext = b"Hello, KChat Drive!";
    let aad = b"test-aad";

    let ct = encrypt_chunk(&version_dek, &node_id, &version_id, 0, plaintext, aad).unwrap();
    let pt = decrypt_chunk(&version_dek, &node_id, &version_id, 0, &ct, aad).unwrap();

    assert_eq!(pt, plaintext);
}

#[test]
fn chunk_aad_mismatch_fails() {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([1; 16]);
    let version_id = VersionId::new([2; 16]);
    let plaintext = b"Hello, KChat Drive!";

    let ct = encrypt_chunk(
        &version_dek,
        &node_id,
        &version_id,
        0,
        plaintext,
        b"correct-aad",
    )
    .unwrap();
    let result = decrypt_chunk(&version_dek, &node_id, &version_id, 0, &ct, b"wrong-aad");

    assert!(result.is_err());
}

#[test]
fn chunk_wrong_key_fails() {
    let version_dek = [0x42u8; 32];
    let wrong_dek = [0x99u8; 32];
    let node_id = NodeId::new([1; 16]);
    let version_id = VersionId::new([2; 16]);
    let plaintext = b"Hello, KChat Drive!";
    let aad = b"test-aad";

    let ct = encrypt_chunk(&version_dek, &node_id, &version_id, 0, plaintext, aad).unwrap();
    let result = decrypt_chunk(&wrong_dek, &node_id, &version_id, 0, &ct, aad);

    assert!(result.is_err());
}

#[test]
fn file_encrypt_decrypt_roundtrip() {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([1; 16]);
    let version_id = VersionId::new([2; 16]);
    let drive_id = [3u8; 16];
    let domain_id = DomainId::new([4; 16]);
    let plaintext =
        b"Hello, KChat Drive! This is a test file for the encrypt/decrypt round-trip.".to_vec();

    let (chunk_plan, ciphertexts) = encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        1,
        &[5u8; 32],
        &plaintext,
    )
    .unwrap();

    let decrypted = decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        1,
        &[5u8; 32],
        &chunk_plan,
        &ciphertexts,
    )
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn select_chunk_size_thresholds() {
    assert_eq!(select_chunk_size(0), 4 * 1024 * 1024);
    assert_eq!(select_chunk_size(63 * 1024 * 1024), 4 * 1024 * 1024);
    assert_eq!(select_chunk_size(64 * 1024 * 1024), 8 * 1024 * 1024);
    assert_eq!(select_chunk_size(511 * 1024 * 1024), 8 * 1024 * 1024);
    assert_eq!(select_chunk_size(512 * 1024 * 1024), 16 * 1024 * 1024);
}

#[test]
fn chunk_count_calculation() {
    assert_eq!(chunk_count(0, 4096), 1);
    assert_eq!(chunk_count(1, 4096), 1);
    assert_eq!(chunk_count(4096, 4096), 1);
    assert_eq!(chunk_count(4097, 4096), 2);
    assert_eq!(chunk_count(8192, 4096), 2);
}
