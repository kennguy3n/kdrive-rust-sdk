use kchat_drive_crypto::*;
use kchat_drive_types::*;

#[test]
fn kdf_vectors_are_deterministic() {
    let vectors1 = generate_kdf_vectors();
    let vectors2 = generate_kdf_vectors();
    assert_eq!(vectors1.len(), vectors2.len());
    for (v1, v2) in vectors1.iter().zip(vectors2.iter()) {
        assert_eq!(v1.expected_chunk_key_hex, v2.expected_chunk_key_hex);
        assert_eq!(v1.expected_chunk_nonce_hex, v2.expected_chunk_nonce_hex);
        assert_eq!(v1.expected_manifest_key_hex, v2.expected_manifest_key_hex);
        assert_eq!(
            v1.expected_manifest_nonce_hex,
            v2.expected_manifest_nonce_hex
        );
    }
}

#[test]
fn round_trip_vector_is_deterministic() {
    let v1 = generate_round_trip_vector();
    let v2 = generate_round_trip_vector();
    assert_eq!(v1.chunk_plan_root_hex, v2.chunk_plan_root_hex);
    assert_eq!(v1.chunk_count, v2.chunk_count);
}

#[test]
fn all_vectors_json_is_valid() {
    let json = all_vectors_json();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(parsed["kdf"].is_array());
    assert!(parsed["round_trip"].is_object());
}
