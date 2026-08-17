use kchat_drive_types::*;
use serde::Serialize;

/// Cross-language test vector for KDF derivation.
/// These vectors must produce identical bytes in Rust, Go, and WASM.
#[derive(Debug, Clone, Serialize)]
pub struct KdfVector {
    pub version_dek_hex: String,
    pub node_id_hex: String,
    pub version_id_hex: String,
    pub chunk_index: u64,
    pub expected_chunk_key_hex: String,
    pub expected_chunk_nonce_hex: String,
    pub expected_manifest_key_hex: String,
    pub expected_manifest_nonce_hex: String,
}

/// Cross-language test vector for chunk encryption.
#[derive(Debug, Clone, Serialize)]
pub struct ChunkVector {
    pub version_dek_hex: String,
    pub node_id_hex: String,
    pub version_id_hex: String,
    pub drive_id_hex: String,
    pub domain_id_hex: String,
    pub chunk_index: u64,
    pub plaintext_hex: String,
    pub aad_hex: String,
    pub expected_ciphertext_hex: String,
}

/// Cross-language test vector for the full encrypt/decrypt round-trip.
#[derive(Debug, Clone, Serialize)]
pub struct RoundTripVector {
    pub version_dek_hex: String,
    pub node_id_hex: String,
    pub version_id_hex: String,
    pub drive_id_hex: String,
    pub domain_id_hex: String,
    pub access_context_revision: u64,
    pub access_context_snapshot_hash_hex: String,
    pub plaintext_hex: String,
    pub chunk_plan_root_hex: String,
    pub chunk_count: u64,
}

/// Generates a set of KDF test vectors with known inputs.
pub fn generate_kdf_vectors() -> Vec<KdfVector> {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([0x01u8; 16]);
    let version_id = VersionId::new([0x02u8; 16]);

    let mut vectors = Vec::new();
    for chunk_index in 0..3u64 {
        let prk = crate::kdf::extract_prk(&version_dek);
        let chunk_key =
            crate::kdf::derive_chunk_key(&prk, &node_id, &version_id, chunk_index).expect("valid PRK");
        let chunk_nonce =
            crate::kdf::derive_chunk_nonce(&prk, &node_id, &version_id, chunk_index).expect("valid PRK");
        let manifest_key =
            crate::kdf::derive_manifest_key(&prk, &node_id, &version_id).expect("valid PRK");
        let manifest_nonce =
            crate::kdf::derive_manifest_nonce(&prk, &node_id, &version_id).expect("valid PRK");

        vectors.push(KdfVector {
            version_dek_hex: hex::encode(version_dek),
            node_id_hex: node_id.to_hex(),
            version_id_hex: version_id.to_hex(),
            chunk_index,
            expected_chunk_key_hex: hex::encode(chunk_key),
            expected_chunk_nonce_hex: hex::encode(chunk_nonce),
            expected_manifest_key_hex: hex::encode(manifest_key),
            expected_manifest_nonce_hex: hex::encode(manifest_nonce),
        });
    }
    vectors
}

/// Generates a round-trip test vector.
pub fn generate_round_trip_vector() -> RoundTripVector {
    let version_dek = [0x42u8; 32];
    let node_id = NodeId::new([0x01u8; 16]);
    let version_id = VersionId::new([0x02u8; 16]);
    let drive_id = [0x03u8; 16];
    let domain_id = DomainId::new([0x04u8; 16]);
    let access_context_revision = 1u64;
    let access_context_snapshot_hash = [0x05u8; 32];
    let plaintext = b"Hello, KChat Drive! This is a test file for cross-language verification.";

    let (chunk_plan, _ciphertexts) = crate::chunk::encrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &access_context_snapshot_hash,
        plaintext,
    )
    .expect("encrypt_file should succeed");

    let root = chunk_plan.merkle_root();

    RoundTripVector {
        version_dek_hex: hex::encode(version_dek),
        node_id_hex: node_id.to_hex(),
        version_id_hex: version_id.to_hex(),
        drive_id_hex: hex::encode(drive_id),
        domain_id_hex: domain_id.to_hex(),
        access_context_revision,
        access_context_snapshot_hash_hex: hex::encode(access_context_snapshot_hash),
        plaintext_hex: hex::encode(plaintext),
        chunk_plan_root_hex: root.to_hex(),
        chunk_count: chunk_plan.chunks.len() as u64,
    }
}

/// Serializes all test vectors as JSON (for cross-language verification).
pub fn all_vectors_json() -> String {
    #[derive(Serialize)]
    struct AllVectors {
        protocol: &'static str,
        version: u32,
        suite: u32,
        kdf: Vec<KdfVector>,
        round_trip: RoundTripVector,
    }

    let all = AllVectors {
        protocol: "kdrv1",
        version: 1,
        suite: 1,
        kdf: generate_kdf_vectors(),
        round_trip: generate_round_trip_vector(),
    };

    serde_json::to_string_pretty(&all).expect("serialize vectors")
}
