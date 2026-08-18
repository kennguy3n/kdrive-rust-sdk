use kchat_drive_types::*;

fn main() {
    // Use a public key with high bytes to detect encoding issues
    let pub_key = [0xff; 32];
    let header = PublicVersionHeader {
        protocol: 1,
        suite: 1,
        drive_id: DriveId::new([0; 16]),
        node_id: NodeId::new([0; 16]),
        version_id: VersionId::new([0; 16]),
        domain_id: DomainId::new([0; 16]),
        privacy_mode: PrivacyMode::Secured,
        plaintext_size: 0,
        chunk_size: 0,
        chunk_count: 0,
        chunk_plan_root: Hash256::new([0; 32]),
        manifest_ciphertext_sha256: Hash256::new([0; 32]),
        manifest_ciphertext_len: 0,
        manifest_nonce: Nonce12::new([0; 12]),
        access_context_revision: 1,
        access_context_snapshot_hash: Hash256::new([0; 32]),
        creator_device_key: Ed25519PublicKey::new(pub_key),
        created_at: 0,
        signature: None,
        content_id: None,
    };
    let mut buf = Vec::new();
    minicbor::encode(&header, &mut buf).unwrap();
    print!("CBOR bytes ({}): ", buf.len());
    for (i, b) in buf.iter().enumerate() {
        if i == 205 { print!("[POS205: {:02x}] ", b); }
        else { print!("{:02x} ", b); }
    }
    println!();
    // Also print bytes around position 205
    print!("Around pos 205: ");
    for i in 200..210.min(buf.len()) {
        print!("[{}] {:02x} ", i, buf[i]);
    }
    println!();
}
