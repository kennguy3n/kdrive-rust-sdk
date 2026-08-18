use kchat_drive_crypto::content::encrypt_content_file;

fn main() {
    let pepper = [0xAA; 32];
    let chunk1 = vec![0x41u8; 4 * 1024 * 1024]; // 4MB of 'A'
    let chunk2_a = vec![0x42u8; 1024]; // 1KB of 'B'
    let chunk2_b = vec![0x43u8; 1024]; // 1KB of 'C'

    let mut plaintext1 = chunk1.clone();
    plaintext1.extend_from_slice(&chunk2_a);

    let mut plaintext2 = chunk1.clone();
    plaintext2.extend_from_slice(&chunk2_b);

    let (plan1, cts1, _, _) = encrypt_content_file(&plaintext1, &pepper).unwrap();
    let (plan2, cts2, _, _) = encrypt_content_file(&plaintext2, &pepper).unwrap();

    println!("Chunk 0 hash 1: {}", hex::encode(plan1.chunks[0].ciphertext_sha256.as_bytes()));
    println!("Chunk 0 hash 2: {}", hex::encode(plan2.chunks[0].ciphertext_sha256.as_bytes()));
    println!("Chunk 0 match: {}", plan1.chunks[0].ciphertext_sha256 == plan2.chunks[0].ciphertext_sha256);
    println!("Chunk 1 hash 1: {}", hex::encode(plan1.chunks[1].ciphertext_sha256.as_bytes()));
    println!("Chunk 1 hash 2: {}", hex::encode(plan2.chunks[1].ciphertext_sha256.as_bytes()));
    println!("Chunk 1 match: {}", plan1.chunks[1].ciphertext_sha256 == plan2.chunks[1].ciphertext_sha256);
}
