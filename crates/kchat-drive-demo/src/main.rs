use std::io::{Read, Write};
use std::net::TcpListener;

use kchat_drive_crypto::{
    decrypt_file, decrypt_manifest, encrypt_file, encrypt_manifest, generate_key,
    select_chunk_size, sign_header, verify_header,
};
use kchat_drive_types::{
    DomainId, DriveId, Ed25519PublicKey, Hash256, NodeId, Nonce12, PrivacyMode, PublicVersionHeader,
    VersionId, PROTOCOL_VERSION, SUITE_KDRV1,
};

mod html;

fn main() {
    let port = 3000;
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).expect("bind failed");
    println!("KChat Drive demo server running at http://127.0.0.1:{}", port);
    println!("Open this URL in your browser to try the encrypt/decrypt demo.\n");

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Connection error: {}", e);
                continue;
            }
        };
        handle_request(&mut stream);
    }
}

fn handle_request(stream: &mut std::net::TcpStream) {
    let mut buf = [0u8; 65536];
    let n = match stream.read(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let lines: Vec<&str> = request.lines().collect();
    let request_line = lines.first().copied().unwrap_or("");
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let path = parts[1];

    let body_start = request.find("\r\n\r\n").map(|i| i + 4).unwrap_or(request.len());
    let body = &request[body_start..];

    let (status, content_type, response_body) = match (method, path) {
        ("GET", "/") => (200, "text/html; charset=utf-8", html::INDEX_HTML.to_string()),
        ("GET", "/api/health") => (
            200,
            "application/json",
            r#"{"status":"ok","protocol":1,"suite":1}"#.to_string(),
        ),
        ("GET", "/api/generate-key") => {
            let key = generate_key();
            let json = serde_json::json!({
                "version_dek": hex::encode(key),
            });
            (200, "application/json", json.to_string())
        }
        ("GET", "/api/generate-ids") => {
            let node_id = NodeId::random();
            let version_id = VersionId::random();
            let drive_id = DriveId::random();
            let domain_id = DomainId::random();
            let snapshot_hash = generate_key();
            let json = serde_json::json!({
                "node_id": node_id.to_hex(),
                "version_id": version_id.to_hex(),
                "drive_id": drive_id.to_hex(),
                "domain_id": domain_id.to_hex(),
                "access_context_revision": 1,
                "access_context_snapshot_hash": hex::encode(snapshot_hash),
            });
            (200, "application/json", json.to_string())
        }
        ("GET", "/api/test-vectors") => {
            let json = kchat_drive_crypto::all_vectors_json();
            (200, "application/json", json)
        }
        ("POST", "/api/encrypt") => match handle_encrypt(body) {
            Ok(json) => (200, "application/json", json),
            Err(e) => (400, "application/json", format!(r#"{{"error":"{}"}}"#, e)),
        },
        ("POST", "/api/decrypt") => match handle_decrypt(body) {
            Ok(json) => (200, "application/json", json),
            Err(e) => (400, "application/json", format!(r#"{{"error":"{}"}}"#, e)),
        },
        ("POST", "/api/sign-header") => match handle_sign_header(body) {
            Ok(json) => (200, "application/json", json),
            Err(e) => (400, "application/json", format!(r#"{{"error":"{}"}}"#, e)),
        },
        ("POST", "/api/verify-header") => match handle_verify_header(body) {
            Ok(json) => (200, "application/json", json),
            Err(e) => (400, "application/json", format!(r#"{{"error":"{}"}}"#, e)),
        },
        _ => (404, "text/plain", "Not Found".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n{}",
        status,
        content_type,
        response_body.len(),
        response_body
    );
    let _ = stream.write_all(response.as_bytes());
}

fn handle_encrypt(body: &str) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {}", e))?;

    let version_dek_hex = req["version_dek"]
        .as_str()
        .ok_or("missing version_dek")?;
    let node_id_hex = req["node_id"].as_str().ok_or("missing node_id")?;
    let version_id_hex = req["version_id"]
        .as_str()
        .ok_or("missing version_id")?;
    let drive_id_hex = req["drive_id"].as_str().ok_or("missing drive_id")?;
    let domain_id_hex = req["domain_id"]
        .as_str()
        .ok_or("missing domain_id")?;
    let access_context_revision = req["access_context_revision"]
        .as_u64()
        .ok_or("missing access_context_revision")?;
    let snapshot_hash_hex = req["access_context_snapshot_hash"]
        .as_str()
        .ok_or("missing access_context_snapshot_hash")?;
    let plaintext_b64 = req["plaintext_base64"]
        .as_str()
        .ok_or("missing plaintext_base64")?;

    let version_dek = hex::decode(version_dek_hex).map_err(|e| format!("invalid version_dek: {}", e))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| "version_dek must be 32 bytes")?;

    let node_id = NodeId::from_hex(node_id_hex).map_err(|e| e.to_string())?;
    let version_id = VersionId::from_hex(version_id_hex).map_err(|e| e.to_string())?;
    let drive_id = hex::decode(drive_id_hex).map_err(|e| format!("invalid drive_id: {}", e))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| "drive_id must be 16 bytes")?;
    let domain_id = DomainId::from_hex(domain_id_hex).map_err(|e| e.to_string())?;
    let snapshot_hash = hex::decode(snapshot_hash_hex)
        .map_err(|e| format!("invalid snapshot_hash: {}", e))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| "snapshot_hash must be 32 bytes")?;

    let plaintext = base64_decode(plaintext_b64)?;

    let (chunk_plan, ciphertexts) =
        encrypt_file(
            &version_dek,
            &node_id,
            &version_id,
            &drive_id,
            &domain_id,
            access_context_revision,
            &snapshot_hash,
            &plaintext,
        )
        .map_err(|e| e.to_string())?;

    let root = chunk_plan.merkle_root();

    let manifest = kchat_drive_types::Manifest {
        version_id: version_id.clone(),
        node_id: node_id.clone(),
        chunk_plan: chunk_plan.clone(),
        name_ciphertext: vec![],
        mime_type: None,
        plaintext_size: plaintext.len() as u64,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        parent_version_id: None,
    };

    let (manifest_ct, manifest_nonce) =
        encrypt_manifest(&version_dek, &node_id, &version_id, &manifest).map_err(|e| e.to_string())?;

    let manifest_sha = kchat_drive_crypto::sha256(&manifest_ct);

    let header = PublicVersionHeader {
        protocol: PROTOCOL_VERSION,
        suite: SUITE_KDRV1,
        drive_id: DriveId::new(drive_id),
        node_id: node_id.clone(),
        version_id: version_id.clone(),
        domain_id: domain_id.clone(),
        privacy_mode: PrivacyMode::Advanced,
        plaintext_size: plaintext.len() as u64,
        chunk_size: select_chunk_size(plaintext.len() as u64),
        chunk_count: chunk_plan.chunks.len() as u64,
        chunk_plan_root: root.clone(),
        manifest_ciphertext_sha256: manifest_sha,
        manifest_ciphertext_len: manifest_ct.len() as u64,
        manifest_nonce: manifest_nonce.clone(),
        access_context_revision,
        access_context_snapshot_hash: Hash256::new(snapshot_hash),
        creator_device_key: Ed25519PublicKey::new([0u8; 32]),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        signature: None,
    };

    let mut header_buf = Vec::new();
    minicbor::encode(&header, &mut header_buf).map_err(|e| e.to_string())?;

    let json = serde_json::json!({
        "version_id": version_id.to_hex(),
        "chunk_plan_root": root.to_hex(),
        "chunk_count": chunk_plan.chunks.len(),
        "chunk_size": select_chunk_size(plaintext.len() as u64),
        "manifest_ciphertext_hex": hex::encode(&manifest_ct),
        "manifest_nonce_hex": hex::encode(manifest_nonce.as_bytes()),
        "header_cbor_hex": hex::encode(&header_buf),
        "ciphertexts_hex": ciphertexts.iter().map(hex::encode).collect::<Vec<_>>(),
        "chunks": chunk_plan.chunks.iter().map(|c| {
            serde_json::json!({
                "index": c.index,
                "plaintext_len": c.plaintext_len,
                "ciphertext_len": c.ciphertext_len,
                "ciphertext_sha256": c.ciphertext_sha256.to_hex(),
                "blob_key": c.blob_key,
            })
        }).collect::<Vec<_>>(),
    });

    Ok(json.to_string())
}

fn handle_decrypt(body: &str) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {}", e))?;

    let version_dek_hex = req["version_dek"]
        .as_str()
        .ok_or("missing version_dek")?;
    let node_id_hex = req["node_id"].as_str().ok_or("missing node_id")?;
    let version_id_hex = req["version_id"]
        .as_str()
        .ok_or("missing version_id")?;
    let drive_id_hex = req["drive_id"].as_str().ok_or("missing drive_id")?;
    let domain_id_hex = req["domain_id"]
        .as_str()
        .ok_or("missing domain_id")?;
    let access_context_revision = req["access_context_revision"]
        .as_u64()
        .ok_or("missing access_context_revision")?;
    let snapshot_hash_hex = req["access_context_snapshot_hash"]
        .as_str()
        .ok_or("missing access_context_snapshot_hash")?;
    let manifest_ct_hex = req["manifest_ciphertext_hex"]
        .as_str()
        .ok_or("missing manifest_ciphertext_hex")?;
    let manifest_nonce_hex = req["manifest_nonce_hex"]
        .as_str()
        .ok_or("missing manifest_nonce_hex")?;
    let ciphertexts_hex = req["ciphertexts_hex"]
        .as_array()
        .ok_or("missing ciphertexts_hex array")?;

    let version_dek = hex::decode(version_dek_hex).map_err(|e| format!("invalid version_dek: {}", e))?;
    let version_dek: [u8; 32] = version_dek
        .as_slice()
        .try_into()
        .map_err(|_| "version_dek must be 32 bytes")?;

    let node_id = NodeId::from_hex(node_id_hex).map_err(|e| e.to_string())?;
    let version_id = VersionId::from_hex(version_id_hex).map_err(|e| e.to_string())?;
    let drive_id = hex::decode(drive_id_hex).map_err(|e| format!("invalid drive_id: {}", e))?;
    let drive_id: [u8; 16] = drive_id
        .as_slice()
        .try_into()
        .map_err(|_| "drive_id must be 16 bytes")?;
    let domain_id = DomainId::from_hex(domain_id_hex).map_err(|e| e.to_string())?;
    let snapshot_hash = hex::decode(snapshot_hash_hex)
        .map_err(|e| format!("invalid snapshot_hash: {}", e))?;
    let snapshot_hash: [u8; 32] = snapshot_hash
        .as_slice()
        .try_into()
        .map_err(|_| "snapshot_hash must be 32 bytes")?;

    let manifest_ct =
        hex::decode(manifest_ct_hex).map_err(|e| format!("invalid manifest_ciphertext: {}", e))?;
    let manifest_nonce_bytes =
        hex::decode(manifest_nonce_hex).map_err(|e| format!("invalid manifest_nonce: {}", e))?;
    let manifest_nonce_bytes: [u8; 12] = manifest_nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "manifest_nonce must be 12 bytes")?;
    let manifest_nonce = Nonce12::new(manifest_nonce_bytes);

    let manifest = decrypt_manifest(
        &version_dek,
        &node_id,
        &version_id,
        &manifest_ct,
        &manifest_nonce,
    )
    .map_err(|e| e.to_string())?;

    let ciphertexts: Vec<Vec<u8>> = ciphertexts_hex
        .iter()
        .map(|h| {
            hex::decode(h.as_str().unwrap_or(""))
                .map_err(|e| format!("invalid ciphertext hex: {}", e))
        })
        .collect::<Result<_, _>>()?;

    let plaintext = decrypt_file(
        &version_dek,
        &node_id,
        &version_id,
        &drive_id,
        &domain_id,
        access_context_revision,
        &snapshot_hash,
        &manifest.chunk_plan,
        &ciphertexts,
    )
    .map_err(|e| e.to_string())?;

    let plaintext_b64 = base64_encode(&plaintext);

    let json = serde_json::json!({
        "plaintext_base64": plaintext_b64,
        "plaintext_size": plaintext.len(),
    });

    Ok(json.to_string())
}

fn handle_sign_header(body: &str) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {}", e))?;

    let header_cbor_hex = req["header_cbor_hex"]
        .as_str()
        .ok_or("missing header_cbor_hex")?;
    let signing_key_hex = req["signing_key_hex"]
        .as_str()
        .ok_or("missing signing_key_hex")?;

    let header_bytes =
        hex::decode(header_cbor_hex).map_err(|e| format!("invalid header_cbor: {}", e))?;
    let mut header: PublicVersionHeader =
        minicbor::decode(&header_bytes).map_err(|e| e.to_string())?;

    let signing_key_bytes =
        hex::decode(signing_key_hex).map_err(|e| format!("invalid signing_key: {}", e))?;
    let signing_key_bytes: [u8; 32] = signing_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing_key must be 32 bytes")?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_key_bytes);

    let sig = sign_header(&header, &signing_key).map_err(|e| e.to_string())?;
    let sig_bytes = sig.as_bytes().to_vec();
    header.signature = Some(sig);

    let mut signed_buf = Vec::new();
    minicbor::encode(&header, &mut signed_buf).map_err(|e| e.to_string())?;

    let verifying_key = signing_key.verifying_key();

    let json = serde_json::json!({
        "signed_header_cbor_hex": hex::encode(&signed_buf),
        "signature_hex": hex::encode(&sig_bytes),
        "verifying_key_hex": hex::encode(verifying_key.to_bytes()),
    });

    Ok(json.to_string())
}

fn handle_verify_header(body: &str) -> Result<String, String> {
    let req: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("invalid JSON: {}", e))?;

    let header_cbor_hex = req["header_cbor_hex"]
        .as_str()
        .ok_or("missing header_cbor_hex")?;
    let verifying_key_hex = req["verifying_key_hex"]
        .as_str()
        .ok_or("missing verifying_key_hex")?;

    let header_bytes =
        hex::decode(header_cbor_hex).map_err(|e| format!("invalid header_cbor: {}", e))?;
    let header: PublicVersionHeader =
        minicbor::decode(&header_bytes).map_err(|e| e.to_string())?;

    let verifying_key_bytes =
        hex::decode(verifying_key_hex).map_err(|e| format!("invalid verifying_key: {}", e))?;
    let verifying_key_bytes: [u8; 32] = verifying_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "verifying_key must be 32 bytes")?;

    let pk = Ed25519PublicKey::new(verifying_key_bytes);
    let valid = verify_header(&header, &pk).map_err(|e| e.to_string())?;

    let json = serde_json::json!({
        "valid": valid,
    });

    Ok(json.to_string())
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);

        result.push(CHARS[(b0 >> 2) as usize] as char);
        result.push(CHARS[((b0 & 0x03) << 4 | b1 >> 4) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((b1 & 0x0f) << 2 | b2 >> 6) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(b2 & 0x3f) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let mut result = Vec::new();
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk
            .iter()
            .map(|&b| match b {
                b'A'..=b'Z' => Ok(b - b'A'),
                b'a'..=b'z' => Ok(b - b'a' + 26),
                b'0'..=b'9' => Ok(b - b'0' + 52),
                b'+' => Ok(62),
                b'/' => Ok(63),
                b'=' => Ok(0),
                _ => Err(format!("invalid base64 char: {}", b as char)),
            })
            .collect::<Result<_, _>>()?;

        result.push((vals[0] << 2) | (vals[1] >> 4));
        if chunk.len() > 2 && chunk[2] != b'=' {
            result.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            result.push((vals[2] << 6) | vals[3]);
        }
    }
    Ok(result)
}
