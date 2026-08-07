pub const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>KChat Drive — Crypto Demo</title>
<style>
  :root {
    --bg: #0f1117;
    --card: #1a1d27;
    --border: #2a2d3a;
    --accent: #6c5ce7;
    --accent-hover: #5a4bd1;
    --text: #e2e2e2;
    --text-dim: #888;
    --success: #00b894;
    --error: #e74c3c;
    --radius: 10px;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 20px;
  }
  h1 { font-size: 1.6rem; margin-bottom: 4px; }
  h2 { font-size: 1.1rem; margin-bottom: 12px; color: var(--text-dim); }
  .header { text-align: center; margin-bottom: 30px; }
  .header p { color: var(--text-dim); font-size: 0.9rem; }
  .container { max-width: 900px; margin: 0 auto; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 20px;
  }
  .card h3 {
    font-size: 1rem;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .card h3 .num {
    background: var(--accent);
    color: #fff;
    border-radius: 50%;
    width: 24px;
    height: 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: bold;
  }
  label { display: block; font-size: 0.85rem; color: var(--text-dim); margin-bottom: 4px; margin-top: 12px; }
  input[type="text"], input[type="number"], textarea, select {
    width: 100%;
    padding: 10px 12px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.85rem;
  }
  textarea { min-height: 80px; resize: vertical; }
  input:focus, textarea:focus, select:focus { outline: none; border-color: var(--accent); }
  .row { display: flex; gap: 12px; }
  .row > * { flex: 1; }
  button {
    padding: 10px 20px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.9rem;
    font-weight: 600;
    transition: background 0.2s;
  }
  button:hover { background: var(--accent-hover); }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  button.secondary { background: var(--border); }
  button.secondary:hover { background: #3a3d4a; }
  .btn-row { display: flex; gap: 10px; margin-top: 16px; }
  .result {
    margin-top: 16px;
    padding: 14px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 0.8rem;
    overflow-x: auto;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .result.success { border-color: var(--success); }
  .result.error { border-color: var(--error); }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
  }
  .badge.ok { background: var(--success); color: #fff; }
  .badge.fail { background: var(--error); color: #fff; }
  .status { margin-top: 8px; font-size: 0.85rem; }
  .status.ok { color: var(--success); }
  .status.err { color: var(--error); }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media (max-width: 700px) { .grid2 { grid-template-columns: 1fr; } .row { flex-direction: column; } }
  .file-info { font-size: 0.8rem; color: var(--text-dim); margin-top: 4px; }
  .tab-bar { display: flex; gap: 4px; margin-bottom: 16px; }
  .tab {
    padding: 8px 16px;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px 6px 0 0;
    cursor: pointer;
    font-size: 0.85rem;
    color: var(--text-dim);
  }
  .tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>KChat Drive — KDRV1 Crypto Demo</h1>
    <p>End-to-end encrypted file storage — AES-256-GCM chunked encryption with HKDF key derivation</p>
  </div>

  <!-- Step 1: Setup -->
  <div class="card">
    <h3><span class="num">1</span> Setup — Generate Encryption Keys & IDs</h3>
    <p style="font-size:0.85rem;color:var(--text-dim);margin-bottom:12px;">
      Generate a random VersionDEK and set of IDs for this encryption session, or enter your own hex values.
    </p>
    <div class="row">
      <div>
        <label>Version DEK (32 bytes hex)</label>
        <input type="text" id="version_dek" placeholder="auto-generated">
      </div>
      <div>
        <label>Access Context Revision</label>
        <input type="number" id="access_context_revision" value="1">
      </div>
    </div>
    <div class="row">
      <div>
        <label>Node ID (16 bytes hex)</label>
        <input type="text" id="node_id" placeholder="auto-generated">
      </div>
      <div>
        <label>Version ID (16 bytes hex)</label>
        <input type="text" id="version_id" placeholder="auto-generated">
      </div>
    </div>
    <div class="row">
      <div>
        <label>Drive ID (16 bytes hex)</label>
        <input type="text" id="drive_id" placeholder="auto-generated">
      </div>
      <div>
        <label>Domain ID (16 bytes hex)</label>
        <input type="text" id="domain_id" placeholder="auto-generated">
      </div>
    </div>
    <div>
      <label>Access Context Snapshot Hash (32 bytes hex)</label>
      <input type="text" id="access_context_snapshot_hash" placeholder="auto-generated">
    </div>
    <div class="btn-row">
      <button onclick="generateIds()">Generate All</button>
      <button class="secondary" onclick="generateKey()">Generate New DEK Only</button>
    </div>
    <div id="setup_status" class="status"></div>
  </div>

  <!-- Step 2: Encrypt -->
  <div class="card">
    <h3><span class="num">2</span> Encrypt File</h3>
    <label>File to encrypt</label>
    <input type="file" id="file_input">
    <div id="file_info" class="file-info"></div>
    <p style="font-size:0.85rem;color:var(--text-dim);margin-top:8px;">Or enter text directly:</p>
    <textarea id="plaintext_text" placeholder="Enter text to encrypt..."></textarea>
    <div class="btn-row">
      <button onclick="encryptFile()" id="encrypt_btn">Encrypt</button>
      <button class="secondary" onclick="encryptText()">Encrypt Text</button>
    </div>
    <div id="encrypt_status" class="status"></div>
    <div id="encrypt_result" class="result hidden"></div>
  </div>

  <!-- Step 3: Encrypted Output -->
  <div class="card" id="output_card" style="display:none;">
    <h3><span class="num">3</span> Encrypted Output — Chunk Plan & Ciphertexts</h3>
    <div id="encrypt_summary"></div>
    <div class="tab-bar">
      <div class="tab active" onclick="switchTab('tab_ciphertexts', this)">Ciphertexts</div>
      <div class="tab" onclick="switchTab('tab_manifest', this)">Manifest</div>
      <div class="tab" onclick="switchTab('tab_header', this)">Header</div>
    </div>
    <div id="tab_ciphertexts">
      <div id="ciphertext_list"></div>
    </div>
    <div id="tab_manifest" class="hidden">
      <label>Manifest Ciphertext (hex)</label>
      <div id="manifest_ct" class="result"></div>
      <label>Manifest Nonce (hex)</label>
      <div id="manifest_nonce" class="result"></div>
    </div>
    <div id="tab_header" class="hidden">
      <label>Public Version Header (CBOR hex)</label>
      <div id="header_cbor" class="result"></div>
      <div class="btn-row">
        <button onclick="signHeader()">Sign Header</button>
      </div>
      <div id="sign_status" class="status"></div>
      <div id="sign_result" class="result hidden"></div>
    </div>
  </div>

  <!-- Step 4: Decrypt -->
  <div class="card" id="decrypt_card" style="display:none;">
    <h3><span class="num">4</span> Decrypt — Round-Trip Verification</h3>
    <p style="font-size:0.85rem;color:var(--text-dim);margin-bottom:12px;">
      Decrypt the ciphertext using the same VersionDEK and IDs to verify the round-trip.
    </p>
    <div class="btn-row">
      <button onclick="decryptData()" id="decrypt_btn">Decrypt</button>
    </div>
    <div id="decrypt_status" class="status"></div>
    <div id="decrypt_result" class="result hidden"></div>
    <div id="decrypt_download" style="margin-top:12px;display:none;">
      <button class="secondary" onclick="downloadDecrypted()">Download Decrypted File</button>
    </div>
  </div>

  <!-- Step 5: Test Vectors -->
  <div class="card">
    <h3>Test Vectors (Cross-Language Compatibility)</h3>
    <p style="font-size:0.85rem;color:var(--text-dim);margin-bottom:12px;">
      Deterministic test vectors for verifying KDF, chunk encryption, and round-trip across language implementations.
    </p>
    <button class="secondary" onclick="loadTestVectors()">Load Test Vectors</button>
    <div id="test_vectors_result" class="result hidden"></div>
  </div>
</div>

<script>
let encryptedData = null;
let decryptedData = null;
let originalFileName = null;

async function api(path, opts = {}) {
  const resp = await fetch(path, opts);
  const text = await resp.text();
  try { return JSON.parse(text); } catch { return { error: text }; }
}

function setStatus(id, msg, ok) {
  const el = document.getElementById(id);
  el.className = 'status ' + (ok ? 'ok' : 'err');
  el.textContent = msg;
}

function showResult(id, text, ok) {
  const el = document.getElementById(id);
  el.className = 'result ' + (ok ? 'success' : 'error');
  el.textContent = text;
  el.classList.remove('hidden');
}

async function generateIds() {
  const data = await api('/api/generate-ids');
  if (data.error) return setStatus('setup_status', data.error, false);
  document.getElementById('version_dek').value = '';
  document.getElementById('node_id').value = data.node_id;
  document.getElementById('version_id').value = data.version_id;
  document.getElementById('drive_id').value = data.drive_id;
  document.getElementById('domain_id').value = data.domain_id;
  document.getElementById('access_context_snapshot_hash').value = data.access_context_snapshot_hash;
  document.getElementById('access_context_revision').value = data.access_context_revision;
  await generateKey();
  setStatus('setup_status', 'IDs and DEK generated successfully', true);
}

async function generateKey() {
  const data = await api('/api/generate-key');
  if (data.error) return setStatus('setup_status', data.error, false);
  document.getElementById('version_dek').value = data.version_dek;
  setStatus('setup_status', 'New VersionDEK generated', true);
}

function getParams() {
  return {
    version_dek: document.getElementById('version_dek').value,
    node_id: document.getElementById('node_id').value,
    version_id: document.getElementById('version_id').value,
    drive_id: document.getElementById('drive_id').value,
    domain_id: document.getElementById('domain_id').value,
    access_context_revision: parseInt(document.getElementById('access_context_revision').value),
    access_context_snapshot_hash: document.getElementById('access_context_snapshot_hash').value,
  };
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const arr = new Uint8Array(reader.result);
      let binary = '';
      for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
      resolve(btoa(binary));
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(file);
  });
}

function base64ToUint8Array(b64) {
  const binary = atob(b64);
  const arr = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) arr[i] = binary.charCodeAt(i);
  return arr;
}

document.getElementById('file_input').addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (file) {
    document.getElementById('file_info').textContent =
      `${file.name} — ${(file.size / 1024).toFixed(2)} KB (${file.size} bytes)`;
    originalFileName = file.name;
  }
});

async function encryptFile() {
  const file = document.getElementById('file_input').files[0];
  if (!file) return setStatus('encrypt_status', 'Please select a file', false);
  const b64 = await fileToBase64(file);
  await doEncrypt(b64, file.name);
}

async function encryptText() {
  const text = document.getElementById('plaintext_text').value;
  if (!text) return setStatus('encrypt_status', 'Please enter text', false);
  const b64 = btoa(unescape(encodeURIComponent(text)));
  await doEncrypt(b64, 'text.txt');
}

async function doEncrypt(plaintextB64, filename) {
  const params = getParams();
  if (!params.version_dek) return setStatus('encrypt_status', 'Generate keys first', false);

  setStatus('encrypt_status', 'Encrypting...', true);
  const data = await api('/api/encrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...params, plaintext_base64: plaintextB64 }),
  });

  if (data.error) {
    setStatus('encrypt_status', 'Error: ' + data.error, false);
    return;
  }

  encryptedData = { ...params, ...data, original_filename: filename };
  setStatus('encrypt_status', `Encrypted successfully — ${data.chunk_count} chunk(s), root: ${data.chunk_plan_root.slice(0,16)}...`, true);

  // Show output card
  document.getElementById('output_card').style.display = '';
  document.getElementById('decrypt_card').style.display = '';

  // Summary
  document.getElementById('encrypt_summary').innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-bottom:16px;">
      <div><label style="margin:0">Chunk Count</label><div style="font-size:1.2rem;font-weight:bold">${data.chunk_count}</div></div>
      <div><label style="margin:0">Chunk Size</label><div style="font-size:1.2rem;font-weight:bold">${(data.chunk_size/1024/1024).toFixed(0)} MB</div></div>
      <div><label style="margin:0">Merkle Root</label><div style="font-family:monospace;font-size:0.8rem;word-break:break-all">${data.chunk_plan_root}</div></div>
    </div>
  `;

  // Ciphertext list
  let html = '';
  data.ciphertexts_hex.forEach((ct, i) => {
    const chunk = data.chunks[i];
    html += `<div style="margin-bottom:12px;padding:10px;background:var(--bg);border-radius:6px;">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
        <strong>Chunk ${i}</strong>
        <span style="font-size:0.8rem;color:var(--text-dim)">${chunk.plaintext_len} → ${chunk.ciphertext_len} bytes</span>
      </div>
      <div style="font-family:monospace;font-size:0.75rem;color:var(--text-dim);word-break:break-all">SHA-256: ${chunk.ciphertext_sha256}</div>
      <div style="font-family:monospace;font-size:0.75rem;color:var(--text-dim);word-break:break-all;margin-top:4px">CT: ${ct.slice(0,80)}... (${ct.length/2} bytes)</div>
    </div>`;
  });
  document.getElementById('ciphertext_list').innerHTML = html;
  document.getElementById('manifest_ct').textContent = data.manifest_ciphertext_hex;
  document.getElementById('manifest_nonce').textContent = data.manifest_nonce_hex;
  document.getElementById('header_cbor').textContent = data.header_cbor_hex;
}

async function decryptData() {
  if (!encryptedData) return setStatus('decrypt_status', 'Encrypt something first', false);
  const params = getParams();

  setStatus('decrypt_status', 'Decrypting...', true);
  const data = await api('/api/decrypt', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      version_dek: params.version_dek,
      node_id: params.node_id,
      version_id: params.version_id,
      drive_id: params.drive_id,
      domain_id: params.domain_id,
      access_context_revision: params.access_context_revision,
      access_context_snapshot_hash: params.access_context_snapshot_hash,
      manifest_ciphertext_hex: encryptedData.manifest_ciphertext_hex,
      manifest_nonce_hex: encryptedData.manifest_nonce_hex,
      ciphertexts_hex: encryptedData.ciphertexts_hex,
    }),
  });

  if (data.error) {
    setStatus('decrypt_status', 'Error: ' + data.error, false);
    return;
  }

  decryptedData = data.plaintext_base64;
  const bytes = base64ToUint8Array(data.plaintext_base64);

  // Try to show as text
  let textDisplay;
  try {
    textDisplay = new TextDecoder().decode(bytes);
  } catch {
    textDisplay = `[Binary data — ${data.plaintext_size} bytes]`;
  }

  const match = data.plaintext_size === encryptedData.chunks.reduce((a,c) => a + c.plaintext_len, 0);
  setStatus('decrypt_status',
    `Decrypted ${data.plaintext_size} bytes — ${match ? '✓ Size matches original' : '✗ Size mismatch!'}`,
    match);

  showResult('decrypt_result',
    `Plaintext size: ${data.plaintext_size} bytes\n\n--- Content preview ---\n${textDisplay.slice(0, 500)}${textDisplay.length > 500 ? '...' : ''}`,
    true);

  document.getElementById('decrypt_download').style.display = '';
}

function downloadDecrypted() {
  if (!decryptedData) return;
  const bytes = base64ToUint8Array(decryptedData);
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'decrypted_' + (originalFileName || 'file');
  a.click();
  URL.revokeObjectURL(url);
}

function switchTab(tabId, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  el.classList.add('active');
  ['tab_ciphertexts', 'tab_manifest', 'tab_header'].forEach(id => {
    document.getElementById(id).classList.add('hidden');
  });
  document.getElementById(tabId).classList.remove('hidden');
}

async function signHeader() {
  if (!encryptedData) return;
  // Generate an Ed25519 keypair via the server
  // For demo, we generate a signing key on the server side
  const signingKeyHex = prompt('Enter Ed25519 signing key (32 bytes hex), or leave empty to generate:');
  if (signingKeyHex === null) return;

  let key = signingKeyHex.trim();
  if (!key) {
    // Generate a random 32-byte key in JS
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    key = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  const data = await api('/api/sign-header', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      header_cbor_hex: encryptedData.header_cbor_hex,
      signing_key_hex: key,
    }),
  });

  if (data.error) {
    setStatus('sign_status', 'Error: ' + data.error, false);
    return;
  }

  encryptedData.header_cbor_hex = data.signed_header_cbor_hex;
  document.getElementById('header_cbor').textContent = data.signed_header_cbor_hex;

  setStatus('sign_status', 'Header signed successfully', true);
  showResult('sign_result',
    `Signature: ${data.signature_hex}\n\nVerifying key: ${data.verifying_key_hex}\n\nSigned header CBOR: ${data.signed_header_cbor_hex}`,
    true);
}

async function loadTestVectors() {
  const data = await api('/api/test-vectors');
  if (data.error) {
    showResult('test_vectors_result', 'Error: ' + data.error, false);
    return;
  }
  const formatted = JSON.stringify(data, null, 2);
  showResult('test_vectors_result', formatted, true);
}

// Auto-generate IDs on load
window.addEventListener('DOMContentLoaded', generateIds);
</script>
</body>
</html>
"#;
