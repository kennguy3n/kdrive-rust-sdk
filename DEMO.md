# KChat Drive Rust SDK — Demo Guide

This guide walks through the two demo entry points in the `kdrive-rust-sdk`
repo:

1. **Native demo server** — a standalone TCP server (`cargo run -p
   kchat-drive-demo`) that exercises the pure-Rust crypto core with no browser,
   no WASM, and no Go gateway required. Best for quickly verifying the crypto
   compiles and runs.
2. **Web sample** — a React + Vite app (`web-sample/`) that compiles the SDK to
   WebAssembly and runs against a live Go gateway. Demonstrates all three
   privacy modes end-to-end with six automated scenarios.

For the web sample's full setup, scenario reference, and troubleshooting, see
[`web-sample/README.md`](web-sample/README.md) and
[`web-sample/DEMO.md`](web-sample/DEMO.md). This document covers the native
demo in depth and gives a condensed overview of the web sample.

## 1. Native demo server (`kchat-drive-demo`)

A minimal HTTP server bound to `127.0.0.1:3000` that serves an HTML page with
encrypt/decrypt/sign/verify forms. It uses only the `kchat-drive-crypto` and
`kchat-drive-types` crates — no MLS, no vault, no transport, no gateway.

### 1.1 Run it

```bash
cd /path/to/kdrive-rust-sdk
cargo run -p kchat-drive-demo
# → KChat Drive demo server running at http://127.0.0.1:3000
# → Open this URL in your browser to try the encrypt/decrypt demo.
```

Open <http://127.0.0.1:3000> in any browser. The page lets you:

1. Generate a random VersionDEK + node/version/drive/domain IDs + snapshot hash.
2. Paste plaintext (base64-encoded) and encrypt it into chunks.
3. Decrypt the ciphertext back to plaintext and verify it matches.
4. Sign a version header with an Ed25519 key and verify the signature.

### 1.2 HTTP endpoints

| Method | Path | Returns | Purpose |
| --- | --- | --- | --- |
| `GET` | `/` | `text/html` | Demo page (`INDEX_HTML` in `html.rs`) |
| `GET` | `/api/health` | `{"status":"ok","protocol":1,"suite":1}` | Health check |
| `GET` | `/api/generate-key` | `{"version_dek":"..."}` | Random 32-byte DEK (hex) |
| `GET` | `/api/generate-ids` | `{node_id, version_id, drive_id, domain_id, access_context_revision, access_context_snapshot_hash}` | Random 16-byte IDs + snapshot hash |
| `GET` | `/api/test-vectors` | `all_vectors_json()` | KDRV1 cross-language test vectors |
| `POST` | `/api/encrypt` | `{chunk_plan_root, chunk_count, ciphertexts, manifest_ciphertext, manifest_nonce, header_cbor, ...}` | Encrypt plaintext into chunks + manifest + header |
| `POST` | `/api/decrypt` | `{"plaintext_base64":"..."}` | Decrypt chunks back to plaintext |
| `POST` | `/api/sign-header` | `{signed_header_cbor_hex, signature_hex, verifying_key_hex}` | Sign a version header with Ed25519 |
| `POST` | `/api/verify-header` | `{"valid":true/false}` | Verify a header signature |

All responses set `Access-Control-Allow-Origin: *` so you can call the API
from a browser on a different origin. The request body for `/api/encrypt` is
JSON with `version_dek`, `node_id`, `version_id`, `drive_id`, `domain_id`,
`access_context_revision`, `access_context_snapshot_hash` (all hex), and
`plaintext_base64`.

### 1.3 What it verifies

- The KDRV1 chunk AEAD pipeline produces self-consistent ciphertext + chunk
  plan + manifest.
- `encrypt_file` → `decrypt_file` round-trips byte-for-byte.
- Ed25519 header signing + verification works.
- The cross-language test vectors are served correctly (compare with the Go
  gateway's `/v1/vectors`).

The native demo does **not** exercise the privacy-mode key wrapping (DomainKey
/ ShareGrantKey) or the MLS bridge — those are demonstrated in the web sample.

### 1.4 Quick curl smoke test

```bash
# Start the server in one terminal:
cargo run -p kchat-drive-demo &

# Health check:
curl http://127.0.0.1:3000/api/health
# → {"status":"ok","protocol":1,"suite":1}

# Generate a key:
curl http://127.0.0.1:3000/api/generate-key
# → {"version_dek":"a1b2c3..."}

# Test vectors:
curl http://127.0.0.1:3000/api/test-vectors | python3 -m json.tool | head -20
```

## 2. Web sample (`web-sample/`)

A React 18 + Vite 6 + TypeScript app that loads the SDK as WebAssembly and
talks to the Go gateway from the sibling `kdrive` repo. This is the
full-featured demo that exercises all three privacy modes, key wrapping, and
cross-language vector verification.

### 2.1 Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | stable (1.75+) | `rustup default stable` |
| `wasm-pack` | latest | `cargo install wasm-pack` |
| `wasm32-unknown-unknown` target | — | `rustup target add wasm32-unknown-unknown` |
| Node.js | 18+ | — |
| Docker | latest | For Postgres + Go gateway |
| Go | 1.22+ | Only if running gateway natively |

### 2.2 Full setup

#### Step 1 — Start Postgres + Go gateway

```bash
cd /path/to/kdrive

# Start both Postgres and the gateway in Docker:
docker compose -f deploy/dev/docker-compose.yml up -d

# Verify:
curl http://localhost:8080/healthz          # → "ok"
curl http://localhost:8080/v1/tenants | python3 -m json.tool
# → { "tenants": [ { "id": "tenant_acme", ... }, ... ] }
```

The gateway auto-runs migrations on startup, including the demo seed
(`deploy/migrations/003_drive_demo.sql`) which creates 4 tenants, 10 root
folders, and 13 demo users.

**Alternative — run gateway natively** (faster iteration):

```bash
docker compose -f deploy/dev/docker-compose.yml up -d postgres
go run ./cmd/drive-gateway -addr :8080
```

#### Step 2 — Build the WASM package

```bash
cd /path/to/kdrive-rust-sdk
rustup target add wasm32-unknown-unknown

# If wasm-pack fails with "target not found", put rustup's toolchain first:
PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
  wasm-pack build crates/kchat-drive-wasm \
    --target web \
    --out-dir pkg \
    -- --features mls-js

# Verify:
ls crates/kchat-drive-wasm/pkg/
# → kchat_drive_wasm.js, kchat_drive_wasm_bg.wasm, .d.ts files
```

#### Step 3 — Copy WASM into the web sample

```bash
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.js           web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm       web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.d.ts          web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm.d.ts  web-sample/src/wasm/
```

WASM files live under `src/wasm/` (not `public/`) so Vite processes the JS
glue as an ES module and resolves the `.wasm` binary via `import.meta.url`.

#### Step 4 — Start the React dev server

```bash
cd web-sample
npm install   # first time only
npm run dev
```

Open <http://localhost:5173>. You should see:

- **WASM: Ready** (green badge)
- **Gateway: Connected** (green badge)
- A row of 13 demo user cards
- Four tabs: Folders, Upload, Scenarios, Vectors

### 2.3 Demo tenants & users

The seed migration creates:

| Tenant | Type | Users | Folders |
| --- | --- | --- | --- |
| `tenant_b2c` | B2C | Alice (owner), Bob (member) | `folder_b2c_personal` (Max only) |
| `tenant_acme` | B2B | Alice (owner), Bob (member), Charlie (late joiner), Dana (admin) | secured, advanced, max |
| `tenant_globex` | B2B | Eve (owner), Frank (member), Grace (admin) | secured, advanced, max |
| `tenant_initech` | B2B | Heidi (owner), Ivan (member), Judy (admin) | secured, advanced, max |

Folder names use the demo convention: 16 zero bytes + ASCII name, hex-encoded
in the DB and base64 in JSON. `FolderTree.tsx` decodes this for display.

### 2.4 Tabs

| Tab | What it shows |
| --- | --- |
| **Folders** | Expandable tree of folders + files for the selected user's tenant. Mode badges: blue=Secured, yellow=Advanced, red=Max. |
| **Upload** | Manual encrypt + upload form. Pick a folder (auto-sets privacy mode), type plaintext, click **Encrypt & Upload**. Runs the full pipeline: generate DEK → encrypt → wrap DEK → create node → initiate session → register chunks → verify round-trip. |
| **Scenarios** | Six automated end-to-end tests (see below). Filtered by tenant type — B2C users see only B2C-relevant scenarios. |
| **Vectors** | Cross-language test vector comparison between Rust (WASM) and Go gateway. Verifies `protocol`, `version`, `suite` match. |

### 2.5 Scenarios

#### Scenario 1 — Upload in each privacy mode (B2B only)

For each mode (Secured, Advanced, Max):

1. Generate VersionDEK + IDs.
2. `encrypt_file_wasm` → chunk plan + ciphertexts.
3. Wrap DEK:
   - Secured/Advanced → `generate_domain_key_wasm` → `wrap_dek_under_domain_key`
   - Max → `generate_share_grant_key_wasm` → `wrap_dek_under_share_grant_key`
4. Unwrap DEK and verify it matches the original.
5. `createNode` → `initiateUpload` → `registerChunk` (per chunk) on the
   gateway.

**Expected**: All three modes pass — crypto wrap/unwrap OK + gateway upload OK.

**Evidence**: `{mode, chunk_root, dek_prefix, wrap_type, node_id}`.

#### Scenario 2 — New user joins, history access (B2B only)

1. Owner encrypts "History test — version 1".
2. **Secured**: late joiner receives the DomainKey → `decrypt_file_wasm`
   succeeds → late joiner can read history. ✅
3. **Max**: late joiner only gets a ShareGrantKey at epoch 2; the old version
   was wrapped under the epoch 1 key → late joiner cannot decrypt history. ✅
   (by design).

**Expected**: Secured history access ✅, Max no-history ✅.

#### Scenario 3 — Admin recovery attempt (B2B only)

1. Encrypt a file.
2. **Secured**: admin has the DomainKey → `unwrap_dek_from_domain_key`
   succeeds → recovery works. ✅
3. **Max**: admin does not have the ShareGrantKey → attempts unwrap with a
   wrong key → AES-256-GCM tag verification fails → recovery denied. ✅

**Expected**: Secured admin recovery ✅, Max admin blocked ✅.

#### Scenario 4 — User removed, can't read new versions (B2B + B2C)

1. Epoch 1: user is a recipient → `generate_share_grant_key_wasm` with
   `[userId]`.
2. Epoch 2: user removed → `generate_share_grant_key_wasm` with
   `["other_user"]`.
3. New DEK wrapped under the epoch 2 key.
4. Removed user attempts `unwrap_dek_from_share_grant_key` with their old
   epoch 1 key → fails. ✅

**Expected**: Unwrap fails — old key cannot decrypt new versions.

#### Scenario 5 — B2C zone, Max only (B2C only)

For each mode (Secured, Advanced, Max):

- **Secured/Advanced**: client-side policy rejects the wrap before any crypto
  operation. ✅ (rejected by `client_policy`)
- **Max**: `generate_share_grant_key_wasm` → `wrap_dek_under_share_grant_key`
  → `unwrap_dek_from_share_grant_key` round-trips. ✅

**Expected**: Secured rejected ✅, Advanced rejected ✅, Max allowed ✅.

#### Scenario 6 — Cross-language vector check (B2B + B2C)

1. Fetch Rust vectors via `get_test_vectors_json()`.
2. Fetch Go vectors via `GET /v1/vectors`.
3. Compare `protocol` (`kdrv1`) and `version` (`1`).
4. Run a local `encrypt_file_wasm` → `decrypt_file_wasm` round-trip and
   verify plaintext matches.

**Expected**: Protocol match ✅, version match ✅, round-trip ✅.

### 2.6 Walkthrough: B2B demo (Acme Corp)

1. Select **Alice (Acme Owner)** from the user switcher.
2. **Folders** → expand all three folders (Secured, Advanced, Max).
3. **Upload** → select `folder_acme_secured` → type a message → click
   **Encrypt & Upload** → verify all steps show ✅.
4. **Folders** → expand `folder_acme_secured` → your uploaded file appears.
5. **Scenarios** → run each:
   - Scenario 1: all three modes pass.
   - Scenario 2: Secured history ✅, Max no-history ✅.
   - Scenario 3: Secured admin recovery ✅, Max blocked ✅.
   - Scenario 4: removed user cannot decrypt ✅.
   - Scenario 6: vectors match ✅.
6. Switch to **Charlie (Acme Late Joiner)** → run Scenario 2 to see the
   late-joiner perspective.
7. Switch to **Dana (Acme Admin)** → run Scenario 3 to see admin recovery.

### 2.7 Walkthrough: B2C demo (B2C Zone)

1. Select **Alice (B2C Owner)**.
2. **Folders** → expand "My Files" (Max only).
3. **Upload** → only `folder_b2c_personal` is available → type a message →
   **Encrypt & Upload** → verify ✅.
4. **Scenarios** → only 3 scenarios are visible (4, 5, 6):
   - Scenario 4: user removal forward secrecy ✅.
   - Scenario 5: B2C Max-only enforcement ✅.
   - Scenario 6: vectors match ✅.
5. **Vectors** → verify protocol + version match.

### 2.8 Reset demo data

```bash
# Stop + wipe Postgres volume:
docker compose -f deploy/dev/docker-compose.yml down -v

# Start fresh (gateway re-runs migrations + seed):
docker compose -f deploy/dev/docker-compose.yml up -d
```

To clear browser-side keys (IndexedDB):

1. DevTools → Application → IndexedDB → `kchat-drive-demo`
2. Right-click → Delete database
3. Refresh the page (new Ed25519 keypairs will be generated).

### 2.9 Troubleshooting

| Symptom | Fix |
| --- | --- |
| "WASM Load Error: HTTP status code is not ok" | Ensure WASM files are in `src/wasm/` (not `public/`); ensure `Cross-Origin-Resource-Policy: same-origin` is set in `vite.config.ts`. |
| "Cannot convert 1 to a BigInt" | All `u64` WASM parameters require `bigint` literals (`1n`, not `1`). |
| "invalid recipient id: Invalid character 'u'" | `generate_share_grant_key_wasm` expects hex-encoded `UserId` values (16-byte `OpaqueId`). Use `sha256_hex(userId).slice(0, 32)` to convert string IDs. |
| Gateway not connected | Verify Postgres is running: `docker compose -f deploy/dev/docker-compose.yml ps`. Verify gateway: `curl http://localhost:8080/healthz`. |
| Scenario 1 fails for B2C user | B2C tenants only have Max-mode folders. Scenarios 1–3 (which test all three modes) are B2B-only. Switch to an Acme/Globex/Initech user. |
| `wasm-pack` fails with "target not found" | Put rustup's toolchain `bin` first in `PATH` so `wasm-pack` uses rustup's rustc instead of any Homebrew-installed Rust. |

## 3. WASM API reference (for the web sample)

All functions are defined in `crates/kchat-drive-wasm/src/crypto.rs` +
`types.rs` and exposed via `#[wasm_bindgen]`. Complex returns are JSON strings;
plaintext is `Uint8Array`; `u64` parameters are `bigint`.

| Function | Parameters | Returns | Purpose |
| --- | --- | --- | --- |
| `generate_version_dek()` | — | `string` (hex) | Random 32-byte DEK |
| `generate_domain_key_wasm(domain_id_hex)` | 16-byte hex ID | `{domain_key_hex, generation}` | Derive domain key |
| `rotate_domain_key_wasm(current_key_hex, domain_id_hex, current_generation)` | hex key + ID + `bigint` gen | `{domain_key_hex, generation, prev_envelope_hex, prev_envelope_nonce_hex}` | Rotate domain key |
| `generate_share_grant_key_wasm(grant_id_hex, recipients_json, snapshot_hash_hex, mls_epoch, tree_hash_hex)` | hex IDs + JSON array + `bigint` epoch | `{share_grant_key_hex, generation}` | Generate MLS-derived share grant key |
| `encrypt_file_wasm(...)` | DEK, node/version/drive/domain IDs, `bigint` revision, snapshot hash, `Uint8Array` plaintext | JSON: chunk plan, ciphertexts, chunks | Encrypt file into chunks |
| `decrypt_file_wasm(...)` | Same + chunk plan JSON + ciphertexts JSON | `Uint8Array` | Decrypt chunks back to plaintext |
| `encrypt_manifest_wasm(version_dek_hex, node_id_hex, version_id_hex, manifest_cbor_hex)` | hex inputs | `{manifest_ciphertext_hex, manifest_nonce_hex}` | Encrypt manifest |
| `decrypt_manifest_wasm(...)` | hex inputs | `string` (hex CBOR) | Decrypt manifest |
| `wrap_dek_under_domain_key(domain_key_hex, dek_hex)` | Two hex keys | `{wrapped_dek_hex, wrap_nonce_hex}` | Wrap DEK for Secured/Advanced |
| `unwrap_dek_from_domain_key(...)` | Domain key + wrapped DEK + nonce | `string` (hex DEK) | Unwrap DEK |
| `wrap_dek_under_share_grant_key(sgk_hex, dek_hex)` | Two hex keys | `{wrapped_dek_hex, wrap_nonce_hex}` | Wrap DEK for Max |
| `unwrap_dek_from_share_grant_key(...)` | SGK + wrapped DEK + nonce | `string` (hex DEK) | Unwrap DEK |
| `sign_header_wasm(header_cbor_hex, signing_key_hex)` | CBOR header + Ed25519 key | `{signed_header_cbor_hex, signature_hex, verifying_key_hex}` | Sign manifest header |
| `verify_header_wasm(header_cbor_hex, verifying_key_hex)` | CBOR header + pubkey | `boolean` | Verify signature |
| `generate_hpke_keypair()` | — | `{private_key_hex, public_key_hex}` | HPKE keypair |
| `generate_ed25519_keypair()` | — | `{private_key_hex, public_key_hex}` | Ed25519 keypair |
| `random_id_hex()` | — | `string` (32-char hex) | Random 16-byte opaque ID |
| `sha256_hex(data: Uint8Array)` | Bytes | `string` (hex) | SHA-256 hash |
| `select_chunk_size(file_size: bigint)` | File size | `bigint` | KDRV1 chunk sizing |
| `chunk_count(file_size: bigint, chunk_size: bigint)` | Sizes | `bigint` | Chunk count |
| `get_test_vectors_json()` | — | `string` (JSON) | KDRV1 cross-language test vectors |

> **Important:** All `u64` Rust parameters become `bigint` in JavaScript. Pass
> `1n` (not `1`) for values like `access_context_revision` and `mls_epoch`.

## 4. Gateway API endpoints (used by the web sample)

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/v1/tenants` | List all demo tenants |
| `GET` | `/v1/folders?parent=` | List folders (root if parent empty) |
| `POST` | `/v1/folders` | Create a folder |
| `GET` | `/v1/folders/{id}/children` | Get folder + sub-folders + nodes |
| `POST` | `/v1/folders/{id}/children` | Create a node (file) in folder |
| `POST` | `/v1/uploads:initiate` | Start an upload session |
| `POST` | `/v1/uploads/{sid}/chunks/{ordinal}:register` | Register a chunk |
| `POST` | `/v1/versions/{vid}:authorizeDownload` | Authorize a download |
| `GET` | `/v1/vectors` | KDRV1 test vectors |
| `POST` | `/v1/nodes/{id}/shares` | Create a share grant |
| `DELETE` | `/v1/shares/{id}` | Revoke a share grant |

All endpoints accept `X-Demo-Tenant` and `X-Demo-User` headers for demo
multi-tenancy routing. API requests are proxied through Vite
(`/v1` → `http://localhost:8080`) to avoid CORS issues during development.

## 5. Cross-origin isolation

The Vite dev server sets these headers (required for `SharedArrayBuffer` and
threaded WASM):

```
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

The Go gateway sets `Access-Control-Allow-Origin: *` and related CORS headers
on all `/v1/` endpoints.
