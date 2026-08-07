# KChat Drive — Web Sample

A React + TypeScript frontend that demonstrates the KChat Drive Rust SDK compiled to
WebAssembly. The app showcases end-to-end encrypted file uploads with three privacy
modes (Secured, Advanced, Max), backed by a Go gateway with Postgres metadata storage.

## Quick Start

### Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| Rust | stable (1.75+) | Install via [rustup](https://rustup.rs) |
| `wasm-pack` | latest | `cargo install wasm-pack` |
| `wasm32-unknown-unknown` target | — | `rustup target add wasm32-unknown-unknown` |
| Node.js | 18+ | — |
| Docker | latest | For Postgres + Go gateway |
| Go | 1.22+ | Only if running gateway natively |

### 1. Start Postgres + Go Gateway

```bash
# From the kdrive repo root:
docker compose -f deploy/dev/docker-compose.yml up -d

# Verify:
curl http://localhost:8080/healthz   # → "ok"
curl http://localhost:8080/v1/tenants # → JSON tenant list
```

The gateway auto-runs migrations on startup, including the demo seed data
(`deploy/migrations/003_drive_demo.sql`) which creates demo tenants, folders,
and users.

**Alternative — run gateway natively** (useful for development):

```bash
# Start only Postgres:
docker compose -f deploy/dev/docker-compose.yml up -d postgres

# Run gateway natively:
cd /path/to/kdrive
go run ./cmd/drive-gateway -addr :8080
```

### 2. Build the WASM Package

```bash
cd /path/to/kdrive-rust-sdk

# Build with the mls-js feature for browser MLS support:
PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
  wasm-pack build crates/kchat-drive-wasm \
    --target web \
    --out-dir pkg \
    -- --features mls-js
```

> **Note:** If `wasm-pack` fails with "target not found", ensure the rustup
> toolchain's `bin` directory is first in `PATH` so `wasm-pack` uses rustup's
> rustc instead of any Homebrew-installed Rust.

### 3. Copy WASM Package into Web Sample

```bash
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.js      web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm  web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.d.ts     web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm.d.ts web-sample/src/wasm/
```

The WASM files live under `src/wasm/` (not `public/`) so that Vite processes
the JS glue as an ES module and resolves the `.wasm` binary via
`import.meta.url`.

### 4. Install Dependencies & Start Dev Server

```bash
cd web-sample
npm install
npm run dev
```

Open **http://localhost:5173**.

### 5. Verify Everything Works

1. The header should show **WASM: Ready** and **Gateway: Connected**.
2. Click the **Folders** tab — you should see seed folders (Secured, Advanced, Max).
3. Click the **Vectors** tab — protocol `kdrv1` and version `1` should match
   between Rust and Go.
4. Switch to **Alice (Acme Owner)** → **Scenarios** tab → run Scenario 1.

## Project Structure

```
web-sample/
├── index.html              # Vite entry point
├── package.json            # React 18 + Vite 6 + lucide-react
├── vite.config.ts          # COOP/COEP/CORP headers + gateway proxy
├── tsconfig.json
├── src/
│   ├── App.tsx             # Root component — user switcher + tab navigation
│   ├── api.ts             # Gateway REST client (fetch-based)
│   ├── types.ts           # TypeScript interfaces (Folder, Node, Tenant, etc.)
│   ├── vault.ts           # IndexedDB key vault (domain keys, share grant keys)
│   ├── wasm-loader.ts     # Dynamic WASM import + singleton cache
│   ├── vite-env.d.ts      # WasmExports interface — all WASM function signatures
│   ├── demo-data.ts       # Demo tenants, users, and scenario definitions
│   ├── styles.css         # Dark theme styles
│   ├── wasm/              # Built WASM package (copied from pkg/)
│   │   ├── kchat_drive_wasm.js
│   │   ├── kchat_drive_wasm_bg.wasm
│   │   └── kchat_drive_wasm.d.ts
│   └── components/
│       ├── UserSwitcher.tsx   # Horizontal user picker (13 demo users)
│       ├── FolderTree.tsx     # Expandable folder/file tree view
│       ├── UploadView.tsx     # Manual encrypt + upload form
│       ├── ScenarioPanel.tsx  # 6 automated demo scenarios
│       └── VectorCheck.tsx    # Cross-language test vector comparison
```

## WASM Functions Exposed

All functions are defined in `crates/kchat-drive-wasm/src/crypto.rs` and
`types.rs`, then exposed via `#[wasm_bindgen]`.

| Function | Parameters | Returns | Purpose |
| --- | --- | --- | --- |
| `generate_version_dek()` | — | `string` (hex) | Generate a 32-byte random DEK |
| `generate_domain_key_wasm(domain_id_hex)` | 16-byte hex ID | `{ domain_key_hex }` | Derive domain key from domain ID |
| `encrypt_file_wasm(...)` | DEK, node/version/drive/domain IDs, `bigint` revision, snapshot hash, plaintext `Uint8Array` | JSON: chunk plan, ciphertexts, chunks | Encrypt file into chunks |
| `decrypt_file_wasm(...)` | Same + chunk plan JSON + ciphertexts JSON | `Uint8Array` | Decrypt chunks back to plaintext |
| `wrap_dek_under_domain_key(domain_key_hex, dek_hex)` | Two hex keys | `{ wrapped_dek_hex, wrap_nonce_hex }` | Wrap DEK for Secured/Advanced |
| `unwrap_dek_from_domain_key(...)` | Domain key + wrapped DEK + nonce | `string` (hex DEK) | Unwrap DEK |
| `wrap_dek_under_share_grant_key(sgk_hex, dek_hex)` | Share grant key + DEK | `{ wrapped_dek_hex, wrap_nonce_hex }` | Wrap DEK for Max mode |
| `unwrap_dek_from_share_grant_key(...)` | SGK + wrapped DEK + nonce | `string` (hex DEK) | Unwrap DEK |
| `generate_share_grant_key_wasm(...)` | Grant ID, recipients JSON, snapshot hash, `bigint` epoch, tree hash | `{ share_grant_key_hex, generation }` | Generate MLS-derived share grant key |
| `sign_header_wasm(header_cbor_hex, signing_key_hex)` | CBOR header + Ed25519 key | `{ signed_header_cbor_hex, signature_hex, verifying_key_hex }` | Sign manifest header |
| `verify_header_wasm(header_cbor_hex, verifying_key_hex)` | CBOR header + pubkey | `boolean` | Verify signature |
| `generate_hpke_keypair()` | — | `{ private_key_hex, public_key_hex }` | HPKE keypair |
| `generate_ed25519_keypair()` | — | `{ private_key_hex, public_key_hex }` | Ed25519 keypair |
| `random_id_hex()` | — | `string` (32-char hex) | Random 16-byte opaque ID |
| `sha256_hex(data: Uint8Array)` | Bytes | `string` (hex) | SHA-256 hash |
| `select_chunk_size(file_size: bigint)` | File size | `bigint` | KDRV1 chunk sizing |
| `chunk_count(file_size: bigint, chunk_size: bigint)` | Sizes | `bigint` | Chunk count |
| `get_test_vectors_json()` | — | `string` (JSON) | KDRV1 cross-language test vectors |

> **Important:** All `u64` Rust parameters become `bigint` in JavaScript. Pass
> `1n` (not `1`) for values like `access_context_revision` and `mls_epoch`.

## Gateway API Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/tenants` | List all demo tenants |
| GET | `/v1/folders?parent=` | List folders (root if parent empty) |
| POST | `/v1/folders` | Create a folder |
| GET | `/v1/folders/{id}/children` | Get folder + sub-folders + nodes |
| POST | `/v1/folders/{id}/children` | Create a node (file) in folder |
| POST | `/v1/uploads:initiate` | Start an upload session |
| POST | `/v1/uploads/{sid}/chunks/{ordinal}:register` | Register a chunk |
| POST | `/v1/versions/{vid}:authorizeDownload` | Authorize a download |
| GET | `/v1/vectors` | KDRV1 test vectors |
| POST | `/v1/nodes/{id}/shares` | Create a share grant |
| DELETE | `/v1/shares/{id}` | Revoke a share grant |

All endpoints accept `X-Demo-Tenant` and `X-Demo-User` headers for demo
multi-tenancy routing.

## Cross-Origin Isolation

The Vite dev server sets these headers (required for `SharedArrayBuffer` and
threaded WASM):

```
Cross-Origin-Opener-Policy:   same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

The Go gateway also sets `Access-Control-Allow-Origin: *` and related CORS
headers on all `/v1/` endpoints. API requests are proxied through Vite
(``/v1` → `http://localhost:8080``) to avoid CORS issues during development.

## Troubleshooting

**"WASM Load Error: HTTP status code is not ok"**
- Ensure WASM files are in `src/wasm/` (not `public/`)
- Ensure `Cross-Origin-Resource-Policy: same-origin` header is set in
  `vite.config.ts`

**"Cannot convert 1 to a BigInt"**
- All `u64` WASM parameters require `bigint` literals (`1n`, not `1`)

**"invalid recipient id: Invalid character 'u'"**
- `generate_share_grant_key_wasm` expects hex-encoded `UserId` values (16-byte
  `OpaqueId`). Use `sha256_hex(userId).slice(0, 32)` to convert string IDs.

**Gateway not connected**
- Verify Postgres is running: `docker compose -f deploy/dev/docker-compose.yml ps`
- Verify gateway: `curl http://localhost:8080/healthz`

**Scenario 1 fails for B2C user**
- B2C tenants only have Max-mode folders. Scenarios 1–3 (which test all three
  modes) are B2B-only. Switch to an Acme/Globex/Initech user.
