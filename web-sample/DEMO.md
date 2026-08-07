# KChat Drive — Demo Setup & Scenarios

This guide walks through setting up the full demo environment and running each
scenario with expected results and explanations.

## Full Setup

### Step 1: Start Postgres + Go Gateway

```bash
cd /path/to/kdrive

# Start both Postgres and gateway in Docker:
docker compose -f deploy/dev/docker-compose.yml up -d

# Wait for health check:
docker compose -f deploy/dev/docker-compose.yml ps

# Verify gateway is up:
curl http://localhost:8080/healthz
# → "ok"

# Verify demo data is seeded:
curl http://localhost:8080/v1/tenants | python3 -m json.tool
# → { "tenants": [ { "id": "tenant_acme", ... }, ... ] }
```

**Alternative — run gateway natively** (faster iteration):

```bash
# Start only Postgres:
docker compose -f deploy/dev/docker-compose.yml up -d postgres

# Run gateway from source:
go run ./cmd/drive-gateway -addr :8080
```

The gateway auto-migrates on startup. The demo seed migration
(`deploy/migrations/003_drive_demo.sql`) creates:

- 4 tenants (1 B2C, 3 B2B)
- 10 root folders (3 per B2B tenant + 1 B2C)
- 13 demo users with roles (owner, member, latejoiner, admin)

### Step 2: Build the WASM Package

```bash
cd /path/to/kdrive-rust-sdk

# Ensure the wasm32 target is installed:
rustup target add wasm32-unknown-unknown

# Build (use rustup's toolchain if Homebrew Rust interferes):
PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
  wasm-pack build crates/kchat-drive-wasm \
    --target web \
    --out-dir pkg \
    -- --features mls-js
```

Verify the build succeeded:

```bash
ls crates/kchat-drive-wasm/pkg/
# → kchat_drive_wasm.js, kchat_drive_wasm_bg.wasm, .d.ts files
```

### Step 3: Copy WASM to Web Sample

```bash
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.js           web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm       web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm.d.ts          web-sample/src/wasm/
cp crates/kchat-drive-wasm/pkg/kchat_drive_wasm_bg.wasm.d.ts  web-sample/src/wasm/
```

### Step 4: Start the React Dev Server

```bash
cd web-sample
npm install   # first time only
npm run dev
```

### Step 5: Open the App

Navigate to **http://localhost:5173**. You should see:

- **WASM: Ready** (green badge in header)
- **Gateway: Connected** (green badge in header)
- A row of 13 demo user cards
- Four tabs: Folders, Upload, Scenarios, Vectors

## Demo Tenants & Users

### B2C Zone (`tenant_b2c`)

| User | Role | Notes |
| --- | --- | --- |
| Alice | Owner | B2C zone, Max-only mode |
| Bob | Member | B2C zone, Max-only mode |

Folders: `folder_b2c_personal` (Max mode only)

### Acme Corp (`tenant_acme`)

| User | Role | Notes |
| --- | --- | --- |
| Alice | Owner | Full access |
| Bob | Member | Standard access |
| Charlie | Late Joiner | Joins after files exist — tests history access |
| Dana | Admin | Tests admin recovery |

Folders: `folder_acme_secured`, `folder_acme_advanced`, `folder_acme_max`

### Globex (`tenant_globex`)

| User | Role | Notes |
| --- | --- | --- |
| Eve | Owner | Full access |
| Frank | Member | Standard access |
| Grace | Admin | Tests admin recovery |

Folders: `folder_globex_secured`, `folder_globex_advanced`, `folder_globex_max`

### Initech (`tenant_initech`)

| User | Role | Notes |
| --- | --- | --- |
| Heidi | Owner | Full access |
| Ivan | Member | Standard access |
| Judy | Admin | Tests admin recovery |

Folders: `folder_initech_secured`, `folder_initech_advanced`, `folder_initech_max`

## Tab Guide

### 1. User Switcher (top bar)

Click any user card to switch context. All tabs below show data for the
selected user's tenant. The active user is highlighted with a purple border.

### 2. Folders Tab

Shows an expandable tree of folders and files for the selected user's tenant.

- Click a folder to expand/collapse and see its sub-folders and files
- Each folder shows a colored **mode badge** (blue=Secured, yellow=Advanced,
  red=Max)
- File names are decoded from the demo encryption format (16-byte zero prefix
  + ASCII name)
- Files uploaded via the Upload tab or Scenarios appear here in real-time

### 3. Upload Tab

Manually encrypt and upload a file to the gateway.

1. **Folder dropdown** — shows only folders for the selected user's tenant.
   Selecting a folder auto-sets the privacy mode to match.
2. **Privacy Mode** — auto-set from the folder. Changing it to a mismatched
   mode shows a warning (the folder's mode is authoritative).
3. **File content** — textarea with the plaintext to encrypt.
4. **Encrypt & Upload** button — runs the full pipeline:
   - Generate VersionDEK
   - Encrypt file with WASM (`encrypt_file_wasm`)
   - Wrap DEK (domain key for Secured/Advanced, share grant key for Max)
   - Create node on gateway
   - Initiate upload session
   - Register each chunk
   - Verify round-trip decryption locally
5. **Log output** — step-by-step log with ✅/❌ indicators

### 4. Scenarios Tab

Automated end-to-end tests. Scenarios are filtered by tenant type — B2C users
see only B2C-relevant scenarios, B2B users see B2B scenarios.

### 5. Vectors Tab

Cross-language test vector verification. Compares the KDRV1 protocol version
and cryptographic vectors between the Rust WASM SDK and the Go gateway.

## Scenarios

### Scenario 1: Upload in Each Privacy Mode (B2B only)

**Tests**: End-to-end upload for all three privacy modes.

**Steps**:
1. Fetch available folders for the tenant from the gateway
2. For each mode (Secured, Advanced, Max):
   a. Generate a VersionDEK
   b. Encrypt "Scenario 1 test data" with `encrypt_file_wasm`
   c. Wrap DEK:
      - Secured/Advanced: `wrap_dek_under_domain_key`
      - Max: `generate_share_grant_key_wasm` → `wrap_dek_under_share_grant_key`
   d. Unwrap DEK and verify it matches the original
   e. Create node on gateway (`POST /v1/folders/{id}/children`)
   f. Initiate upload session (`POST /v1/uploads:initiate`)
   g. Register each chunk (`POST /v1/uploads/{sid}/chunks/{i}:register`)

**Expected result**: All three modes pass — crypto wrap/unwrap OK + gateway
upload OK.

**What it demonstrates**: The DEK wrapping mechanism differs by mode:
- Secured/Advanced: Domain Key wrap (shared group key)
- Max: Share Grant Key wrap (per-epoch MLS-derived key)

**Evidence shown**:
```json
{
  "mode": "secured",
  "chunk_root": "3fd97e2a...",
  "dek_prefix": "e0b47fa8...",
  "wrap_type": "domain",
  "node_id": "node_..."
}
```

---

### Scenario 2: New User Joins — History Access (B2B only)

**Tests**: Late joiner access to existing file versions.

**Steps**:
1. Encrypt a file as "History test — version 1"
2. In Secured mode:
   a. Generate domain key
   b. Late joiner receives domain key
   c. Late joiner decrypts the file → **success** (domain key chain allows
      backward walk)
3. In Max mode:
   a. Generate share grant key at epoch 2 (late joiner included)
   b. Late joiner only has epoch 2 key, not epoch 1
   c. Late joiner **cannot** decrypt version 1 → history access denied

**Expected result**:
- Secured: late joiner CAN decrypt history ✅
- Max: late joiner CANNOT decrypt history ✅ (this is by design)

**What it demonstrates**: The fundamental trade-off between Secured (history
accessible to new members) and Max (forward-only access for new members).

---

### Scenario 3: Admin Recovery Attempt (B2B only)

**Tests**: Whether an admin can recover (decrypt) a deleted file version.

**Steps**:
1. Encrypt a file
2. In Secured mode:
   a. Admin has domain key → can decrypt → **recovery succeeds**
3. In Advanced mode:
   a. Admin has domain key but no MLS epoch key → **recovery fails**
4. In Max mode:
   a. Admin has no share grant key → **recovery fails**

**Expected result**:
- Secured: admin CAN recover ✅ (domain key available)
- Advanced: admin CANNOT recover ✅ (MLS forward secrecy)
- Max: admin CANNOT recover ✅ (no MLS key at all)

**What it demonstrates**: Secured mode trades admin recoverability for
convenience. Advanced and Max modes provide stronger isolation — even admins
cannot decrypt content without the appropriate MLS epoch keys.

---

### Scenario 4: User Removed — Can't Read New Versions (B2B + B2C)

**Tests**: Forward secrecy after user removal.

**Steps**:
1. Generate share grant key at epoch 1 (user is a recipient)
2. Generate share grant key at epoch 2 (user is removed — not in recipients)
3. Wrap a new DEK under the epoch 2 key
4. Removed user attempts to unwrap with their epoch 1 key → **fails**

**Expected result**: Unwrap fails — the old key cannot decrypt new versions. ✅

**What it demonstrates**: MLS-based key rotation ensures removed users lose
access to all future content. This works the same in all modes that use MLS
(Advanced, Max) and in Secured mode (new domain key generation).

---

### Scenario 5: B2C Zone — Max Only (B2C only)

**Tests**: Client-side enforcement of Max-only policy for B2C tenants.

**Steps**:
1. Attempt to wrap DEK in Secured mode (domain key wrap)
2. Attempt to wrap DEK in Advanced mode (domain key wrap)
3. Attempt to wrap DEK in Max mode (share grant key wrap)

**Expected result**:
- Secured: rejected by client ✅
- Advanced: rejected by client ✅
- Max: allowed ✅

**What it demonstrates**: The B2C zone enforces Max mode for all users. The
client SDK refuses to wrap DEKs in non-Max modes, preventing weaker privacy
guarantees in consumer scenarios.

---

### Scenario 6: Cross-Language Vector Check (B2B + B2C)

**Tests**: Byte-equality of cryptographic outputs between Rust (WASM) and Go.

**Steps**:
1. Fetch test vectors from Rust SDK via `get_test_vectors_json()`
2. Fetch test vectors from Go gateway via `GET /v1/vectors`
3. Compare:
   - Protocol identifier (`kdrv1`)
   - Protocol version (`1`)
   - Suite number (`1`)
4. Run a local encrypt/decrypt round-trip with WASM

**Expected result**:
- Protocol match: ✅ (`kdrv1` = `kdrv1`)
- Version match: ✅ (`1` = `1`)
- Encrypt/decrypt round-trip: ✅ (plaintext matches)

**What it demonstrates**: The KDRV1 protocol is implemented identically in
Rust and Go. Cross-language compatibility means files encrypted by the Rust
SDK can be verified by the Go gateway and vice versa.

---

## Running a Full Demo Walkthrough

### B2B Demo (Acme Corp)

1. Select **Alice (Acme Owner)** from the user switcher
2. Go to **Folders** → expand all three folders (Secured, Advanced, Max)
3. Go to **Upload** → select `folder_acme_secured` → type a message → click
   **Encrypt & Upload** → verify all steps show ✅
4. Go back to **Folders** → expand `folder_acme_secured` → your uploaded file
   should appear
5. Go to **Scenarios** → run each scenario one by one:
   - Scenario 1: All three modes should pass
   - Scenario 2: Secured history access ✅, Max no-history ✅
   - Scenario 3: Secured admin recovery ✅, Advanced/Max blocked ✅
   - Scenario 4: Removed user cannot decrypt ✅
   - Scenario 6: Vectors match ✅
6. Switch to **Charlie (Acme Late Joiner)** → run Scenario 2 to see the
   late-joiner perspective
7. Switch to **Dana (Acme Admin)** → run Scenario 3 to see admin recovery
   behavior

### B2C Demo (B2C Zone)

1. Select **Alice (B2C Owner)** from the user switcher
2. Go to **Folders** → expand "My Files" (Max mode only)
3. Go to **Upload** → the folder dropdown shows only `folder_b2c_personal`
   → type a message → click **Encrypt & Upload** → verify ✅
4. Go to **Scenarios** → only 3 scenarios are visible (4, 5, 6):
   - Scenario 4: User removal forward secrecy ✅
   - Scenario 5: B2C Max-only enforcement ✅
   - Scenario 6: Vectors match ✅
5. Go to **Vectors** → verify protocol and version match

## Reset Demo Data

To reset the database and re-seed:

```bash
# Stop services:
docker compose -f deploy/dev/docker-compose.yml down -v

# Start fresh:
docker compose -f deploy/dev/docker-compose.yml up -d
```

The `-v` flag removes the Postgres volume, so the gateway will re-run all
migrations and seed data on startup.

To clear browser-side keys (IndexedDB):

1. Open DevTools → Application → IndexedDB → `kchat-drive-demo`
2. Right-click → Delete database
3. Refresh the page (new Ed25519 key pairs will be generated)
