# KChat Drive — Intra-Tenant Content Deduplication (KDRV1)

## Status: DRAFT — Pending Approval

## Problem

Same file uploaded multiple times within a tenant (across Secured/Advanced/Max
modes) currently stores N duplicate copies. Root causes:

1. **Per-version AAD** — `ChunkAAD` includes `node_id`, `version_id`,
   `domain_id`, so ciphertext differs per version even with the same key
2. **Random VersionDEK** — fresh 256-bit key per version → different ciphertext
3. **Random blob keys** — `blob_{version_id}_{i}`, not content-addressed
4. **Cross-mode key isolation** — DomainKey vs ShareGrantKey, no shared content
   layer

## Design Decisions (Approved)

| Decision | Choice | Rationale |
| --- | --- | --- |
| ContentKey derivation | Convergent + tenant pepper | Max dedup ratio; any client with pepper can dedup without accessing original mode |
| Crypto format | New KDRV1 (clean break) | No mixed-mode complexity; KDRV1 legacy decrypt path preserved |
| Dedup granularity | File-level + chunk-level | Fast file-level check + partial dedup for similar files |

---

## Architecture

### Two-Layer Encryption

```
Layer 1: Content Encryption (dedup-eligible, mode-independent)
  Plaintext → ContentKey → Content Ciphertext → Content Blob (content-addressed)

Layer 2: Version Binding (per-version, mode-specific)
  VersionDEK wraps ContentKey → Manifest → VersionDEK wrapped by mode key
```

### Key Derivation

```
tenant_pepper
  = 256-bit random, generated once per tenant, stored in key vault
  = Distributed via:
      Secured:  wrapped under DomainKey (tenant recovery can access)
      Advanced: sealed via MLS exporter to group members
      Max:      wrapped under ShareGrantKey per grant

plaintext_sha256
  = SHA-256 of full plaintext (computed client-side, never sent raw)

content_id
  = HMAC-SHA256(tenant_pepper, plaintext_sha256)
  = 32 bytes, base64-encoded for gateway lookup
  = Opaque to gateway (can't compute without pepper)
  = Tenant-scoped (different tenants → different content_id for same plaintext)

ContentKey
  = HKDF-Extract(salt="kchat-drive/content-key/v1", IKM=plaintext_sha256 || tenant_pepper)
  = Deterministic: same plaintext + same pepper → same ContentKey
  = NOT sent to gateway (stays client-side)

ChunkContentKey[i]
  = HKDF-Expand(ContentKey, "kchat-drive/chunk-content-key/v1" || u64be(i), 32)

ChunkContentNonce[i]
  = HKDF-Expand(ContentKey, "kchat-drive/chunk-content-nonce/v1" || u64be(i), 12)

ChunkContentAAD[i]
  = CBOR({
      protocol: "KDRV1",
      suite: suite_id,
      content_id: Hash256,
      chunk_index: u64be(i),
      plaintext_len: u64,
    })
  // NO node_id, version_id, domain_id — purely content-scoped

ContentCipher[i]
  = AES-256-GCM(ChunkContentKey[i], ChunkContentNonce[i], PlainChunk[i], ChunkContentAAD[i])

chunk_content_hash[i]
  = SHA-256(ContentCipher[i])
  = Used as blob key suffix + dedup check

blob_key
  = "blob_{content_id_hex}_{chunk_content_hash_hex}"
  = Content-addressed: same content → same blob key → gateway skips upload
```

### Version Binding (Layer 2)

```
VersionDEK
  = random 256-bit key (per version, unchanged from KDRV1)

version_salt
  = random 256-bit salt (per version, unchanged from KDRV1)

VersionWrapKey
  = HKDF-Extract(version_salt, VersionDEK)
  // Used to wrap ContentKey

wrapped_content_key
  = AES-256-GCM(
      key:  HKDF-Expand(VersionWrapKey, "kchat-drive/content-wrap-key/v1" || version_id, 32),
      nonce: HKDF-Expand(VersionWrapKey, "kchat-drive/content-wrap-nonce/v1" || version_id, 12),
      plaintext: ContentKey,
      aad: version_id || content_id
    )

Manifest (KDRV1)
  = CBOR({
      protocol: "KDRV1",
      suite: suite_id,
      version_id: VersionId,
      node_id: NodeId,
      content_id: Hash256,           // NEW — links to content blobs
      wrapped_content_key: bytes,    // NEW — ContentKey wrapped under VersionDEK
      chunk_plan: ChunkPlan,         // points to content blobs via blob_key
      plaintext_sha256_encrypted: bytes, // encrypted plaintext hash (for verification)
      name_ciphertext: bytes,
      mime_type: Option<String>,
      plaintext_size: u64,
      created_at: u64,
      parent_version_id: Option<VersionId>,
    })

ManifestKey / ManifestNonce
  = Same as KDRV1 (derived from VersionDEK + version_salt + node_id + version_id)

VersionDEK wrapping (under DomainKey/ShareGrantKey)
  = Unchanged from KDRV1
```

### Public Version Header (KDRV1)

```
PublicVersionHeader = CBOR({
  protocol: "KDRV1",
  suite: suite_id,
  version_id: VersionId,
  node_id: NodeId,
  predecessor_version_id: Option<VersionId>,
  domain_id: DomainId,
  access_context_revision: u64,
  access_context_snapshot_hash: Hash256,
  version_salt: [u8; 32],
  content_id: Hash256,              // NEW — public, enables gateway dedup check
  chunk_count: u64,
  chunk_size: u64,
  chunk_plan_root: Hash256,         // Merkle root over chunk descriptors
  manifest_nonce: [u8; 12],
  manifest_ciphertext_sha256: Hash256,
  initial_wrap_set_root: Hash256,
  uploader_device_id: DeviceId,
  device_signer_context: DeviceSignerContext,
  signature: Ed25519Signature,
})
```

### Chunk Plan (KDRV1)

```
ChunkDescriptor = {
  index: u64,
  plaintext_len: u64,
  ciphertext_len: u64,
  ciphertext_sha256: Hash256,       // hash of content ciphertext
  chunk_content_hash: Hash256,      // NEW — same as ciphertext_sha256 for KDRV1
  blob_key: String,                 // "blob_{content_id}_{chunk_content_hash}"
}

ChunkPlanRoot
  = SHA-256("kchat-drive/chunk-plan-root/v2" || u64be(chunk_count) || leaves...)
  // v2 tag to distinguish from KDRV1
```

---

## Dedup Flow

### Upload (with dedup check)

```
Client                          Gateway                     Blob Store
  |                               |                           |
  | 1. Compute plaintext_sha256   |                           |
  | 2. Derive content_id          |                           |
  | 3. Derive ContentKey          |                           |
  |                               |                           |
  | 4. POST /v1/content:check     |                           |
  |    { content_id, tenant }     |                           |
  |------------------------------>|                           |
  |                               |                           |
  | 5. { exists, blob_keys[],     |                           |
  |       ciphertext_hashes[] }   |                           |
  |<------------------------------|                           |
  |                               |                           |
  | 6a. IF EXISTS:                |                           |
  |   - Verify ciphertext hashes  |                           |
  |     (download spot-check or   |                           |
  |      trust gateway response)  |                           |
  |   - Skip chunk encryption     |                           |
  |   - Skip chunk upload         |                           |
  |                               |                           |
  | 6b. IF NOT EXISTS:            |                           |
  |   - Encrypt chunks with       |                           |
  |     ContentKey                |                           |
  |   - Compute chunk_content_hash|                           |
  |   - Upload only NEW blobs     |                           |
  |------------------------------>|-------------------------->|
  |                               |                           |
  | 7. Generate VersionDEK        |                           |
  | 8. Wrap ContentKey under DEK  |                           |
  | 9. Wrap VersionDEK under mode |                           |
  |    key (DomainKey/SGK)        |                           |
  |                               |                           |
  | 10. POST /v1/uploads:commit   |                           |
  |     { manifest, header,       |                           |
  |       wrapped_dek, wraps }    |                           |
  |------------------------------>|                           |
  |                               |                           |
  | 11. { version_id, committed } |                           |
  |<------------------------------|                           |
```

### Chunk-Level Dedup

For files that share some chunks but differ in others (e.g., appended data,
small edits):

```
Client computes per-chunk content hashes:
  chunk_content_hash[i] = SHA-256(ContentCipher[i])

Client sends chunk list to gateway:
  POST /v1/content:checkChunks
  { content_id, chunk_hashes: [h0, h1, h2, ...] }

Gateway responds per chunk:
  { results: [
      { hash: h0, exists: true,  blob_key: "blob_..." },
      { hash: h1, exists: false, blob_key: null },
      { hash: h2, exists: true,  blob_key: "blob_..." },
  ]}

Client uploads only missing chunks (h1 in this example).
```

### Cross-Mode Dedup

```
Scenario: File F uploaded in Secured mode, then shared via Max mode

1. User A uploads F in Secured mode
   - ContentKey derived from plaintext_hash + tenant_pepper
   - Content blobs stored: blob_{content_id}_{chunk_hashes}
   - VersionDEK₁ wraps ContentKey
   - DomainKey wraps VersionDEK₁

2. User B (same tenant) shares F via Max mode
   - Client computes same plaintext_hash → same content_id
   - POST /v1/content:check → EXISTS
   - Client derives same ContentKey (has tenant_pepper)
   - Client verifies content blobs (spot-check hash)
   - Client generates new VersionDEK₂
   - Client wraps ContentKey under VersionDEK₂
   - Client wraps VersionDEK₂ under ShareGrantKey
   - Client creates new manifest pointing to SAME content blobs
   - ZERO chunk uploads — only manifest + key envelope

3. User C receives via Max mode, saves to Advanced folder
   - Same flow: same content_id, same ContentKey
   - New VersionDEK₃, wrapped under Advanced DomainKey
   - ZERO chunk uploads
```

### Tenant Pepper Distribution

```
Initial generation:
  - Tenant admin generates tenant_pepper (256-bit random)
  - Stored in key vault as "tenant_pepper:{tenant_id}"

Secured mode distribution:
  - tenant_pepper wrapped under DomainKey generation 0
  - Stored in key_envelopes with envelope_type = "TENANT_PEPPER"
  - New devices unwrap via DomainKey when joining domain

Advanced mode distribution:
  - tenant_pepper sealed via MLS exporter to group members
  - Delivered as part of KeyDecisionSet when joining group

Max mode distribution:
  - tenant_pepper wrapped under ShareGrantKey
  - Included in share grant key envelope set
  - Recipient unwraps via ShareGrantKey when accepting share

Key rotation:
  - tenant_pepper rotation re-wraps under all active mode keys
  - Old pepper retained for backward compatibility (decrypt old content)
  - content_id uses current pepper generation
  - Gateway stores content_id → pepper_generation mapping
```

---

## Gateway Changes

### New API Endpoints

```
POST /v1/content:check
  Request:  { content_id: string }
  Response: {
    exists: bool,
    blob_keys: [string],
    ciphertext_hashes: [string],
    chunk_count: u64,
    plaintext_size: u64,
  }
  Auth: tenant-scoped token
  Notes: Only checks within caller's tenant

POST /v1/content:checkChunks
  Request:  {
    content_id: string,
    chunk_hashes: [string],
  }
  Response: {
    results: [{
      hash: string,
      exists: bool,
      blob_key: string | null,
    }]
  }
  Auth: tenant-scoped token

POST /v1/uploads:commit (extended)
  New fields:
    - content_id: string (required for KDRV1)
    - protocol: "KDRV1" (new value)
    - reused_blob_keys: [string] (blobs reused from existing content)
  Gateway validates:
    - All reused blob keys exist in blob_placements
    - All reused blob keys belong to same tenant
    - content_id not already registered to a different plaintext_size
```

### New Database Schema

```sql
-- Migration 004: Content dedup tables

CREATE TABLE IF NOT EXISTS content_entries (
    content_id          TEXT PRIMARY KEY,      -- HMAC(pepper, plaintext_hash)
    tenant_id           TEXT NOT NULL REFERENCES tenants(id),
    plaintext_size      BIGINT NOT NULL,
    chunk_count         BIGINT NOT NULL,
    chunk_size          BIGINT NOT NULL,
    chunk_plan_root     TEXT NOT NULL,
    pepper_generation   INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, content_id)
);

CREATE INDEX content_entries_tenant_idx
    ON content_entries(tenant_id);

CREATE TABLE IF NOT EXISTS content_chunks (
    content_id          TEXT NOT NULL REFERENCES content_entries(content_id),
    chunk_index         INTEGER NOT NULL,
    chunk_content_hash  TEXT NOT NULL,
    blob_key            TEXT NOT NULL REFERENCES blob_placements(blob_key),
    plaintext_len       BIGINT NOT NULL,
    ciphertext_len      BIGINT NOT NULL,
    PRIMARY KEY(content_id, chunk_index)
);

CREATE INDEX content_chunks_hash_idx
    ON content_chunks(tenant_id, chunk_content_hash);

-- Add content_id to file_versions
ALTER TABLE file_versions
    ADD COLUMN IF NOT EXISTS content_id TEXT REFERENCES content_entries(content_id),
    ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'KDRV1';

-- Add tenant_id to blob_placements for tenant-scoped dedup
ALTER TABLE blob_placements
    ADD COLUMN IF NOT EXISTS tenant_id TEXT REFERENCES tenants(id);

CREATE INDEX blob_placements_tenant_hash_idx
    ON blob_placements(tenant_id, checksum_sha256);
```

### Blob Key Change

```go
// Before (KDRV1):
blobKey := fmt.Sprintf("blob_%s_%d", versionID, ordinal)

// After (KDRV1):
blobKey := fmt.Sprintf("blob_%s_%s", contentID, chunkContentHash)

// Gateway checks blob_placements before storing:
func (s *DriveStore) CheckBlobExists(ctx context.Context, tenantID, blobKey string) (bool, error) {
    var exists bool
    err := s.pool.QueryRow(ctx, `
        SELECT EXISTS(
            SELECT 1 FROM blob_placements
            WHERE blob_key = $1 AND tenant_id = $2
        )
    `, blobKey, tenantID).Scan(&exists)
    return exists, err
}
```

---

## SDK Changes (Rust)

### New Crate: `kchat-drive-dedup`

```
crates/kchat-drive-dedup/
  src/
    lib.rs           — Public API: compute_content_id, check_dedup, DedupResult
    pepper.rs        — TenantPepper management (load, wrap, unwrap)
    content_key.rs   — ContentKey derivation, chunk key/nonce derivation
    chunk.rs         — Content-layer chunk encryption (KDRV1)
    manifest.rs      — KDRV1 manifest build/parse
    dedup.rs         — Dedup check logic, chunk-level dedup
```

### `kchat-drive-crypto` Changes

```rust
// New KDRV1 chunk encryption
pub fn encrypt_content_chunk(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_index: u64,
    plaintext: &[u8],
    suite: CipherSuite,
) -> Result<ContentChunk, DriveError>;

pub fn decrypt_content_chunk(
    content_key: &[u8; 32],
    content_id: &Hash256,
    chunk_index: u64,
    ciphertext: &[u8],
    suite: CipherSuite,
) -> Result<Vec<u8>, DriveError>;

// ContentKey derivation
pub fn derive_content_key(
    plaintext_sha256: &Hash256,
    tenant_pepper: &[u8; 32],
) -> [u8; 32];

// Content ID derivation
pub fn compute_content_id(
    plaintext_sha256: &Hash256,
    tenant_pepper: &[u8; 32],
) -> Hash256;

// ContentKey wrapping under VersionDEK
pub fn wrap_content_key(
    version_dek: &[u8; 32],
    version_salt: &[u8; 32],
    version_id: &VersionId,
    content_id: &Hash256,
    content_key: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 12]), DriveError>;

pub fn unwrap_content_key(
    version_dek: &[u8; 32],
    version_salt: &[u8; 32],
    version_id: &VersionId,
    content_id: &Hash256,
    wrapped_content_key: &[u8],
    wrap_nonce: &[u8; 12],
) -> Result<[u8; 32], DriveError>;
```

### `kchat-drive-types` Changes

```rust
// New protocol tag
pub const PROTOCOL_KDRV1: &str = "KDRV1";

// Extended Manifest
pub struct Manifest {
    pub protocol: String,              // "KDRV1" or "KDRV1"
    pub suite: CipherSuite,
    pub version_id: VersionId,
    pub node_id: NodeId,
    // KDRV1 fields (None for KDRV1)
    pub content_id: Option<Hash256>,
    pub wrapped_content_key: Option<Vec<u8>>,
    pub content_wrap_nonce: Option<[u8; 12]>,
    // Shared fields
    pub chunk_plan: ChunkPlan,
    pub name_ciphertext: Vec<u8>,
    pub mime_type: Option<String>,
    pub plaintext_size: u64,
    pub created_at: u64,
    pub parent_version_id: Option<VersionId>,
}

// Extended ChunkDescriptor
pub struct ChunkDescriptor {
    pub index: u64,
    pub plaintext_len: u64,
    pub ciphertext_len: u64,
    pub ciphertext_sha256: Hash256,
    pub blob_key: String,
    // KDRV1 field (None for KDRV1)
    pub chunk_content_hash: Option<Hash256>,
}

// Extended PublicVersionHeader
pub struct PublicVersionHeader {
    // ... existing KDRV1 fields ...
    pub protocol: String,              // "KDRV1" or "KDRV1"
    pub content_id: Option<Hash256>,   // KDRV1 only
}
```

### `kchat-client-runtime` Changes

```rust
// New upload flow with dedup
pub fn upload_with_dedup(
    &self,
    plaintext: &[u8],
    node_id: NodeId,
    domain_id: DomainId,
    privacy_mode: PrivacyMode,
    wrapping_key: &[u8; 32],
    tenant_pepper: &[u8; 32],
) -> Result<UploadResult, DriveError> {
    // 1. Compute plaintext hash
    let plaintext_sha256 = sha256(plaintext);

    // 2. Derive content_id
    let content_id = compute_content_id(&plaintext_sha256, tenant_pepper);

    // 3. Derive ContentKey
    let content_key = derive_content_key(&plaintext_sha256, tenant_pepper);

    // 4. Check gateway for existing content
    let dedup_result = self.transport.check_content(&content_id)?;

    if dedup_result.exists {
        // 5a. Dedup hit — verify and reuse
        let chunk_plan = self.verify_and_reuse(
            &content_id,
            &content_key,
            &dedup_result.blob_keys,
            &dedup_result.ciphertext_hashes,
        )?;

        // No chunk uploads needed
        let version_dek = generate_key();
        let wrapped_content_key = wrap_content_key(
            &version_dek, &version_salt, &version_id,
            &content_id, &content_key,
        )?;

        // Build manifest pointing to existing blobs
        let manifest = Manifest {
            protocol: PROTOCOL_KDRV1.into(),
            content_id: Some(content_id),
            wrapped_content_key: Some(wrapped_content_key),
            // ...
        };

        // Commit version (no chunk uploads)
        self.transport.commit_version(manifest, header, wrapped_dek)?;
    } else {
        // 5b. Dedup miss — encrypt and upload
        let (chunk_plan, ciphertexts) = encrypt_content_chunks(
            &content_key, &content_id, plaintext,
        )?;

        // Check chunk-level dedup
        let chunk_check = self.transport.check_chunks(
            &content_id,
            &chunk_plan.chunks.iter().map(|c| c.chunk_content_hash).collect(),
        )?;

        // Upload only missing chunks
        for (i, chunk) in ciphertexts.iter().enumerate() {
            if !chunk_check.results[i].exists {
                self.transport.upload_chunk(
                    &chunk_plan.chunks[i].blob_key, chunk,
                )?;
            }
        }

        // ... rest same as dedup hit ...
    }

    Ok(UploadResult { version_id, content_id, deduped: dedup_result.exists })
}
```

### `kchat-drive-transport-core` Changes

```rust
// New transport trait methods
#[async_trait]
pub trait DriveTransport {
    // Existing methods...

    // New dedup methods
    async fn check_content(
        &self,
        content_id: &Hash256,
    ) -> Result<ContentCheckResult, TransportError>;

    async fn check_chunks(
        &self,
        content_id: &Hash256,
        chunk_hashes: &[Hash256],
    ) -> Result<ChunkCheckResult, TransportError>;

    async fn commit_version_dedup(
        &self,
        manifest: Vec<u8>,           // encrypted manifest
        header: Vec<u8>,             // public version header
        wrapped_dek: Vec<u8>,        // wrapped VersionDEK
        wrap_nonce: [u8; 12],
        content_id: Hash256,
        reused_blob_keys: Vec<String>,
    ) -> Result<CommitResult, TransportError>;
}

pub struct ContentCheckResult {
    pub exists: bool,
    pub blob_keys: Vec<String>,
    pub ciphertext_hashes: Vec<Hash256>,
    pub chunk_count: u64,
    pub plaintext_size: u64,
}

pub struct ChunkCheckResult {
    pub results: Vec<ChunkCheckEntry>,
}

pub struct ChunkCheckEntry {
    pub hash: Hash256,
    pub exists: bool,
    pub blob_key: Option<String>,
}
```

---

## Security Analysis

### Threat: Confirmation attack (within tenant)

**Risk:** Tenant member can verify if a specific file exists by computing
content_id from known plaintext.

**Mitigation:** This is acceptable within a tenant — the member already has
access to tenant data. The content_id is HMAC-keyed with tenant_pepper, so
the gateway alone cannot compute it.

### Threat: Cross-tenant content correlation

**Risk:** Gateway sees same content_id for different tenants → learns they
have identical files.

**Mitigation:** content_id = HMAC(tenant_pepper, plaintext_hash). Different
tenants have different peppers → different content_ids for same plaintext.
Gateway cannot correlate across tenants.

### Threat: Low-entropy file brute-force

**Risk:** Attacker with tenant_pepper can precompute content_ids for common
files ("passwords.txt", known documents).

**Mitigation:**
1. Tenant_pepper is only available to authenticated tenant members
2. Gateway rate-limits content:check endpoint
3. Optional: add per-file random salt to content_id (trades dedup for security)
4. The content_id is HMAC (not raw hash) — requires pepper to compute

### Threat: Gateway learns dedup relationships

**Risk:** Gateway sees which files are identical within a tenant.

**Acceptance:** This is the intended behavior for dedup. The gateway already
sees file sizes, timestamps, and access patterns. Content relationships are
less sensitive than the content itself (which is encrypted).

### Threat: Tenant pepper compromise

**Risk:** If tenant_pepper leaks, attacker can derive ContentKeys for all
content in the tenant.

**Mitigation:**
1. Pepper stored encrypted in key vault (same as DomainKey)
2. Pepper rotation re-wraps under all active mode keys
3. Pepper compromise ≠ plaintext compromise (attacker still needs ciphertext
   access and the derived ContentKey)
4. Pepper is separate from DomainKey/ShareGrantKey — compromising one doesn't
   compromise the other

### Invariant preservation

| Invariant | KDRV1 | KDRV1 | Notes |
| --- | --- | --- | --- |
| Object keys carry no semantic info | Yes (random) | Yes (content hash, but opaque without pepper) | content_id is HMAC-keyed, looks random to gateway |
| Fresh VersionDEK per version | Yes | Yes | Unchanged — VersionDEK still random per version |
| Unique chunk key+nonce | Yes | Yes (per content) | ContentKey is per-content, chunks within content have unique keys |
| Storage provider breach reveals only ciphertext | Yes | Yes | Same — provider sees encrypted blobs |
| Cross-tenant dedup forbidden | Yes | Yes | Different peppers → different content_ids |

---

## Implementation Phases

### Phase 1: Crypto primitives (SDK)
**Files:**
- `crates/kchat-drive-crypto/src/content.rs` (new) — ContentKey derivation, content chunk AEAD
- `crates/kchat-drive-crypto/src/pepper.rs` (new) — TenantPepper gen/wrap/unwrap
- `crates/kchat-drive-crypto/src/kdf.rs` — Add KDRV1 KDF labels
- `crates/kchat-drive-crypto/src/lib.rs` — Export new functions

**Deliverable:** Unit tests for content_key derivation, content chunk encrypt/decrypt, content_id computation, pepper wrap/unwrap.

### Phase 2: Types + manifest (SDK)
**Files:**
- `crates/kchat-drive-types/src/manifest.rs` — Add KDRV1 fields
- `crates/kchat-drive-types/src/header.rs` — Add content_id to PublicVersionHeader
- `crates/kchat-drive-types/src/chunk.rs` — Add chunk_content_hash to ChunkDescriptor
- `crates/kchat-drive-types/src/lib.rs` — Export PROTOCOL_KDRV1

**Deliverable:** CBOR round-trip tests for KDRV1 manifest and header.

### Phase 3: Client runtime dedup flow (SDK)
**Files:**
- `crates/kchat-client-runtime/src/facade.rs` — Add upload_with_dedup method
- `crates/kchat-client-runtime/src/dedup.rs` (new) — Dedup check + chunk-level dedup logic
- `crates/kchat-client-runtime/src/pepper.rs` (new) — Pepper vault management
- `crates/kchat-drive-transport-core/src/transport.rs` — Add check_content, check_chunks traits
- `crates/kchat-drive-transport-native/src/client.rs` — Implement HTTP calls

**Deliverable:** Integration test: upload same file twice, verify second upload has zero chunk uploads.

### Phase 4: Gateway endpoints (Go)
**Files:**
- `internal/server/drive_api.go` — Add POST /v1/content:check, POST /v1/content:checkChunks
- `internal/server/drive_api.go` — Extend uploads:commit for KDRV1
- `internal/metadata/drive_store.go` — Add content_entries, content_chunks CRUD
- `internal/metadata/store.go` — Add CheckBlobExists, GetContentEntry
- `internal/blobio/pipeline.go` — Check blob_placements before Put
- `deploy/migrations/004_content_dedup.sql` (new) — Schema migration

**Deliverable:** API tests for content:check, chunk-level dedup, KDRV1 commit.

### Phase 5: Cross-mode dedup (SDK + Gateway)
**Files:**
- `crates/kchat-client-runtime/src/facade.rs` — Cross-mode re-wrap flow
- `crates/kchat-drive-mls-bridge/src/pepper.rs` (new) — Pepper distribution via MLS
- `crates/kchat-drive-crypto/src/pepper.rs` — Pepper wrap under ShareGrantKey
- `internal/server/drive_api.go` — Validate cross-tenant blob reuse

**Deliverable:** Integration test: upload in Secured, share via Max, verify zero chunk uploads for Max version.

### Phase 6: Sample apps + visualization
**Files:**
- `samples/electron-sample/main.js` — Add dedup indicator to UI
- `samples/ios-sample/KchatDriveIOS/KchatDriveIOS/ContentView.swift` — Dedup badge
- `samples/android-sample/app/src/main/java/.../MainActivity.kt` — Dedup badge
- `samples/README.md` — Document dedup feature

**Deliverable:** All 3 samples show "DEDUPED" badge when content is reused.

---

## API Contract

### POST /v1/content:check

```json
// Request
{
  "content_id": "base64-encoded-32-bytes"
}

// Response (200 OK)
{
  "exists": true,
  "blob_keys": ["blob_abc_...", "blob_abc_..."],
  "ciphertext_hashes": ["hex...", "hex..."],
  "chunk_count": 4,
  "plaintext_size": 16777216
}

// Response (404 — content not found)
{
  "exists": false
}
```

### POST /v1/content:checkChunks

```json
// Request
{
  "content_id": "base64...",
  "chunk_hashes": ["hex1", "hex2", "hex3"]
}

// Response
{
  "results": [
    { "hash": "hex1", "exists": true,  "blob_key": "blob_..." },
    { "hash": "hex2", "exists": false, "blob_key": null },
    { "hash": "hex3", "exists": true,  "blob_key": "blob_..." }
  ]
}
```

### POST /v1/uploads:commit (KDRV1 extension)

```json
// Request (KDRV1)
{
  "protocol": "KDRV1",
  "content_id": "base64...",
  "node_id": "...",
  "manifest": "base64...",
  "manifest_nonce": "base64...",
  "manifest_ciphertext_sha256": "hex...",
  "header": "base64...",
  "wrapped_dek_hex": "...",
  "wrap_nonce_hex": "...",
  "wrapped_content_key_hex": "...",
  "content_wrap_nonce_hex": "...",
  "reused_blob_keys": ["blob_...", "blob_..."],
  "new_blob_keys": ["blob_..."],
  "device_signature": "..."
}

// Response
{
  "version_id": "...",
  "committed": true,
  "deduped_chunks": 3,
  "new_chunks": 1
}
```

---

## Migration Strategy

### KDRV1 → KDRV1 Coexistence

1. **KDRV1 versions remain readable** — client detects protocol from header
2. **New uploads default to KDRV1** — configurable per-tenant
3. **No re-encryption needed** — KDRV1 blobs stay as-is
4. **KDRV1 → KDRV1 migration** (optional, future):
   - Client downloads + decrypts KDRV1 version
   - Re-encrypts with KDRV1 content layer
   - Uploads as new version (dedup applies)
   - Old KDRV1 version soft-deleted after retention period

### Tenant Pepper Bootstrap

1. Tenant admin generates pepper via SDK: `generate_tenant_pepper()`
2. Pepper wrapped under Secured DomainKey generation 0
3. Pepper stored in key_envelopes (envelope_type = "TENANT_PEPPER")
4. Each client fetches + unwraps pepper on first sync
5. Advanced/Max clients receive pepper via MLS/ShareGrantKey wrapping

---

## Open Questions

1. **Pepper rotation frequency** — Should pepper rotate on key rotation events,
   or only on explicit admin action? (Recommendation: explicit admin action only,
   to preserve dedup across key rotations)

2. **Spot-check verification** — When deduping, should client download + verify
   a random chunk, or trust gateway response? (Recommendation: download + verify
   first chunk only, for performance)

3. **Garbage collection** — When all versions referencing a content blob are
   deleted, should the blob be deleted? (Recommendation: yes, with retention
   period for crash safety)

4. **Quota accounting** — Should deduped versions count against tenant quota
   for storage? (Recommendation: only new chunks count, reused chunks are free)
