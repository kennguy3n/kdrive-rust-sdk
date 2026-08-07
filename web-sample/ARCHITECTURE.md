# KChat Drive — Architecture

## System Overview

KChat Drive is an end-to-end encrypted (E2EE) file storage system with three
privacy modes that trade off between collaboration flexibility and
cryptographic isolation. The system spans three codebases:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Browser (Client)                              │
│                                                                      │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────────────┐   │
│  │ React UI    │──▶│ TypeScript   │──▶│ WASM (Rust → wasm-pack) │   │
│  │ (Vite + TS) │   │ API Client   │   │                         │   │
│  │             │   │ (fetch)      │   │ kchat-drive-crypto:     │   │
│  │ Components:  │   └──────┬──────┘   │  - KDRV1 chunk AEAD     │   │
│  │  UserSwitcher│          │          │  - KDF key derivation   │   │
│  │  FolderTree  │          │          │  - DEK wrap/unwrap      │   │
│  │  UploadView  │          │          │  - HPKE recipient env   │   │
│  │  Scenario    │          │          │  - Ed25519 signing      │   │
│  │  VectorCheck │          │          │  - ShareGrantKey (MLS)  │   │
│  └─────────────┘          │          └─────────────────────────┘   │
│                            │                                        │
│  IndexedDB (vault.ts)      │                                        │
│  ┌─────────────────┐       │                                        │
│  │ domain_key_*    │       │                                        │
│  │ share_grant_*   │       │                                        │
│  │ ed25519_priv_*  │       │                                        │
│  │ ed25519_pub_*   │       │                                        │
│  └─────────────────┘       │                                        │
└────────────────────────────┼────────────────────────────────────────┘
                             │ HTTP (proxied via Vite dev server)
                             │ X-Demo-Tenant / X-Demo-User headers
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Go Gateway (drive-gateway)                       │
│                                                                      │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐     │
│  │ HTTP Mux     │──▶│ Metadata     │──▶│ Postgres             │     │
│  │ (net/http)   │   │ Store        │   │                      │     │
│  │              │   │              │   │ Tables:              │     │
│  │ /v1/tenants  │   │ metadata.    │   │  tenants             │     │
│  │ /v1/folders  │   │ drive_demo.go│   │  folders             │     │
│  │ /v1/uploads  │   │              │   │  nodes               │     │
│  │ /v1/versions │   │              │   │  encryption_domains  │     │
│  │ /v1/shares   │   │              │   │  key_envelopes       │     │
│  │ /v1/vectors  │   │              │   │  share_grants        │     │
│  └──────────────┘   └──────┬───────┘   │  access_context_*    │     │
│                            │           └──────────────────────┘     │
│  ┌──────────────┐          │                                        │
│  │ Blob Store   │◀─────────┘                                        │
│  │ (local_fs_dev│                                                   │
│  │  in dev)     │                                                   │
│  └──────────────┘                                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## Three-Repo Layout

| Repo | Path | Language | Purpose |
| --- | --- | --- | --- |
| `kdrive` | `/Users/Ken/workspaces/kdrive` | Go | Gateway API + Postgres metadata + blob storage |
| `kdrive-rust-sdk` | `/Users/Ken/workspaces/kdrive-rust-sdk` | Rust + TS | Crypto SDK, WASM bindings, web sample frontend |
| `openmls` | `/Users/Ken/workspaces/openmls` | Rust | KChat fork of OpenMLS for MLS key management |

## Privacy Modes

The three privacy modes determine how the Version DEK (Data Encryption Key) is
wrapped and who can access it:

### Secured (B2B default)

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐
│ Version  │────▶│ Domain Key   │────▶│ Domain Key Chain │
│ DEK      │     │ (wrap)       │     │ (generation N)   │
│ (32-byte)│     │ AES-256-GCM  │     │                  │
└──────────┘     └──────────────┘     └─────────────────┘
```

- **DEK wrapping**: AES-256-GCM with Domain Key
- **Key distribution**: Domain Key is shared with all group members
- **Late joiner**: Can decrypt all history (domain key chain allows backward walk)
- **Admin recovery**: Can decrypt (domain key available)
- **User removal**: Cannot read new versions (new domain key generation)

### Advanced (B2B optional)

```
┌──────────┐     ┌──────────────┐     ┌─────────────────┐
│ Version  │────▶│ Domain Key   │────▶│ Domain Key Chain │
│ DEK      │     │ (wrap)       │     │ + MLS forward    │
│ (32-byte)│     │ AES-256-GCM  │     │   secrecy        │
└──────────┘     └──────────────┘     └─────────────────┘
```

- **DEK wrapping**: Same as Secured (domain key)
- **Key distribution**: Domain Key + MLS exporter for forward secrecy
- **Late joiner**: Can decrypt history (domain key shared)
- **Admin recovery**: Cannot decrypt (no MLS epoch key)
- **User removal**: Cannot read new versions

### Max (B2C and high-security B2B)

```
┌──────────┐     ┌──────────────────┐     ┌─────────────────┐
│ Version  │────▶│ Share Grant Key  │────▶│ MLS Exporter    │
│ DEK      │     │ (wrap)           │     │ (per-epoch)     │
│ (32-byte)│     │ AES-256-GCM      │     │                 │
└──────────┘     └──────────────────┘     └─────────────────┘
```

- **DEK wrapping**: AES-256-GCM with Share Grant Key (MLS-derived)
- **Key distribution**: Per-epoch MLS exporter — no domain key
- **Late joiner**: Cannot decrypt history (only future epochs)
- **Admin recovery**: Cannot decrypt (no MLS key)
- **User removal**: Cannot read new versions (new epoch excludes them)

## KDRV1 Protocol

The KDRV1 protocol defines the cryptographic primitives used for file
encryption:

### Key Derivation (KDF)

```
VersionDEK (32 bytes)
    │
    ▼
HKDF-Extract (SHA-256)
    │
    ├──▶ Chunk Key[i]  = HKDF-Expand(DEK, "chunk" || node_id || version_id || i)
    ├──▶ Chunk Nonce[i] = HKDF-Expand(DEK, "nonce" || node_id || version_id || i)
    ├──▶ Manifest Key   = HKDF-Expand(DEK, "manifest" || node_id || version_id)
    └──▶ Manifest Nonce = HKDF-Expand(DEK, "manifest-nonce" || node_id || version_id)
```

### Chunk Encryption

Each chunk is encrypted with AES-256-GCM using its derived key and nonce:

```
plaintext[i] ──▶ AES-256-GCM(chunk_key[i], chunk_nonce[i]) ──▶ ciphertext[i]
```

### Chunk Plan (Merkle Tree)

Chunks are organized into a Merkle tree for integrity verification:

```
              chunk_plan_root (SHA-256)
             /                        \
        hash(left)                  hash(right)
        /      \                    /        \
   chunk[0]  chunk[1]          chunk[2]  chunk[3]
```

Each chunk descriptor contains:
- `index`: Chunk ordinal
- `plaintext_len`: Original bytes
- `ciphertext_len`: Encrypted bytes (plaintext + 16-byte GCM tag)
- `ciphertext_sha256`: Hash for integrity verification
- `blob_key`: Storage key in the blob store

## Upload Pipeline

```
Client (Browser)                          Gateway (Go)
─────────────────                         ──────────────
1. Generate VersionDEK (WASM)
   ↓
2. Generate IDs (node, version, drive, domain)
   ↓
3. Encrypt file (WASM)
   → chunk_plan, ciphertexts[], chunks[]
   ↓
4. Wrap DEK based on privacy mode:
   - Secured/Advanced: wrap_dek_under_domain_key()
   - Max: wrap_dek_under_share_grant_key()
   ↓
5. Create node on gateway ────────────▶ POST /v1/folders/{id}/children
   ← node_id                              (stores name_encrypted, mime_type)
   ↓
6. Initiate upload session ───────────▶ POST /v1/uploads:initiate
   ← session_id                           (stores chunk_plan, wrapped_dek, etc.)
   ↓
7. For each chunk[i]:
   Register chunk ────────────────────▶ POST /v1/uploads/{sid}/chunks/{i}:register
   ← blob_key                             (stores ciphertext in blob store)
   ↓
8. Verify round-trip locally:
   decrypt_file_wasm() → compare with original
```

## Key Management

### Domain Key Chain (Secured / Advanced)

```
Generation 1          Generation 2          Generation 3
┌──────────┐         ┌──────────┐         ┌──────────┐
│DomainKey │◀────────│DomainKey │◀────────│DomainKey │
│  (gen 1) │ prev_key│  (gen 2) │ prev_key│  (gen 3) │
└──────────┘         └──────────┘         └──────────┘
     │                    │                    │
     ▼                    ▼                    ▼
  wrap DEK            wrap DEK            wrap DEK
  (version 1)         (version 2)         (version 3)
```

- Each generation stores a reference to the previous key envelope
- Late joiners receive the current domain key and can walk backward
- On user removal: new generation created, old key revoked

### Share Grant Key (Max)

```
MLS Epoch 1              MLS Epoch 2
┌────────────────┐      ┌────────────────┐
│ ShareGrantKey  │      │ ShareGrantKey  │
│ (epoch 1)      │      │ (epoch 2)      │
│ recipients:    │      │ recipients:    │
│  [Alice, Bob]  │      │  [Alice]       │  ← Bob removed
└────────────────┘      └────────────────┘
       │                       │
       ▼                       ▼
   wrap DEK                wrap DEK
   (version 1)             (version 2)
```

- Key derived from MLS exporter (per-epoch, per-group)
- No backward access — late joiners only get future epochs
- User removal = new MLS epoch without them

## Data Model (Postgres)

```
tenants
  ├── id, pool_id, privacy_mode, tenant_type, bucket_name
  │
  ├── folders
  │     ├── id, tenant_id, parent_folder_id, name_encrypted, privacy_mode
  │     │
  │     └── nodes (files)
  │           ├── id, tenant_id, folder_id, name_encrypted, mime_type
  │           │
  │           ├── encryption_domains
  │           │     └── id, tenant_id, folder_id, privacy_mode, generation
  │           │
  │           ├── key_envelopes
  │           │     └── id, domain_id, ciphertext, nonce, encapsulated_key
  │           │
  │           ├── share_grants
  │           │     └── id, node_id, grantor, grantee, generation, key_envelope_id
  │           │
  │           └── access_context_snapshots
  │                 └── id, node_id, revision, snapshot_hash, acl_ciphertext
  │
  └── (blob store: ciphertext chunks keyed by blob_key)
```

## Demo Data

The migration `deploy/migrations/003_drive_demo.sql` seeds:

- **4 tenants**: `tenant_b2c` (B2C, Max-only), `tenant_acme`, `tenant_globex`,
  `tenant_initech` (B2B, all modes)
- **10 root folders**: 3 per B2B tenant (secured/advanced/max) + 1 for B2C
  (personal/max)
- **13 demo users**: 2 for B2C, 3-4 per B2B tenant (owner/member/latejoiner/admin)

Folder names use a demo convention: 16 zero bytes + ASCII name, encoded as
hex in the DB and base64 in JSON responses. The `bytesToName()` function in
`FolderTree.tsx` decodes this for display.

## WASM ↔ JavaScript Type Mapping

| Rust Type | wasm-bindgen JS Type | TypeScript |
| --- | --- | --- |
| `&str` | `string` | `string` |
| `&[u8]` | `Uint8Array` | `Uint8Array` |
| `[]byte` (Go JSON) | `string` (base64) | `string` |
| `u64` | `bigint` | `bigint` |
| `u32` | `number` | `number` |
| `bool` | `boolean` | `boolean` |
| `Result<JsValue, JsValue>` | `any` (JSON string) | `any` |
| `Result<String, JsValue>` | `string` | `string` |

## Security Boundaries

```
┌─────────────────────────────────────────────────┐
│ Client (Browser) — TRUSTED                       │
│                                                  │
│  ✓ Plaintext file content                        │
│  ✓ Version DEK (plaintext)                        │
│  ✓ Domain Key / Share Grant Key (plaintext)      │
│  ✓ Ed25519 private signing key                   │
│  ✓ HPKE private key                              │
│                                                  │
│  Stored in: IndexedDB (vault.ts)                 │
└──────────────────────┬──────────────────────────┘
                       │
                       │ Only ciphertext + wrapped keys cross this boundary
                       │
┌──────────────────────▼──────────────────────────┐
│ Gateway (Go) — UNTRUSTED                         │
│                                                  │
│  ✗ Never sees plaintext DEK                      │
│  ✗ Never sees plaintext file content             │
│  ✗ Never sees domain key / share grant key       │
│                                                  │
│  ✓ Stores: ciphertext chunks, wrapped DEKs,      │
│           encrypted names, opaque metadata       │
│  ✓ Enforces: tenant isolation, access control    │
└──────────────────────────────────────────────────┘
```

The gateway is treated as untrusted storage. Even if compromised, an attacker
cannot decrypt file contents without the client-side keys.
