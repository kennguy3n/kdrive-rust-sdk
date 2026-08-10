# KChat Drive Rust SDK — Architecture

This document describes the internal architecture of the `kdrive-rust-sdk`
workspace: how the crates layer, how the KDRV1 crypto pipeline works, how the
three privacy modes map onto key wrapping, how the MLS bridge transports keys,
and how the runtime enforces the safety invariants from the architecture spec
(§19).

The source-of-truth spec is `KChat-Privacy-Drive-Storage-Architecture-v1.0.md`
in the sibling `kdrive` repo. This SDK implements §5 (Privacy modes), §8 (Key
hierarchy), §9 (Crypto format), §10 (MLS bridge), §16 (Events), §17 (Client
API), and §19 (Client implementation) of that spec.

## 1. System context

KChat Drive spans three repos:

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Client (this SDK)                              │
│                                                                       │
│  Browser (WASM)        Native (UniFFI)        Electron (NAPI)         │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐        │
│  │ React UI     │      │ Swift/Kotlin │      │ JS addon     │        │
│  │   ↓          │      │   ↓          │      │   ↓          │        │
│  │ wasm-bindgen │      │ uniffi       │      │ napi-rs      │        │
│  │   ↓          │      │   ↓          │      │   ↓          │        │
│  │ DriveFacade  │      │ DriveFacade  │      │ DriveFacade  │        │
│  │   ↓          │      │   ↓          │      │   ↓          │        │
│  │ crypto+mls   │      │ crypto+mls   │      │ crypto+mls   │        │
│  └──────────────┘      └──────────────┘      └──────────────┘        │
│         │                     │                     │                │
│  IndexedDB vault        SQLCipher vault        SQLCipher vault        │
└─────────┼─────────────────────┼─────────────────────┼────────────────┘
          │ ciphertext + wrapped DEKs only (never plaintext keys)
          ▼
┌──────────────────────────────────────────────────────────────────────┐
│              Go Gateway (sibling `kdrive` repo)                       │
│  Postgres metadata + blob storage (Wasabi / local_fs_dev)             │
│  Never sees plaintext DEK, DomainKey, ShareGrantKey, or file content  │
└──────────────────────────────────────────────────────────────────────┘
          ▲
          │ MLS exporter label + context (no raw key bytes cross FFI)
┌──────────────────────────────────────────────────────────────────────┐
│        OpenMLS (sibling `openmls` repo, KChat fork)                   │
│  MlsGroup::export_secret → per-epoch exporter output                  │
└──────────────────────────────────────────────────────────────────────┘
```

The three repos are wired together via path dependencies in the root
`Cargo.toml`:

```toml
uq-openmls = { path = "../kchat-rust-sdk/crates/uq-openmls" }
openmls    = { path = "../openmls/openmls" }

[patch.crates-io]
openmls = { path = "../openmls/openmls" }
# ... openmls_traits, openmls_rust_crypto, openmls_basic_credential
```

## 2. Crate dependency graph

The workspace is layered so the crypto core has **no I/O and no platform
dependencies**. Bindings and transports pull in platform crates only behind
`cfg` gates.

```
                    kchat-drive-types  ← canonical CBOR types, IDs, errors
                          ▲
            ┌─────────────┼──────────────┐
            │             │              │
   kchat-drive-crypto   kchat-drive-sync-core   kchat-drive-transport-core
   (KDRV1 primitives)   (journal, state)        (Transport/AsyncTransport traits)
            ▲             ▲              ▲
            │             │              │
   kchat-drive-mls-bridge │              │
   (OpenMLS exporter)     │              │
            ▲             │              │
            └──────┬──────┘              │
                   │                     │
          kchat-drive-identity           │
          (vault, account, device)       │
                   ▲                     │
                   │                     │
          kchat-client-runtime           │
          (DriveFacade, EpochBarrier,    │
           FencingToken, runtime)        │
                   ▲                     │
      ┌────────────┼────────────┐        │
      │            │            │        │
   kchat-drive-   kchat-drive-  kchat-drive-
   wasm           uniffi        napi
   (wasm-bindgen) (Swift/Kotlin) (NAPI-RS)
                                          │
                              kchat-drive-transport-native (tokio)
                              kchat-drive-transport-web    (fetch + worker)
                              kchat-drive-store-sqlite     (SQLCipher)
                              kchat-drive-store-idb        (IndexedDB)
```

`kchat-drive-types` is the leaf: every other crate depends on it. It defines
the wire format (CBOR) and the error enum (`DriveError`) used everywhere.

## 3. KDRV1 crypto pipeline

The KDRV1 protocol (suite 1, version 1) defines how a file is encrypted into
chunks and how per-chunk keys are derived from a single 32-byte VersionDEK.

### 3.1 Key derivation (HKDF-SHA256)

All KDF operations use `HKDF-SHA256` with the version salt
`"kchat-drive/v1"`. The VersionDEK is the input keying material (IKM).

```
PRK = HKDF-Extract(salt="kchat-drive/v1", IKM=VersionDEK)

ChunkKey[i]   = HKDF-Expand(PRK, "kchat-drive/chunk-key/v1"   || node_id || version_id || u64be(i), 32)
ChunkNonce[i] = HKDF-Expand(PRK, "kchat-drive/chunk-nonce/v1" || node_id || version_id || u64be(i), 12)
ManifestKey   = HKDF-Expand(PRK, "kchat-drive/manifest-key/v1"   || node_id || version_id, 32)
ManifestNonce = HKDF-Expand(PRK, "kchat-drive/manifest-nonce/v1" || node_id || version_id, 12)
```

Implementation: `crates/kchat-drive-crypto/src/kdf.rs`. The info strings bind
each derived key to its specific chunk index, node, and version, so reusing a
VersionDEK across versions does not collide.

### 3.2 Chunk encryption (AES-256-GCM)

Each chunk is encrypted with `AES-256-GCM` using its derived key + nonce. The
AAD is a deterministic byte encoding (not full CBOR) of:

```
(protocol: u16, suite: u16, drive_id: [u8;16], node_id: [u8;16],
 version_id: [u8;16], chunk_index: u64, plaintext_len: u64,
 domain_id: [u8;16], access_context_revision: u64,
 access_context_snapshot_hash: [u8;32])
```

Binding the AAD to all of these prevents chunk-swapping, version-swapping, and
domain-confusion attacks. Implementation: `crates/kchat-drive-crypto/src/chunk.rs`
(`encrypt_chunk`, `decrypt_chunk`, `encrypt_file`, `decrypt_file`).

### 3.3 Chunk sizing

`select_chunk_size(file_size)` (architecture §9.2):

| File size | Chunk size |
| --- | --- |
| `< 64 MiB` | 4 MiB |
| `< 512 MiB` | 8 MiB |
| `>= 512 MiB` | 16 MiB |

Empty files produce exactly one chunk (so `chunk_count(0, cs) == 1`).

### 3.4 Chunk plan (Merkle tree)

Chunks are organized into a Merkle tree for integrity verification. The leaf
hash is:

```
leaf[i] = SHA-256("kchat-drive/chunk-plan-leaf/v1" || u64be(i) || u64be(plaintext_len) || ciphertext_sha256)
```

Internal nodes:

```
node = SHA-256("kchat-drive/chunk-plan-node/v1" || left || right)
```

A lone child is hashed with itself (no padding). The root is stored in
`PublicVersionHeader.chunk_plan_root`. Implementation:
`ChunkPlan::merkle_root` in `crates/kchat-drive-types/src/header.rs`.

Each `ChunkDescriptor` records `index`, `plaintext_len`, `ciphertext_len`
(plaintext + 16-byte GCM tag), `ciphertext_sha256`, and `blob_key` (the opaque
storage key in the blob store, formatted as `blob_{version_id}_{i}` in the
demo).

### 3.5 Manifest

The `Manifest` (architecture §9.3) is CBOR-encoded, then encrypted with
`AES-256-GCM` under `ManifestKey` / `ManifestNonce`. It contains:

```
Manifest {
    version_id, node_id, chunk_plan, name_ciphertext,
    mime_type, plaintext_size, created_at, parent_version_id
}
```

The encrypted manifest ciphertext hash (`manifest_ciphertext_sha256`) and
length are stored in the public version header so the gateway can verify
integrity without decrypting. Implementation:
`crates/kchat-drive-crypto/src/manifest.rs`.

### 3.6 Public version header

The `PublicVersionHeader` (architecture §9.1) is the canonical public metadata
for a version. It is CBOR-encoded and signed with Ed25519 by the creating
device:

```
signature = Ed25519Sign(SHA-256("kchat-drive/version-header-signature/v1"
                                || CanonicalHeaderWithoutSignature))
```

The header carries: protocol, suite, drive/node/version/domain IDs, privacy
mode, plaintext size, chunk size, chunk count, chunk plan root, manifest
ciphertext hash + length + nonce, access context revision + snapshot hash,
creator device public key, creation timestamp, and the signature.

`version_header_hash()` returns `SHA-256(CBOR(header_with_signature))` — used
for re-share wrap lookups. Implementation:
`crates/kchat-drive-types/src/header.rs` + `sign_header` / `verify_header` in
`kchat-drive-crypto/src/manifest.rs`.

## 4. Privacy modes & key wrapping

The three privacy modes differ in **how the VersionDEK is wrapped** and **who
can unwrap it**. The chunk encryption itself is identical across all modes.

### 4.1 Secured (mode 1) — B2B default

```
VersionDEK ──AES-256-GCM──▶ wrapped_dek   (wrap key = DomainKey[g])
                                              ▲
                                              │
                                   DomainKey chain (generations 0..N)
                                   prev_envelope[g] = AEAD(DomainKey[g], DomainKey[g-1])
```

- **Wrap**: `wrap_version_dek_under_domain_key(domain_key, dek)` →
  `(ciphertext, nonce)`. AAD = `"kchat-drive/domain-wrap/v1"`.
- **Unwrap**: `unwrap_version_dek_from_domain_key(domain_key, ct, nonce)`.
- **Domain key chain**: `generate_domain_key` creates generation 0 (always a
  checkpoint). `rotate_domain_key` creates generation `g+1` and encrypts the
  old key under the new key (`prev_envelope`). `walk_backward` recovers the
  previous key. Checkpoints every 32 generations.
- **Late joiner**: receives current DomainKey, can `walk_backward` to decrypt
  history.
- **Admin recovery**: ✅ (admin has the DomainKey).
- **User removal**: rotate to a new generation; old key cannot wrap new
  versions.

Implementation: `crates/kchat-drive-crypto/src/domain_key.rs`.

### 4.2 Advanced (mode 2) — B2B optional

Same DomainKey wrap as Secured, **plus** the DomainKey itself is sealed under
an MLS exporter-derived transport key. This adds forward secrecy: even if the
DomainKey leaks, an admin without the MLS epoch key cannot open the transport
envelope.

```
DomainKey ──MLS exporter──▶ transport_key ──AES-256-GCM──▶ sealed envelope
                                                              │
                            (exporter output never crosses FFI)
```

- **Seal**: `seal_advanced_domain_key(group, provider, envelope_id, domain_key, ctx)`
  calls `MlsGroup::export_secret(label, context, 32)` with label
  `"org.kchat.drive.advanced-domain-transport.v1"`, derives
  `(transport_key, transport_nonce)` via `derive_transport_key_and_nonce`,
  then `create_mls_transport_envelope`.
- **Open**: `open_advanced_domain_key_and_store` re-derives the exporter
  output, opens the envelope, returns `(Key256, DurableKeyReceipt)`. The
  receipt contains only a `key_hash` (audit), not the key itself.
- **Admin recovery**: ❌ (admin has no MLS epoch key).
- **Late joiner**: ✅ (DomainKey is shared via the exporter once they're in the
  group).

Implementation: `crates/kchat-drive-mls-bridge/src/advanced.rs`.

### 4.3 Max (mode 3) — B2C + high-security B2B

No DomainKey at all. The VersionDEK is wrapped under a **ShareGrantKey** that
is derived per MLS epoch per share grant.

```
VersionDEK ──AES-256-GCM──▶ wrapped_dek   (wrap key = ShareGrantKey[g])
                                              ▲
                                              │
                                   MLS exporter (per epoch, per grant)
                                   recipients = [user_id, ...]
                                   recipient_user_set_root = SHA-256(sorted recipients || snapshot_hash)
```

- **Wrap**: `wrap_version_dek_under_share_grant_key(sgk, dek)`. AAD =
  `"kchat-drive/share-grant-wrap/v1"`.
- **ShareGrantKey generation**: `generate_share_grant_key(grant_id, recipients,
  user_snapshot_hash, mls_epoch, mls_tree_hash)` produces a random 32-byte key
  + records the immutable `recipient_user_set_root` and `user_snapshot_hash`.
- **Seal under MLS**: `seal_max_share_grant_key` uses label
  `"org.kchat.drive.max-share-grant-transport.v1"` and the
  `MaxTransportContext` (grant_id, generation, mls_epoch, mls_tree_hash,
  recipient_user_set_root, user_snapshot_hash).
- **Late joiner**: ❌ (only gets future epochs; no backward access).
- **Admin recovery**: ❌ (no MLS key).
- **User removal**: new MLS epoch without them → new ShareGrantKey generation.

Implementation: `crates/kchat-drive-crypto/src/share_grant.rs` +
`crates/kchat-drive-mls-bridge/src/max.rs`.

### 4.4 Envelope variants

`KeyEnvelope` (architecture §9.4) has three variants:

| Variant | Use | Delivery |
| --- | --- | --- |
| `Hpke` | Per-device direct delivery | `SetupBaseS` to X25519 public key; encapped key + ciphertext stored |
| `MlsTransport` | Advanced + Max group delivery | Symmetric AES-256-GCM under MLS-derived transport key; salt + nonce stored |
| `Recovery` | Secured mode tenant recovery | AES-256-GCM under a recovery key (demo KMS stub) |

The `WrapSetRoot` is `SHA-256("kchat-drive/wrap-set-root/v1" || sorted(envelope_hashes))`
— a single hash committing to the entire wrap set for a version.

Implementation: `crates/kchat-drive-crypto/src/envelope.rs` +
`crates/kchat-drive-types/src/envelope.rs`.

## 5. MLS bridge

The MLS bridge (`kchat-drive-mls-bridge`) is the only crate that touches
OpenMLS. It exposes four operations: seal/open for Advanced, seal/open for Max.
Each operation:

1. Builds a context (`AdvancedTransportContext` or `MaxTransportContext`).
2. Calls `MlsGroup::export_secret(provider.crypto(), label, context_bytes, 32)`.
3. Derives `(transport_key, transport_nonce)` from the exporter output via
   `derive_transport_key_and_nonce` (HKDF-SHA256 with a random salt).
4. Seals or opens the key envelope under the transport key.

**The exporter output never crosses FFI** — only the sealed envelope is
returned. This keeps the per-epoch secret inside the MLS provider.

### 5.1 Ordering proof

`OrderingProof` (architecture §10) validates that a staged Commit has the
correct winning Commit hash + tree hash + admitted roster before merge:

```
commit_hash = SHA-256("kchat-drive/commit-hash/v1" || commit_bytes)
```

`post_merge_assertion` verifies the group's epoch + tree hash match the proof
after merging. This prevents stale-Commit attacks. Implementation:
`crates/kchat-drive-mls-bridge/src/proof.rs`.

### 5.2 Exporter labels

| Purpose | Label |
| --- | --- |
| Advanced domain key transport | `org.kchat.drive.advanced-domain-transport.v1` |
| Max share grant key transport | `org.kchat.drive.max-share-grant-transport.v1` |

Context bytes are a deterministic encoding of the transport context fields
(domain_id/grant_id, generation, mls_epoch, mls_tree_hash, and for Max also
recipient_user_set_root + user_snapshot_hash). The context hash
(`SHA-256(context_bytes)`) is mixed into the transport key derivation.

## 6. Client runtime

`kchat-client-runtime` is the **sole owner** of the MLS provider handle, the
`DriveKeyVault`, the `OperationJournal`, and the `EpochBarrier`. It enforces
the architecture §19.1 invariants.

### 6.1 ClientRuntime

```
ClientRuntime {
    fencing_token: FencingToken,        // monotonically increasing AtomicU64
    vault: Mutex<DriveKeyVault>,        // AES-256-GCM encrypted key store
    journal: Mutex<OperationJournal>,   // ordered operation log
    barrier: Mutex<EpochBarrier>,       // per-domain / per-grant epoch tracking
    locked_groups: Mutex<Vec<String>>,  // deny-by-default group mutation lock
}
```

- `lock_group` / `unlock_group` — deny-by-default for Drive-bound groups.
- `fencing_token()` / `next_fencing_token()` — prevents stale operations from
  a previous lease holder.
- `vault()` / `journal()` / `barrier()` — `MutexGuard` accessors.

### 6.2 EpochBarrier

The epoch barrier ensures key material from a previous MLS epoch is not used
after a Commit that changes group membership. It tracks the current epoch per
`DomainId` and per `ShareGrantId`, and exposes `check_domain` / `check_grant`
which return `EpochMismatch` if the current epoch is below the required
minimum. Pending barriers (`wait_for_domain` / `wait_for_grant`) are
auto-satisfied when the epoch advances.

### 6.3 DriveFacade

`DriveFacade` is the high-level API that bindings expose. It owns an
`Arc<ClientRuntime>` and delegates all state mutations through it:

| Method | What it does |
| --- | --- |
| `upload(...)` | Generate VersionDEK → `encrypt_file` → `encrypt_manifest` → wrap DEK (domain or share-grant) → `sign_header` → store DEK in vault → return `UploadResult` |
| `download(...)` | `decrypt_manifest` → `decrypt_file` → return `DownloadResult` |
| `get_version_dek(version_id)` | Load stored DEK from vault |
| `create_domain(domain_id)` | `generate_domain_key` → store CBOR record in vault → return key |
| `rotate_domain(domain_id, gen)` | Load record → `rotate_domain_key` → store new record → return new key |
| `create_share_grant(...)` | `generate_share_grant_key` → store CBOR record in vault → return key |
| `rotate_share_grant(...)` | Load record → `rotate_share_grant_key` → store new record → return new key |

The vault stores full CBOR-encoded `DomainKeyRecord` / `ShareGrantKeyRecord`
(including the `prev_envelope` chain) so the backward chain is preserved
across rotations.

### 6.4 DriveKeyVault

`DriveKeyVault` (`kchat-drive-identity`) is an in-memory AES-256-GCM encrypted
key store. The master key is either random (`new()`) or supplied externally
(`from_master_key`, e.g. from WebCrypto wrapping root). Entries are stored as
`(ciphertext, nonce)` pairs under string key IDs like
`"domain_key:{domain_id}:{generation}"` or `"version_dek:{version_id}"`. The
master key is `Zeroize`d on drop.

## 7. Identity & enrollment

`kchat-drive-identity` implements the account authority model:

```
AccountAuthorityRecord {
    user_id, root_public_key (Ed25519),
    devices: [DeviceCertificate { device_id, device_public_key, device_name, enrolled_at, active }],
    created_at, updated_at,
    signature: Ed25519 over SHA-256("kchat-drive/account-authority/v1" || canonical_record)
}
```

- `enroll_user(user_id, device_name)` — generates account root keypair + device
  keypair, creates the signed authority record.
- `add_device(account, root_key, device_name)` — appends a new device cert,
  re-signs.
- `remove_device(account, root_key, device_id)` — deactivates a device cert,
  re-signs.

`DeviceKeyPair` wraps `ed25519_dalek::SigningKey` (which zeroizes on drop when
the `zeroize` feature is enabled).

## 8. Sync core

`kchat-drive-sync-core` is target-neutral (no I/O):

- **`OperationJournal`** — ordered log of `JournalEntry { seq, op_type, status,
  node_id, version_id, timestamp, error }`. Operation types: Upload, Download,
  CreateFolder, DeleteNode, RenameNode, ShareGrant, ShareRevoke,
  DomainKeyRotate. Statuses: Pending, InProgress, Completed, Failed,
  Conflicted.
- **`DriveSyncState`** — per-node `NodeSyncState { node_id, state,
  local_version, remote_version, last_sync }`. States: Idle, Uploading,
  Downloading, Conflicted, Error.
- **`SyncConflict`** + `ResolutionStrategy` — `ConcurrentEdit`,
  `DeleteWithLocalChanges`, `RemoteNewer` conflicts; `KeepLocal`,
  `AcceptRemote`, `Merge` resolutions.

## 9. Persistence

### 9.1 Native — `kchat-drive-store-sqlite`

`SqliteDriveStore` uses `rusqlite` (bundled SQLite) with an embedded `SCHEMA_V1`:

| Table | Purpose |
| --- | --- |
| `drive_keys` | Encrypted key blobs (key_id, ciphertext, nonce) |
| `journal` | Operation journal (seq, op_type, status, node_id, version_id, timestamp, error) |
| `sync_state` | Per-node sync state (node_id, state, local_version, remote_version, last_sync) |
| `domain_keys` | Domain key chain (domain_id, generation, key_ciphertext, prev_envelope, is_checkpoint) |
| `share_grant_keys` | Share grant keys (grant_id, generation, recipient_set_root, mls_epoch, mls_tree_hash) |

`open(path)` runs migrations on startup; `open_in_memory()` for tests. In
production, SQLCipher encrypts the database file at rest.

### 9.2 Browser — `kchat-drive-store-idb`

- **`IdbDriveStore`** — IndexedDB-backed store (scaffold; the async open is
  implemented in the WASM facade).
- **`TwoSlotSnapshot`** — A/B slot atomic swap (architecture §19.5). `commit`
  writes to the inactive slot then flips the active pointer, so a crash leaves
  the previous consistent snapshot readable.
- **`OrderedWriteSet`** — ordered journal of `(seq, key, value)` entries for
  replay.

## 10. Transport

### 10.1 Core traits — `kchat-drive-transport-core`

| Trait | Method | Use |
| --- | --- | --- |
| `Transport` | `send(DriveRequest) -> Result<DriveResponse>` | Sync native |
| `AsyncTransport` | `send_async(DriveRequest) -> Future<...>` | WASM (non-`Send` futures, `Rc`-based) |
| `StreamSession` | `read`/`write`/`checkpoint`/`cancel`/`progress` | Bounded streaming (architecture §19.1) |

`DriveRequest` / `DriveResponse` are serde-serializable structs (method, path,
body, headers). `RetryConfig` (max_attempts, initial_delay, max_delay,
backoff_factor) + `with_retry` provide exponential backoff. On WASM, `sleep`
is a no-op (callers should use async retry with `setTimeout`).

`DownloadCapability` / `UploadCapability` (architecture §17) carry short-lived
tokens + blob keys + expiry.

### 10.2 Native — `kchat-drive-transport-native`

`NativeTransport` is a stub that delegates to platform HTTP clients
(iOS `URLSession` / Android `WorkManager` via callback contracts in
production).

### 10.3 Web — `kchat-drive-transport-web`

- **`FetchTransport`** — async `fetch` via `JsFuture`, returns
  `DriveResponse` with status + body. Implements `AsyncTransport`.
- **`WorkerCoordinator`** — SharedWorker leader election via
  `navigator.locks.request("kdrive-leader", ...)` (scaffold assumes leader).
- **`ServiceWorkerStream`** — registers a Service Worker that intercepts
  download requests and streams encrypted chunks through the WASM decryptor
  (scaffold).

## 11. Bindings

All three bindings expose the same crypto + key-wrap surface; they differ only
in type marshalling.

### 11.1 WASM — `kchat-drive-wasm`

`#[wasm_bindgen]` functions in `src/crypto.rs` + `src/types.rs` + `src/api.rs`:

- `generate_version_dek()`, `generate_domain_key_wasm`, `rotate_domain_key_wasm`,
  `generate_share_grant_key_wasm`
- `encrypt_file_wasm`, `decrypt_file_wasm`
- `encrypt_manifest_wasm`, `decrypt_manifest_wasm`
- `wrap_dek_under_domain_key`, `unwrap_dek_from_domain_key`
- `wrap_dek_under_share_grant_key`, `unwrap_dek_from_share_grant_key`
- `sign_header_wasm`, `verify_header_wasm`
- `generate_hpke_keypair`, `generate_ed25519_keypair`
- `select_chunk_size`, `chunk_count`, `random_id_hex`, `sha256_hex`
- `get_test_vectors_json`

Complex returns are JSON strings; plaintext is `Uint8Array`; `u64` parameters
are `bigint`. The `WasmDriveRuntime` struct holds a master key for the vault.

### 11.2 UniFFI — `kchat-drive-uniffi`

`#[uniffi::export]` functions for Swift / Kotlin. Returns `UploadResultFfi`,
`DownloadResultFfi`, `KeyPairFfi` records. Errors are mapped through
`DriveSdkError` (a `#[uniffi::Error]` enum with `Crypto`, `NotFound`,
`InvalidState`, `MlsBridge`, `Envelope`, `PermissionDenied` variants).

### 11.3 NAPI — `kchat-drive-napi`

`#[napi]` functions for Electron. Uses `Buffer` for binary data, `i64` for
64-bit integers (JS numbers), `String` for hex. Same surface as UniFFI.

## 12. Events

`DriveEvent` (architecture §16) is the audit log record:

```
DriveEvent { event_id, drive_id, event_type, actor, timestamp, payload (CBOR) }
```

Event types: `DriveCreated`, `FolderCreated`, `FileCreated`, `VersionUploaded`,
`VersionDownloaded`, `MemberAdded`, `MemberRemoved`, `DomainKeyRotated`,
`ShareGranted`, `ShareRevoked`, `RecoveryInitiated`, `ReshareRequested`.

Payload structs: `ShareGrantedPayload` (grant_id, node_id, recipient, role,
generation), `ShareRevokedPayload`, `DomainKeyRotatedPayload` (old/new
generation), `MemberChangePayload` (user_id, role, device_key).

Implementation: `crates/kchat-drive-types/src/events.rs`.

## 13. Cross-language test vectors

`kchat-drive-crypto::vector` generates deterministic vectors with known inputs
so Rust, Go, and WASM produce byte-identical output:

- **`KdfVector`** — VersionDEK `[0x42; 32]`, NodeId `[0x01; 16]`, VersionId
  `[0x02; 16]`, chunk indices 0–2. Records expected chunk key, chunk nonce,
  manifest key, manifest nonce.
- **`RoundTripVector`** — full `encrypt_file` round-trip with
  DriveId `[0x03; 16]`, DomainId `[0x04; 16]`, revision 1, snapshot hash
  `[0x05; 32]`, plaintext `"Hello, KChat Drive! ..."`. Records chunk plan root
  + chunk count.
- **`all_vectors_json()`** — serializes everything as
  `{ protocol: "kdrv1", version: 1, suite: 1, kdf: [...], round_trip: {...} }`.

The web sample's Vectors tab and the Go gateway's `/v1/vectors` endpoint both
serve this JSON; the sample verifies byte-equality.

## 14. Security boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│ Client (this SDK) — TRUSTED                                      │
│                                                                  │
│  ✓ Plaintext file content                                        │
│  ✓ VersionDEK (plaintext, in vault)                              │
│  ✓ DomainKey / ShareGrantKey (plaintext, in vault)               │
│  ✓ Ed25519 private signing key (in vault or WebCrypto)           │
│  ✓ HPKE / X25519 private key                                     │
│  ✓ MLS exporter output (never crosses FFI)                       │
│                                                                  │
│  Storage: SQLCipher (native) / IndexedDB (browser)               │
└───────────────────────┬──────────────────────────────────────────┘
                        │ Only ciphertext + wrapped DEKs + encrypted
                        │ names + opaque metadata cross this boundary
                        ▼
┌─────────────────────────────────────────────────────────────────┐
│ Go Gateway — UNTRUSTED                                            │
│                                                                  │
│  ✗ Never sees plaintext DEK, DomainKey, ShareGrantKey             │
│  ✗ Never sees plaintext file content                              │
│  ✗ Never sees MLS exporter output                                 │
│                                                                  │
│  ✓ Stores: ciphertext chunks, wrapped DEKs, encrypted names,      │
│           opaque metadata, access context snapshots               │
│  ✓ Enforces: tenant isolation, access control, capability expiry  │
└─────────────────────────────────────────────────────────────────┘
```

The gateway is treated as untrusted storage. Even if compromised, an attacker
cannot decrypt file contents without the client-side keys. The MLS exporter
output never leaves the OpenMLS provider — only sealed envelopes cross the
FFI boundary.

## 15. Demo binary

`kchat-drive-demo` is a standalone TCP server (`127.0.0.1:3000`) that serves
an HTML page with encrypt/decrypt/sign/verify forms. It exercises the pure
Rust crypto core with no browser, no WASM, no gateway required:

```
GET  /                  → HTML demo page
GET  /api/health        → {"status":"ok","protocol":1,"suite":1}
GET  /api/generate-key  → {"version_dek":"..."}
GET  /api/generate-ids  → {node_id, version_id, drive_id, domain_id, ...}
GET  /api/test-vectors  → all_vectors_json()
POST /api/encrypt       → {chunk_plan_root, ciphertexts, manifest, header}
POST /api/decrypt       → {plaintext_base64}
POST /api/sign-header   → {signed_header_cbor_hex, signature_hex}
POST /api/verify-header → {valid: bool}
```

Useful for quickly verifying the crypto core compiles and runs on a new
platform before wiring up bindings.
