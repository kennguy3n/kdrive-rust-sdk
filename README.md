# kdrive-rust-sdk

Cross-platform Rust SDK for **KChat Privacy Drive** — an end-to-end encrypted
(E2EE) file storage system with three privacy modes that trade off between
collaboration flexibility and cryptographic isolation. The SDK compiles to
native (desktop / iOS / Android), Node.js (Electron), and WebAssembly
(browser) targets from a single workspace.

> **Status:** Pre-1.0 scaffold. Crypto primitives, KDRV1 protocol, MLS bridge,
> and WASM bindings are implemented and tested. Native transports, IndexedDB
> persistence, and ServiceWorker streaming are scaffolded for production wiring.

## What this SDK does

- **Encrypts files client-side** using the KDRV1 protocol (AES-256-GCM chunks,
  HKDF-SHA256 key derivation, Ed25519-signed version headers, CBOR manifests).
- **Wraps the per-version DEK** under one of three key classes depending on the
  privacy mode:
  - **Secured** — DomainKey shared across the tenant domain (admin-recoverable).
  - **Advanced** — DomainKey + MLS exporter forward secrecy (admin cannot
    decrypt).
  - **Max** — ShareGrantKey derived per MLS epoch (no domain key, no history
    access for late joiners).
- **Bridges to OpenMLS** for exporter-based key transport in Advanced and Max
  modes, with ordering proofs and post-merge assertions.
- **Exposes a unified `DriveFacade`** through WASM, UniFFI (Swift / Kotlin), and
  NAPI (Electron) bindings so the same crypto runs on every platform.
- **Verifies cross-language correctness** via shared KDRV1 test vectors that
  must produce byte-identical output in Rust, Go (gateway), and WASM.

In all three modes the KChat server (the Go gateway in the sibling `kdrive`
repo) only ever sees ciphertext chunks, wrapped DEKs, encrypted names, and
opaque metadata. It can never decrypt file contents.

## Repository layout

```
kdrive-rust-sdk/
├── Cargo.toml                 # Workspace manifest + shared dependency versions
├── rust-toolchain.toml        # Stable channel + rustfmt/clippy components
├── rustfmt.toml               # Edition 2024, 100-col, field-init-shorthand
├── crates/                    # 15 crates (see "Crates" below)
└── web-sample/                # React + Vite demo app (separate npm project)
    ├── README.md              # Web sample quick start + WASM API reference
    ├── ARCHITECTURE.md        # System diagram + privacy-mode walkthrough
    ├── DEMO.md                # Demo setup + scenario scripts
    └── src/                   # React components + TS API client + vault
```

## Crates

The workspace is layered so that the crypto core has no I/O or platform
dependencies; bindings and transports pull in platform crates only when needed.

| Crate | Target | Description |
| --- | --- | --- |
| `kchat-drive-types` | all | Canonical CBOR types: `OpaqueId`, `Hash256`, `Key256`, `Nonce12`, `PublicVersionHeader`, `Manifest`, `ChunkPlan`, `KeyEnvelope`, `DomainKeyRecord`, `ShareGrantKeyRecord`, `DriveEvent`, `PrivacyMode`, `Role`, `DriveError`. Defines `PROTOCOL_VERSION=1` and `SUITE_KDRV1=1`. |
| `kchat-drive-crypto` | all | KDRV1 primitives: HKDF-SHA256 KDF, AES-256-GCM chunk AEAD, manifest encrypt/decrypt, Ed25519 header signing, HPKE `SetupBaseS` recipient envelopes, MLS transport envelopes, DomainKey chain (rotate / walk-backward), ShareGrantKey wrap/unwrap, cross-language test vectors. |
| `kchat-drive-identity` | all | Account authority record (root-signed device set), `DeviceCertificate`, `DeviceKeyPair`, `DriveKeyVault` (AES-256-GCM encrypted in-memory key store with `ZeroizeOnDrop`), enrollment + add/remove device flows. |
| `kchat-drive-mls-bridge` | native + wasm | MLS exporter-based key transport for Advanced + Max modes. `AdvancedTransportContext` / `MaxTransportContext`, `seal_advanced_domain_key`, `open_advanced_domain_key_and_store`, `seal_max_share_grant_key`, `open_max_share_grant_key_and_store`, `OrderingProof` (commit/tree-hash validation + post-merge assertion). |
| `kchat-drive-sync-core` | all | Target-neutral sync state machines: `OperationJournal` (Upload/Download/CreateFolder/Delete/Rename/ShareGrant/ShareRevoke/DomainKeyRotate), `DriveSyncState` per-node tracking, `SyncConflict` + `ResolutionStrategy`. |
| `kchat-client-runtime` | all | **Sole owner** of the MLS provider handle, `DriveKeyVault`, `OperationJournal`, `EpochBarrier`, and per-group mutation lock. Enforces architecture §19.1 invariants: single runtime, deny-by-default raw MLS mutations, fencing tokens, epoch barrier for key/epoch synchronization. Exposes `DriveFacade` for upload/download/create-domain/rotate-domain/create-share-grant/rotate-share-grant. |
| `kchat-drive-store-sqlite` | native | SQLCipher-backed persistence. `SqliteDriveStore` with embedded `SCHEMA_V1` (drive_keys, journal, sync_state, domain_keys, share_grant_keys). Uses `rusqlite` (bundled) + `refinery` migrations. |
| `kchat-drive-store-idb` | wasm | Browser IndexedDB persistence. `IdbDriveStore`, `TwoSlotSnapshot` (A/B atomic swap, architecture §19.5), `OrderedWriteSet` journal. |
| `kchat-drive-transport-core` | all | Target-neutral transport traits: `Transport` (sync), `AsyncTransport` (wasm-friendly, non-`Send` futures), `StreamSession` (read/write/checkpoint/cancel/progress), `DriveRequest`/`DriveResponse`, `DownloadCapability`/`UploadCapability`, `RetryConfig` + `with_retry`. |
| `kchat-drive-transport-native` | native | Desktop/mobile transport stub (tokio + platform HTTP client wiring). |
| `kchat-drive-transport-web` | wasm | Browser `FetchTransport` (async fetch + `JsFuture`), `WorkerCoordinator` (SharedWorker leader election via `navigator.locks`), `ServiceWorkerStream` (download streaming scaffold). |
| `kchat-drive-wasm` | wasm | `#[wasm_bindgen]` bindings exposing the full crypto + key-wrap API to JavaScript. Returns JSON strings for complex types, `Uint8Array` for plaintext, `bigint` for `u64`. |
| `kchat-drive-uniffi` | native | UniFFI bindings for iOS (Swift) and Android (Kotlin). `#[uniffi::export]` functions + `DriveSdkError` FFI error enum. |
| `kchat-drive-napi` | native | NAPI-RS bindings for Electron. `#[napi]` functions returning `Buffer` / `String` / typed objects. |
| `kchat-drive-demo` | native | Standalone TCP demo server (`127.0.0.1:3000`) serving an HTML page + JSON endpoints for encrypt/decrypt/sign/verify. Useful for testing the crypto core without a browser. |

## Build & test

```bash
# Native build + tests + lints:
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# WASM build (for the web sample):
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build crates/kchat-drive-wasm --target web --out-dir pkg
```

The workspace uses Rust **edition 2024** and the **stable** toolchain (see
`rust-toolchain.toml`). `rustfmt.toml` enforces 100-column width, field-init
shorthand, and try shorthand.

## Dependencies

This workspace depends on two sibling repos via path dependencies
(configured in the root `Cargo.toml`):

| Dependency | Path | Purpose |
| --- | --- | --- |
| `kchat-rust-sdk` | `../kchat-rust-sdk` | Provides `uq-openmls` (KChat's OpenMLS provider). |
| `openmls` (KChat fork) | `../openmls` | The OpenMLS crates (`openmls`, `openmls_traits`, `openmls_rust_crypto`, `openmls_basic_credential`) used by `kchat-drive-mls-bridge`. The fork is patched into `crates-io` via `[patch.crates-io]` so transitive deps resolve to the local copy. |

Notable third-party crates: `aes-gcm`, `hkdf`, `sha2`, `hpke` (X25519HkdfSha256
+ AesGcm256), `ed25519-dalek`, `minicbor` (canonical CBOR encoding), `zeroize`
+ `secrecy`, `rusqlite` (bundled) + `refinery`, `wasm-bindgen` + `web-sys` +
`js-sys`, `uniffi`, `napi` + `napi-derive`.

## Architecture

The full architecture is documented in [ARCHITECTURE.md](ARCHITECTURE.md).
The source-of-truth spec is `KChat-Privacy-Drive-Storage-Architecture-v1.0.md`
in the sibling `kdrive` repo; this SDK implements §19 (Client implementation),
§5 (Privacy modes), §8 (Key hierarchy), §9 (Crypto format), §10 (MLS bridge),
and §17 (Client API) of that spec.

Key invariants enforced by the runtime:

1. **Single runtime owns MLS provider + Drive vault** — no other code path can
   mutate MLS state or read raw keys.
2. **Raw MLS mutations are deny-by-default** for Drive-bound groups; all
   mutations go through the facade.
3. **Fencing tokens** prevent stale operations from a previous lease holder.
4. **Epoch barrier** blocks Drive operations until the new epoch's keys are
   derived and stored, preventing use of stale key material.

## Privacy modes

| Mode | DEK wrap key | Late joiner history | Admin recovery | User removal |
| --- | --- | --- | --- | --- |
| **Secured** (B2B default) | DomainKey (AES-256-GCM) | ✅ Can walk backward via chain | ✅ Domain key available | New generation blocks new versions |
| **Advanced** (B2B optional) | DomainKey + MLS exporter | ✅ Domain key shared | ❌ No MLS epoch key | New epoch blocks new versions |
| **Max** (B2C + high-security B2B) | ShareGrantKey (MLS-derived) | ❌ Future epochs only | ❌ No MLS key | New epoch excludes them |

In all three modes KChat (the server) cannot access or decrypt files.

## Demo

The `web-sample/` directory contains a React + Vite app that demonstrates all
three privacy modes against a live Go gateway. See [DEMO.md](DEMO.md) for
end-to-end setup and the `web-sample/README.md` for the WASM API reference.

A standalone native demo is also available:

```bash
cargo run -p kchat-drive-demo
# → KChat Drive demo server running at http://127.0.0.1:3000
```

This serves an HTML page with encrypt/decrypt/sign/verify forms backed by the
pure-Rust crypto core (no browser, no WASM, no gateway required).

## Cross-language test vectors

`kchat-drive-crypto::vector` generates deterministic KDF + round-trip test
vectors with known inputs (e.g. `version_dek = [0x42; 32]`,
`node_id = [0x01; 16]`). These are exposed via:

- `get_test_vectors_json()` in WASM / UniFFI / NAPI
- `GET /api/test-vectors` in the native demo server
- `GET /v1/vectors` in the Go gateway

The web sample's **Vectors** tab fetches both the Rust (WASM) and Go vectors and
verifies byte-equality of `protocol`, `version`, `suite`, and the round-trip
chunk plan root. This guarantees files encrypted by the Rust SDK can be
verified by the Go gateway and vice versa.

## Contributing

Run all checks before submitting changes:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

When adding a new crypto primitive, add a corresponding cross-language vector
to `crates/kchat-drive-crypto/src/vector.rs` and a test in
`crates/kchat-drive-crypto/tests/` so the Go gateway can verify byte-equality.

## License

Dual-licensed under `MIT OR Apache-2.0` (see `Cargo.toml` `[workspace.package]`).
