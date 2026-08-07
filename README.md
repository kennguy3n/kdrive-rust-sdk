# kdrive-rust-sdk

Cross-platform Rust SDK for KChat Privacy Drive. Provides end-to-end encrypted
file storage with three privacy modes (Secured, Advanced, Max) backed by MLS
key management via OpenMLS.

## Architecture

See `/Users/Ken/workspaces/kdrive/KChat-Privacy-Drive-Storage-Architecture-v1.0.md`
for the full architecture specification.

## Crates

| Crate | Description |
| --- | --- |
| `kchat-drive-types` | Canonical CBOR types, IDs, headers, envelopes, manifests, events, roles, errors |
| `kchat-drive-crypto` | KDRV1 chunk AEAD, manifest encrypt/sign, HPKE recipient envelopes, DomainKey chain, ShareGrantKey |
| `kchat-drive-identity` | Account authority, device certificates, per-device vault, enrollment |
| `kchat-drive-mls-bridge` | MLS exporter-based key transport for Advanced + Max modes |
| `kchat-client-runtime` | Sole owner of MLS provider + Drive vault + journal |
| `kchat-drive-sync-core` | State machines, operation journal, scheduling, conflicts |
| `kchat-drive-store-sqlite` | SQLCipher native persistence |
| `kchat-drive-store-idb` | Browser IndexedDB persistence |
| `kchat-drive-transport-core` | Target-neutral transport traits |
| `kchat-drive-transport-native` | Desktop/mobile transport |
| `kchat-drive-transport-web` | Browser Fetch/Worker/ServiceWorker transport |
| `kchat-drive-wasm` | WASM binding for web |
| `kchat-drive-uniffi` | Swift + Kotlin bindings (iOS/Android) |
| `kchat-drive-napi` | Electron native addon |

## Build

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings

# WASM
cargo build -p kchat-drive-wasm --target wasm32-unknown-unknown
wasm-pack build crates/kchat-drive-wasm --target web
```

## Dependencies

This workspace depends on:
- `kchat-rust-sdk` (sibling repo at `/Users/Ken/workspaces/kchat-rust-sdk`)
- `openmls` KChat fork (sibling repo at `/Users/Ken/workspaces/openmls`)
