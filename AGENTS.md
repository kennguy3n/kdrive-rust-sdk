# kdrive-rust-sdk

Cross-platform Rust SDK for KChat Privacy Drive.

## Build & test

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Layout

- `crates/kchat-drive-types` — Canonical CBOR types, IDs, headers, envelopes, manifests, events, roles, errors.
- `crates/kchat-drive-crypto` — KDRV1 chunk AEAD, manifest encrypt/sign, HPKE envelopes, DomainKey chain, ShareGrantKey.
- `crates/kchat-drive-identity` — Account authority, device certs, per-device vault, enrollment.
- `crates/kchat-drive-mls-bridge` — MLS exporter-based key transport (Advanced + Max modes).
- `crates/kchat-client-runtime` — Sole owner of MLS provider + Drive vault + journal + epoch barrier.
- `crates/kchat-drive-sync-core` — State machines, operation journal, scheduling, conflicts.
- `crates/kchat-drive-store-sqlite` — SQLCipher native persistence.
- `crates/kchat-drive-store-idb` — Browser IndexedDB persistence.
- `crates/kchat-drive-transport-core` — Target-neutral transport traits.
- `crates/kchat-drive-transport-native` — Desktop/mobile transport.
- `crates/kchat-drive-transport-web` — Browser Fetch/Worker/ServiceWorker transport.
- `crates/kchat-drive-wasm` — WASM binding for web.
- `crates/kchat-drive-uniffi` — Swift + Kotlin bindings (iOS/Android).
- `crates/kchat-drive-napi` — Electron native addon.
- `web-sample/` — React + Vite web sample demonstrating the 3 privacy modes.

## Architecture

Source of truth: `KChat-Privacy-Drive-Storage-Architecture-v1.0.md` in the kdrive repo.
This SDK implements §19 (Client implementation), §5 (Privacy modes), §8 (Key hierarchy),
§9 (Crypto format), §10 (MLS bridge), §17 (Client API).

## Privacy modes

- **Secured (mode 1)**: DomainKey per tenant-governed domain + tenant recovery envelope.
- **Advanced (mode 2)**: DomainKey per MLS group/folder domain + encrypted backward chain.
- **Max (mode 3)**: ShareGrantKey per share grant; MLS exporter wraps ShareGrantKey.

In all 3 modes KChat (server) cannot access or decrypt files.
