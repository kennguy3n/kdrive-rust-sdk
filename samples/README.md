# KChat Drive — Platform Samples

Three sample apps demonstrating the KChat Drive Rust SDK on each client
platform. All three use the same Rust crypto core (`kchat-drive-crypto`)
via different binding mechanisms.

| Platform | Binding | Sample | Status |
| --- | --- | --- | --- |
| **iOS** | UniFFI → Swift | [`ios-sample/`](ios-sample/) | Builds + runs in simulator |
| **Android** | UniFFI → Kotlin (JNA) | [`android-sample/`](android-sample/) | Project ready (needs Android SDK to build) |
| **Electron** | NAPI-RS → Node addon | [`electron-sample/`](electron-sample/) | Builds + runs |

## Quick start

### Prerequisites

```bash
# Rust targets (one-time):
rustup target add aarch64-apple-ios aarch64-apple-ios-sim wasm32-unknown-unknown

# UniFFI bindgen (one-time):
cargo install uniffi --version 0.31.2 --locked --features cli

# NAPI-RS CLI (one-time):
npm install -g @napi-rs/cli

# xcodegen (one-time, for iOS project generation):
brew install xcodegen
```

### Build all bindings

```bash
cd /path/to/kdrive-rust-sdk

# 1. iOS static library (device + simulator)
cargo build -p kchat-drive-uniffi --target aarch64-apple-ios --lib --release
cargo build -p kchat-drive-uniffi --target aarch64-apple-ios-sim --lib

# 2. Generate Swift + Kotlin bindings
uniffi-bindgen generate --library target/aarch64-apple-ios-sim/debug/libkchat_drive_uniffi.a \
  --language swift --out-dir bindings/swift
uniffi-bindgen generate --library target/aarch64-apple-ios-sim/debug/libkchat_drive_uniffi.a \
  --language kotlin --out-dir bindings/kotlin

# 3. Electron NAPI addon
cd crates/kchat-drive-napi
napi build --platform --release --output-dir ./dist
```

### Run the samples

```bash
# iOS (simulator):
cd samples/ios-sample/KchatDriveIOS
xcodegen generate
xcodebuild -project KchatDriveIOS.xcodeproj -scheme KchatDriveIOS \
  -destination 'platform=iOS Simulator,name=iPhone 17' build
xcrun simctl install booted build/Build/Products/Debug-iphonesimulator/KchatDriveIOS.app
xcrun simctl launch booted ai.kchat.drive.ios-sample

# Electron:
cd samples/electron-sample
npm install
unset ELECTRON_RUN_AS_NODE  # if set in your environment
npm start

# Android (needs Android SDK + NDK):
cd samples/android-sample
./build-android-libs.sh  # builds Rust .so files for all ABIs
./gradlew assembleDebug
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Architecture

```
                    ┌─────────────────────┐
                    │  kchat-drive-crypto  │
                    │  (Rust core)         │
                    └──────┬──────────────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
     ┌────────▼───┐  ┌─────▼─────┐  ┌───▼──────────┐
     │  UniFFI    │  │  UniFFI   │  │  NAPI-RS     │
     │  → Swift   │  │  → Kotlin │  │  → .node     │
     └────────┬───┘  └─────┬─────┘  └───┬──────────┘
              │            │            │
     ┌────────▼───┐  ┌─────▼─────┐  ┌───▼──────────┐
     │  iOS App   │  │  Android  │  │  Electron    │
     │  (SwiftUI) │  │  (Kotlin) │  │  (HTML/JS)   │
     └────────────┘  └───────────┘  └──────────────┘
```

All three apps demonstrate the same three operations:
1. **Key Generation** — VersionDEK, Ed25519, HPKE keypairs
2. **Encrypt / Decrypt Round-Trip** — full KDRV1 pipeline through the Rust core
3. **Cross-Language Test Vectors** — KDRV1 test vectors for Go gateway verification
