# KChat Drive — Android Sample

A minimal Android app that uses the KChat Drive UniFFI Kotlin bindings to
demonstrate the KDRV1 crypto pipeline (key generation, encrypt/decrypt
round-trip, cross-language test vectors).

## Prerequisites

- Android Studio or Android SDK + NDK
- JDK 17+
- The Rust static library for Android targets must be built:
  ```bash
  # Add Android targets (one-time):
  rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

  # Build (requires Android NDK):
  cargo build -p kchat-drive-uniffi --target aarch64-linux-android --lib --release
  cargo build -p kchat-drive-uniffi --target armv7-linux-androideabi --lib --release
  cargo build -p kchat-drive-uniffi --target x86_64-linux-android --lib --release
  cargo build -p kchat-drive-uniffi --target i686-linux-android --lib --release
  ```

- The `.so` files must be packaged into a JNA-loadable AAR or placed in
  `app/src/main/jniLibs/<abi>/`. See the build script below.

## Build

```bash
cd samples/android-sample
./gradlew assembleDebug
```

The APK will be at `app/build/outputs/apk/debug/app-debug.apk`.

## Run

```bash
# Install on a connected device/emulator:
./gradlew installDebug
# Or:
adb install app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n ai.kchat.drive.sample/.MainActivity
```

## Architecture

```
┌──────────────────────────────────────────────┐
│  Android App (Kotlin)                         │
│                                               │
│  MainActivity.kt                              │
│    → uniffi.kchat_drive_uniffi.*              │
└──────────────────┬───────────────────────────┘
                   │ JNA (Java Native Access)
┌──────────────────▼───────────────────────────┐
│  libkchat_drive_uniffi.so                     │
│  (Rust crypto core, compiled for Android)     │
└──────────────────────────────────────────────┘
```

The Kotlin bindings (`uniffi/kchat_drive_uniffi/kchat_drive_uniffi.kt`) use
JNA to call into the native Rust shared library. No JNI boilerplate is
needed — UniFFI handles all the FFI marshalling.

## Packaging the .so files

The Rust `.so` files need to be placed in `app/src/main/jniLibs/<abi>/`:

```
app/src/main/jniLibs/
├── arm64-v8a/libkchat_drive_uniffi.so
├── armeabi-v7a/libkchat_drive_uniffi.so
├── x86_64/libkchat_drive_uniffi.so
└── x86/libkchat_drive_uniffi.so
```

You can copy them from the Rust target directory:

```bash
for abi in aarch64-linux-android:arm64-v8a \
           armv7-linux-androideabi:armeabi-v7a \
           x86_64-linux-android:x86_64 \
           i686-linux-android:x86; do
  rust_target=${abi%%:*}
  android_abi=${abi##*:}
  cp target/${rust_target}/release/libkchat_drive_uniffi.so \
     app/src/main/jniLibs/${android_abi}/
done
```
