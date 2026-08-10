#!/bin/bash
# Build the Rust UniFFI library for all Android ABIs and copy the .so
# files into the jniLibs directory.
#
# Prerequisites:
#   - Android NDK installed (ANDROID_NDK_HOME or ANDROID_NDK_ROOT set)
#   - Rust Android targets installed:
#       rustup target add aarch64-linux-android armv7-linux-androideabi \
#         x86_64-linux-android i686-linux-android
#
# Usage:
#   cd samples/android-sample
#   ./build-android-libs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SDK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Check NDK
if [ -z "${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" ]; then
  echo "ERROR: ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set."
  echo "  Install the NDK via Android Studio's SDK Manager or:"
  echo "  export ANDROID_NDK_HOME=\$HOME/Library/Android/sdk/ndk/<version>"
  exit 1
fi

NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT}}"
echo "Using NDK: $NDK"

# Mapping of Rust targets to Android ABIs
TARGETS=(
  "aarch64-linux-android:arm64-v8a"
  "armv7-linux-androideabi:armeabi-v7a"
  "x86_64-linux-android:x86_64"
  "i686-linux-android:x86"
)

JNI_LIBS_DIR="$SCRIPT_DIR/app/src/main/jniLibs"
mkdir -p "$JNI_LIBS_DIR"

for entry in "${TARGETS[@]}"; do
  rust_target="${entry%%:*}"
  android_abi="${entry##*:}"

  echo "Building $rust_target → $android_abi …"

  cd "$SDK_ROOT"
  PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH" \
    cargo build -p kchat-drive-uniffi \
      --target "$rust_target" \
      --lib --release

  dest="$JNI_LIBS_DIR/$android_abi"
  mkdir -p "$dest"
  cp "target/$rust_target/release/libkchat_drive_uniffi.so" "$dest/"
  echo "  → $dest/libkchat_drive_uniffi.so"
done

echo ""
echo "Done! .so files are in: $JNI_LIBS_DIR"
echo "Now run: ./gradlew assembleDebug"
