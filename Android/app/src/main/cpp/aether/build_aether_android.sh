#!/bin/bash
# build_aether_android.sh ABI OUTPUT: builds libaether.so for Android from our fork of Aether (github.com/bigmoveus/Aether,
# AGPL-3.0) at the commit iOS/Aether/build_aether.sh pins (tag v2.4.0-srp.2), with cargo-ndk as upstream's release
# workflow builds its Android binaries (BoringSSL with a static libc++), and copies it to OUTPUT. Needs Rust (cargo),
# cargo-ndk and the target (rustup target add aarch64-linux-android); the NDK is the one CMake builds with.
set -euo pipefail
ABI="$1"
OUTPUT="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIN="$(sed -n 's/^PIN="\([0-9a-f]*\)".*/\1/p' "$SCRIPT_DIR/../../../../../../iOS/Aether/build_aether.sh")"
[ -n "$PIN" ] || { echo "no pinned commit in iOS/Aether/build_aether.sh" >&2; exit 1; }
case "$ABI" in
    arm64-v8a) TARGET=aarch64-linux-android ;;
    x86_64) TARGET=x86_64-linux-android ;;
    *) echo "Aether: no Rust target for $ABI" >&2; exit 1 ;;
esac

WORK="${WORK:-$SCRIPT_DIR/.build/fork}"
if [ ! -d "$WORK/.git" ]; then
    git clone https://github.com/bigmoveus/Aether "$WORK"
fi
cd "$WORK"
if [ "$(git rev-parse HEAD 2>/dev/null)" != "$PIN" ]; then
    git fetch --depth 1 origin "$PIN" 2>/dev/null || git fetch origin
    git reset --hard -q "$PIN"
fi

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
export ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK:-$HOME/Library/Android/sdk/ndk/28.2.13676358}}"
export ANDROID_NDK_ROOT="$ANDROID_NDK_HOME"
under=$(echo "$TARGET" | tr '-' '_')
export "BORING_BSSL_RUST_CPPLIB_${under}=static:-bundle=c++"
export CARGO_PROFILE_RELEASE_LTO=false
# The library names itself, so libsrpaether.so needs "libaether.so" and not the build path it was linked from
export "CARGO_TARGET_$(echo "$under" | tr '[:lower:]' '[:upper:]')_RUSTFLAGS=-C link-arg=-Wl,-soname,libaether.so"
cd aether
cargo ndk -t "$ABI" --platform 26 build --release --lib --features tor
mkdir -p "$(dirname "$OUTPUT")"
cp "target/$TARGET/release/libaether.so" "$OUTPUT"
echo "=== libaether.so ($PIN) for $ABI ==="
