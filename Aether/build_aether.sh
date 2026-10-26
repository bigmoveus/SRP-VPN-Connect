#!/bin/bash
# Rebuilds libaether.a from the pinned upstream commit (CluvexStudio/Aether,
# AGPL-3.0). LTO must be OFF for the staticlib: with lto=fat the C FFI
# symbols get internalized and the archive exports nothing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIN="d58f9d568083129ce2c767c85054021eb3ee6a38"   # v2.4.0

WORK="${WORK:-$SCRIPT_DIR/.build/upstream}"
if [ ! -d "$WORK/.git" ]; then
    git clone https://github.com/CluvexStudio/Aether "$WORK"
fi
cd "$WORK"
git fetch --depth 1 origin "$PIN" 2>/dev/null || true
git reset --hard -q "$PIN"   # also drops leftovers of a previously applied patch set
for p in "$SCRIPT_DIR/patches/"*.patch; do
    [ -e "$p" ] && git apply "$p"
done

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
rustup target add aarch64-apple-ios >/dev/null 2>&1 || true

cd aether
IPHONEOS_DEPLOYMENT_TARGET=15.0 CARGO_PROFILE_RELEASE_LTO=false \
    cargo build --release --lib --target aarch64-apple-ios --features tor

mkdir -p "$SCRIPT_DIR/lib/iphoneos"
cp target/aarch64-apple-ios/release/libaether.a "$SCRIPT_DIR/lib/iphoneos/libaether.a"
echo "=== libaether.a rebuilt ($PIN) ==="
