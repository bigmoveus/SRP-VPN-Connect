#!/bin/bash
# Rebuilds libaether.a from our fork of Aether (github.com/bigmoveus/Aether, AGPL-3.0): upstream v2.4.0 with the
# app's changes as commits (the Let's Encrypt YE2 pin, the logger and Tor through the C interface, the SOCKS5 request
# log at debug level, outbound netstack packets kept when the carrier's channel is full), pinned by the commit of tag
# v2.4.0-srp.2.
# LTO must be OFF for the staticlib: with lto=fat the C FFI symbols get internalized and the archive exports nothing.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PIN="afc2f7288be6e7c9ae20e99e19f3c18ebda983da"   # tag v2.4.0-srp.2

WORK="${WORK:-$SCRIPT_DIR/.build/fork}"
if [ ! -d "$WORK/.git" ]; then
    git clone https://github.com/bigmoveus/Aether "$WORK"
fi
cd "$WORK"
git fetch --depth 1 origin "$PIN" 2>/dev/null || true
git reset --hard -q "$PIN"

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"
rustup target add aarch64-apple-ios >/dev/null 2>&1 || true

cd aether
IPHONEOS_DEPLOYMENT_TARGET=15.0 CARGO_PROFILE_RELEASE_LTO=false \
    cargo build --release --lib --target aarch64-apple-ios --features tor

mkdir -p "$SCRIPT_DIR/lib/iphoneos"
cp target/aarch64-apple-ios/release/libaether.a "$SCRIPT_DIR/lib/iphoneos/libaether.a"
echo "=== libaether.a rebuilt ($PIN) ==="
