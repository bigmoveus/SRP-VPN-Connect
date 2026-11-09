#!/bin/bash
# Rebuilds libsrpwg-go.a: one Go c-archive exporting both engines —
# wireguard-go (wg* symbols, latest upstream) and amneziawg-go
# (awg* symbols, pinned tag in bridge/go.mod).
# One Go runtime per process is mandatory: two c-archives would clash
# (each ships its own runtime).
# Output: WireGuard/lib/{iphoneos,macosx}/libsrpwg-go.a
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Build with the Go version go.mod declares.
export GOTOOLCHAIN=go1.26.0+auto

# Paths with spaces break the Makefile's CURDIR-based rules — build in /tmp
# and copy the artifacts back.
WORK=/tmp/srpwg-bridge-build
if [ -d "$WORK/.tmp" ]; then chmod -R u+w "$WORK/.tmp"; fi
rm -rf "$WORK"
cp -R "$SCRIPT_DIR/bridge" "$WORK"
cd "$WORK"

# iOS device (arm64)
if [ -d .tmp ]; then chmod -R u+w .tmp; fi
rm -rf .tmp
make ARCHS=arm64 PLATFORM_NAME=iphoneos \
     DEPLOYMENT_TARGET_CLANG_FLAG_NAME=miphoneos-version-min \
     DEPLOYMENT_TARGET_CLANG_ENV_NAME=IPHONEOS_DEPLOYMENT_TARGET \
     IPHONEOS_DEPLOYMENT_TARGET=15.0 \
     CONFIGURATION_BUILD_DIR="$WORK/out-ios"
mkdir -p "$SCRIPT_DIR/lib/iphoneos"
cp out-ios/libsrpwg-go.a "$SCRIPT_DIR/lib/iphoneos/libsrpwg-go.a"

# macOS (for local harness tests)
if [ -d .tmp ]; then chmod -R u+w .tmp; fi
rm -rf .tmp
make ARCHS=arm64 PLATFORM_NAME=macosx \
     DEPLOYMENT_TARGET_CLANG_FLAG_NAME=mmacosx-version-min \
     DEPLOYMENT_TARGET_CLANG_ENV_NAME=MACOSX_DEPLOYMENT_TARGET \
     MACOSX_DEPLOYMENT_TARGET=12.0 \
     CONFIGURATION_BUILD_DIR="$WORK/out-mac"
mkdir -p "$SCRIPT_DIR/lib/macosx"
cp out-mac/libsrpwg-go.a "$SCRIPT_DIR/lib/macosx/libsrpwg-go.a"

echo "=== libsrpwg-go rebuilt (wireguard-go + amneziawg-go) ==="
