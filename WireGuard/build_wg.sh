#!/bin/bash
# Rebuilds libsrpwg-go.a: one Go c-archive exporting ALL engines —
# wireguard-go (wg* symbols, latest upstream), amneziawg-go
# (awg* symbols, pinned tag in bridge/go.mod) and the Psiphon clientlib
# (srppsi* symbols, vendored psiphon-tunnel-core, pinned commit below).
# One Go runtime per process is mandatory: two c-archives would clash
# (each ships its own runtime).
# Output: WireGuard/lib/{iphoneos,macosx}/libsrpwg-go.a
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

PSIPHON_PIN="d5b23279c4"

# The psiphon-tunnel-core vendor tree is gitignored (78MB): clone the pinned
# commit into the bridge dir if missing (go.mod replaces the module with it)
if [ ! -d "$SCRIPT_DIR/bridge/psiphon-tunnel-core/psiphon" ]; then
    rm -rf /tmp/psiphon-tunnel-core-clone
    git clone -q https://github.com/Psiphon-Labs/psiphon-tunnel-core /tmp/psiphon-tunnel-core-clone
    git -C /tmp/psiphon-tunnel-core-clone checkout -q "$PSIPHON_PIN"
    rm -rf "$SCRIPT_DIR/bridge/psiphon-tunnel-core"
    rsync -a --exclude=.git /tmp/psiphon-tunnel-core-clone/ "$SCRIPT_DIR/bridge/psiphon-tunnel-core/"
fi

# Paths with spaces break the Makefile's CURDIR-based rules — build in /tmp
# and copy the artifacts back.
WORK=/tmp/srpwg-bridge-build
rm -rf "$WORK"
cp -R "$SCRIPT_DIR/bridge" "$WORK"
cd "$WORK"

# iOS device (arm64)
rm -rf .tmp
make ARCHS=arm64 PLATFORM_NAME=iphoneos \
     DEPLOYMENT_TARGET_CLANG_FLAG_NAME=miphoneos-version-min \
     DEPLOYMENT_TARGET_CLANG_ENV_NAME=IPHONEOS_DEPLOYMENT_TARGET \
     IPHONEOS_DEPLOYMENT_TARGET=15.0 \
     CONFIGURATION_BUILD_DIR="$WORK/out-ios"
mkdir -p "$SCRIPT_DIR/lib/iphoneos"
cp out-ios/libsrpwg-go.a "$SCRIPT_DIR/lib/iphoneos/libsrpwg-go.a"

# macOS (for local harness tests)
rm -rf .tmp
make ARCHS=arm64 PLATFORM_NAME=macosx \
     DEPLOYMENT_TARGET_CLANG_FLAG_NAME=mmacosx-version-min \
     DEPLOYMENT_TARGET_CLANG_ENV_NAME=MACOSX_DEPLOYMENT_TARGET \
     MACOSX_DEPLOYMENT_TARGET=12.0 \
     CONFIGURATION_BUILD_DIR="$WORK/out-mac"
mkdir -p "$SCRIPT_DIR/lib/macosx"
cp out-mac/libsrpwg-go.a "$SCRIPT_DIR/lib/macosx/libsrpwg-go.a"

echo "=== libsrpwg-go rebuilt (wireguard-go + amneziawg-go) ==="
