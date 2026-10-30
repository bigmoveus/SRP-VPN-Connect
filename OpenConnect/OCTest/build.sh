#!/bin/bash
# OCTest build script — links libopenconnect (macOS) + prefixed OpenSSL.
set -e
cd "$(dirname "$0")"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
OCLIB="$(cd .. && pwd)"   # vendored OpenConnect/
SE="$(cd ../.. && pwd)/SoftEther"

CLANG="$(xcrun -f clang)"
"$CLANG" -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
  -fobjc-arc -O1 -g \
  -I"$OCLIB/upstream" \
  main.m \
  "$OCLIB/build/macosx/libSRPOpenConnect.a" \
  /tmp/oc-ossl-macosx/libssl.a /tmp/oc-ossl-macosx/libcrypto.a \
  -lz -liconv -lxml2 -lresolv \
  -framework Foundation -framework Security -framework CoreFoundation \
  -o octest
echo BUILT octest
