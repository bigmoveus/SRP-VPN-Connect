#!/bin/bash
# SETest build script — links libSECore-mac.a + prefixed OpenSSL into a macOS harness.
set -e
cd "$(dirname "$0")"
SE="$(dirname "$PWD")"              # SoftEther dir
SDK="$(xcrun --sdk macosx --show-sdk-path)"

CLANG="$(xcrun -f clang)"
"$CLANG" -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
  -fobjc-arc -O1 -g \
  -I"$SE/bridge" \
  -I"$SE/upstream" -I"$SE/upstream/Mayaqua" -I"$SE/upstream/Cedar" \
  -I"$SE/openssl/macosx/include" -I"$SE/shim" \
  -include "$SE/openssl/openssl-prefix.h" \
  main.m \
  "$SE/build/macosx/libSECore.a" \
  "$SE/openssl/macosx/lib/libsrpse_ssl.a" "$SE/openssl/macosx/lib/libsrpse_crypto.a" \
  -lz -liconv -lpthread \
  -framework Foundation -framework Security -framework CoreFoundation \
  -o setest
echo BUILT setest
