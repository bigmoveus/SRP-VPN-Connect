#!/bin/bash
# Builds the macOS test harness for the SSH engine.
set -e
cd "$(dirname "$0")"
ROOT="$PWD/.."
CORE="$ROOT/../Core/SRPCore"

xcrun clang -arch arm64 -isysroot "$(xcrun -sdk macosx --show-sdk-path)" \
    -mmacosx-version-min=12.0 -O0 -g -fobjc-arc -w \
    -DNS_BLOCK_ASSERTIONS=0 \
    -I"$CORE" \
    -I"$ROOT/libssh2/include" \
    -I"$ROOT/upstream/src" \
    -I"$ROOT/upstream/src/core/src" \
    -I"$ROOT/build" \
    -framework Foundation -framework NetworkExtension -framework Security \
    "$ROOT/../Core/SRPCore/SRPSSHClient.m" \
    "$ROOT/../Core/SRPCore/SRPSSHBridge.c" \
    "$ROOT/../Core/SRPCore/SSLog.m" \
    main.m \
    "$ROOT/build/macosx/libSRPSSH2.a" \
    "$ROOT/build/macosx/libSRPSSHEngine.a" \
    "$ROOT/../SoftEther/openssl/macosx/lib/libsrpse_ssl.a" \
    "$ROOT/../SoftEther/openssl/macosx/lib/libsrpse_crypto.a" \
    -lz -liconv -lresolv \
    -o sshtest
echo BUILT sshtest
