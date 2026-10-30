#!/bin/bash
# Builds the macOS test harness for the OpenVPN engine.
set -e
cd "$(dirname "$0")"
ROOT="$PWD/.."
CORE="$ROOT/../Core/SRPCore"
SDK="$(xcrun -sdk macosx --show-sdk-path)"

# ObjC++ TU (C++17) — the client façade
xcrun clang++ -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
    -std=c++17 -O0 -g -fobjc-arc -w \
    -I"$CORE" \
    -I"$ROOT/upstream" -I"$ROOT/upstream/client" -I"$ROOT/asio/include" \
    -I"$ROOT/lz4/lib" -I"$ROOT/jsoncpp/include" \
    -I"$ROOT/../SoftEther/openssl/macosx/include" \
    -include "$ROOT/../SoftEther/openssl/openssl-prefix.h" \
    -DUSE_OPENSSL -DUSE_ASIO -DASIO_STANDALONE \
    -DOPENVPN_EXTERNAL_TUN_FACTORY -DOPENVPN_EXTERNAL_TRANSPORT_FACTORY \
    -c "$CORE/SRPOpenVPNClient.mm" -o /tmp/SRPOpenVPNClient.o

# ObjC TUs
xcrun clang -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
    -O0 -g -fobjc-arc -w -I"$CORE" -c "$CORE/SSLog.m" -o /tmp/SSLog-ovpn.o
xcrun clang -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
    -O0 -g -fobjc-arc -w -I"$CORE" -c main.m -o /tmp/ovpntest-main.o

xcrun clang++ -arch arm64 -isysroot "$SDK" -mmacosx-version-min=12.0 \
    -framework Foundation -framework NetworkExtension -framework Security -framework Network \
    /tmp/SRPOpenVPNClient.o /tmp/SSLog-ovpn.o /tmp/ovpntest-main.o \
    "$ROOT/build/macosx/libSRPOpenVPN.a" \
    "$ROOT/../SoftEther/openssl/macosx/lib/libsrpse_ssl.a" \
    "$ROOT/../SoftEther/openssl/macosx/lib/libsrpse_crypto.a" \
    -lz -liconv -lresolv \
    -o ovpntest
echo BUILT ovpntest
