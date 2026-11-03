#!/bin/bash
# Builds libSRPOpenVPN.a for iphoneos-arm64 and macosx-arm64 from the vendored
# OpenVPN 3 Core (release/3.11.7) + asio + lz4 + jsoncpp, linking the prefixed
# OpenSSL (srpse_*) from ../SoftEther/openssl/.
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
SE="$ROOT/../SoftEther"
UP="$ROOT/upstream"

build_one () {  # $1 = iphoneos|macosx
    local PLAT=$1
    local SDK SYSROOT MIN
    if [ "$PLAT" = iphoneos ]; then
        SDK=iphoneos; MIN="-miphoneos-version-min=15.0"
    else
        SDK=macosx; MIN="-mmacosx-version-min=12.0"
    fi
    SYSROOT="$(xcrun -sdk $SDK --show-sdk-path)"
    local OSSL="$SE/openssl/$PLAT"

    local B=/tmp/ovpn-obj-$PLAT
    rm -rf "$B" && mkdir -p "$B"

    local CXXFLAGS=(-arch arm64 -isysroot "$SYSROOT" $MIN -std=c++17 -O2 -w
        -DUSE_OPENSSL -DUSE_ASIO -DASIO_STANDALONE
        -DOPENVPN_EXTERNAL_TUN_FACTORY -DOPENVPN_EXTERNAL_TRANSPORT_FACTORY
        -I"$UP" -I"$UP/client" -I"$ROOT/asio/include" -I"$ROOT/lz4/lib" -I"$ROOT/jsoncpp/include"
        -I"$OSSL/include" -include "$SE/openssl/openssl-prefix.h")
    local CFLAGS=(-arch arm64 -isysroot "$SYSROOT" $MIN -O2 -w -I"$ROOT/lz4/lib")

    # the core client TU (the whole client library)
    xcrun clang++ "${CXXFLAGS[@]}" -x objective-c++ -c "$UP/client/ovpncli.cpp" -o "$B/ovpncli.o"
    # data epoch crypto implementation
    xcrun clang++ "${CXXFLAGS[@]}" -x objective-c++ -c "$UP/openvpn/crypto/data_epoch.cpp" -o "$B/data_epoch.o"
    # jsoncpp
    for j in json_reader json_value json_writer; do
        xcrun clang++ -arch arm64 -isysroot "$SYSROOT" $MIN -std=c++17 -O2 -w \
            -I"$ROOT/jsoncpp/include" \
            -c "$ROOT/jsoncpp/src/lib_json/$j.cpp" -o "$B/$j.o"
    done
    # lz4
    for l in lz4 lz4hc xxhash; do
        xcrun clang "${CFLAGS[@]}" -c "$ROOT/lz4/lib/$l.c" -o "$B/$l.o"
    done

    libtool -static -o "$ROOT/build/$PLAT/libSRPOpenVPN.a" "$B/"*.o
    echo "BUILT build/$PLAT/libSRPOpenVPN.a"
}

mkdir -p build/iphoneos build/macosx
build_one iphoneos
build_one macosx
echo ALL_DONE
