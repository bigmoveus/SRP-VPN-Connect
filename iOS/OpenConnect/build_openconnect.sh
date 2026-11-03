#!/bin/bash
# Builds libSRPOpenConnect.a for iphoneos-arm64 and macosx-arm64 from the
# vendored openconnect 9.21 sources (upstream/), linking the prefixed OpenSSL
# (srpse_*) from ../SoftEther/openssl/.
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
SE="$ROOT/../SoftEther"

build_one () {  # $1 = iphoneos|macosx
    local PLAT=$1
    local SDK SYSROOT MIN HOSTC
    if [ "$PLAT" = iphoneos ]; then
        SDK=iphoneos; MIN="-miphoneos-version-min=15.0"; HOSTC="--host=arm-apple-darwin"
    else
        SDK=macosx; MIN="-mmacosx-version-min=12.0"; HOSTC=""
    fi
    SYSROOT="$(xcrun -sdk $SDK --show-sdk-path)"

    # prefixed OpenSSL with stock names, space-free path (autotools breaks on spaces)
    local OSSL=/tmp/oc-ossl-$PLAT
    mkdir -p "$OSSL/lib" "$OSSL/include"
    cp "$SE/openssl/$PLAT/lib/libsrpse_ssl.a" "$OSSL/libssl.a"
    cp "$SE/openssl/$PLAT/lib/libsrpse_crypto.a" "$OSSL/libcrypto.a"
    cp -r "$SE/openssl/$PLAT/include/openssl" "$OSSL/include/"
    cp "$SE/openssl/openssl-prefix.h" "$OSSL/openssl-prefix.h"

    local B=/tmp/oc-build-$PLAT
    rm -rf "$B" && cp -r "$ROOT/upstream" "$B"
    # The repo path contains spaces (autotools breaks) — stage the fragment
    # BIO into the space-free build dir.
    cp "$ROOT/../Core/SRPCore/SRPFragBio.h" "$ROOT/../Core/SRPCore/SRPFragBio.c" "$B/"
    cd "$B"
    ac_cv_func_HMAC_CTX_copy=yes ./configure $HOSTC \
        --with-openssl="$OSSL" --without-gnutls --without-lz4 --without-libproxy \
        --without-stoken --without-libpcsclite --without-libpskc --without-gssapi \
        --disable-nls --enable-static --disable-shared \
        --with-vpnc-script=/usr/local/bin/vpnc-script \
        OPENSSL_CFLAGS="-I$OSSL/include" \
        CFLAGS="-arch arm64 -isysroot $SYSROOT $MIN -include $OSSL/openssl-prefix.h -I$B -Wno-deprecated-declarations -w" \
        LDFLAGS="-arch arm64 -isysroot $SYSROOT" > configure.log 2>&1
    make -j"$(sysctl -n hw.ncpu)" > make.log 2>&1 || true   # serverhash tool may fail; lib objects are what we need
    # SRPFragBio: the TLS write-splitting filter BIO referenced by openssl.c
    xcrun clang -arch arm64 -isysroot "$SYSROOT" $MIN \
        -include "$OSSL/openssl-prefix.h" -I"$OSSL/include" -I"$B" -w \
        -c "$B/SRPFragBio.c" -o SRPFragBio.o
    libtool -static -o "$ROOT/build/$PLAT/libSRPOpenConnect.a" libopenconnect_la-*.o json/libopenconnect_la-*.o SRPFragBio.o
    echo "BUILT build/$PLAT/libSRPOpenConnect.a"
    cd "$ROOT"
}

mkdir -p build/iphoneos build/macosx
build_one iphoneos
build_one macosx
echo ALL_DONE
