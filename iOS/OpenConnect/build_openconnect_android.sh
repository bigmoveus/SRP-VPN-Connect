#!/bin/bash
# Builds build/android-arm64/libSRPOpenConnect.a for the Android app from the same vendored openconnect 9.21 sources
# (upstream/) as the iOS library, with upstream's JNI binding (jni.c, used through LibOpenConnect.java) and the SRP fragment
# BIO. TLS: the OpenSSL 3 of the Android SoftEther core (../SoftEther/build_openssl_android.sh); XML: libxml2/android-arm64
# (build_libxml2_android.sh). libsrpopenconnect.so (Android/app/src/main/cpp/CMakeLists.txt) links the archive whole.
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$PWD"
NDK="${ANDROID_NDK_ROOT:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"
TOOLS="$NDK/toolchains/llvm/prebuilt/darwin-x86_64"
API=26

# autotools break on the spaces in the repository's path: stage everything in a space-free directory
B="${TMPDIR:-/tmp}/srp-oc-android"
rm -rf "$B" && mkdir -p "$B"
cp -Rp "$ROOT/upstream" "$B/src"   # -p: newer copies of configure.ac would make make run autoconf
cp "$ROOT/../Core/SRPCore/SRPFragBio.h" "$ROOT/../Core/SRPCore/SRPFragBio.c" "$B/src/"
cp -R "$ROOT/../SoftEther/openssl/android-arm64" "$B/openssl"
cp "$B/openssl/lib/libssl.a" "$B/openssl/lib/libcrypto.a" "$B/openssl/"   # where configure's --with-openssl=DIR looks
cp -R "$ROOT/libxml2/android-arm64" "$B/libxml2"

export CC="$TOOLS/bin/aarch64-linux-android$API-clang"
export AR="$TOOLS/bin/llvm-ar" RANLIB="$TOOLS/bin/llvm-ranlib" STRIP="$TOOLS/bin/llvm-strip"
cd "$B/src"
ac_cv_func_HMAC_CTX_copy=yes ./configure --host=aarch64-linux-android \
    --with-openssl="$B/openssl" --without-gnutls --without-lz4 --without-libproxy \
    --without-stoken --without-libpcsclite --without-libpskc --without-gssapi \
    --disable-nls --enable-static --disable-shared --with-java="$TOOLS/sysroot/usr/include" --enable-jni-standalone \
    --with-vpnc-script=/system/bin/false \
    LIBXML2_CFLAGS="-I$B/libxml2/include/libxml2" LIBXML2_LIBS="-L$B/libxml2/lib -lxml2" \
    CFLAGS="-O2 -fPIC -I$B/src -Wno-deprecated-declarations -w" > configure.log 2>&1
make -j"$(sysctl -n hw.ncpu)" > make.log 2>&1 || true   # the serverhash tool may fail; the library objects are what we need
[ -f libopenconnect_la-jni.o ] || { echo "the JNI binding was not built (see make.log)" >&2; exit 1; }
"$CC" -O2 -fPIC -I"$B/openssl/include" -I"$B/src" -w -c SRPFragBio.c -o SRPFragBio.o
mkdir -p "$ROOT/build/android-arm64"
rm -f "$ROOT/build/android-arm64/libSRPOpenConnect.a"
"$AR" rcs "$ROOT/build/android-arm64/libSRPOpenConnect.a" libopenconnect_la-*.o json/libopenconnect_la-*.o SRPFragBio.o
echo "BUILT build/android-arm64/libSRPOpenConnect.a"
