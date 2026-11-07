#!/bin/bash
# OpenSSL for the SoftEther core in the Android app (libsrpse.so): OpenSSL 3.5 LTS, static, arm64, API 26.
# The WaterWall runtime's OpenSSL 4 has opaque ASN1 strings that the SoftEther core still reads directly, so the core keeps
# OpenSSL 3, as on iOS. libsrpse.so exports only its JNI functions, so these symbols need no prefix: they stay inside it.
# Output: openssl/android-arm64/{include,lib}. Needs the NDK of Android/app/build.gradle.kts.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=3.5.9
NDK="${ANDROID_NDK_ROOT:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"
WORK="${TMPDIR:-/tmp}/srp-openssl-android"
OUT="$PWD/openssl/android-arm64"
rm -rf "$WORK" && mkdir -p "$WORK"
curl -fsSL -o "$WORK/openssl.tar.gz" "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz"
curl -fsSL -o "$WORK/openssl.tar.gz.sha256" "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz.sha256"
expected=$(awk '{print $1}' "$WORK/openssl.tar.gz.sha256")
actual=$(shasum -a 256 "$WORK/openssl.tar.gz" | awk '{print $1}')
[ "$expected" = "$actual" ] || { echo "checksum mismatch: $actual, expected $expected" >&2; exit 1; }
tar -xzf "$WORK/openssl.tar.gz" -C "$WORK"
cd "$WORK/openssl-$VERSION"
export ANDROID_NDK_ROOT="$NDK"
export PATH="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH"
./Configure android-arm64 no-asm no-shared no-dso no-engine no-tests no-comp no-docs -D__ANDROID_API__=26 > configure.log 2>&1
make -j"$(sysctl -n hw.ncpu)" build_libs > make.log 2>&1
rm -rf "$OUT" && mkdir -p "$OUT/lib"
cp libssl.a libcrypto.a "$OUT/lib/"
cp -R include "$OUT/include"
find "$OUT/include" -name "*.in" -delete
echo "built OpenSSL $VERSION ($actual) into $OUT"
