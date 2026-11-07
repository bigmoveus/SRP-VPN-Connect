#!/bin/bash
# libxml2 for the OpenConnect core of the Android app (libsrpopenconnect.so): static, arm64, API 26. libopenconnect reads the
# servers' XML with it (AnyConnect's login forms and settings, GlobalProtect's configuration); iOS links the SDK's libxml2.
# No iconv (Bionic's needs API 28, minSdk is 26): the servers' XML is UTF-8, which libxml2 reads on its own.
# Output: libxml2/android-arm64/{include,lib}. Needs the NDK of Android/app/build.gradle.kts.
set -euo pipefail
cd "$(dirname "$0")"
VERSION=2.15.4
SERIES="${VERSION%.*}"
NDK="${ANDROID_NDK_ROOT:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"
CMAKE="${CMAKE:-$HOME/Library/Android/sdk/cmake/4.1.2/bin/cmake}"
WORK="${TMPDIR:-/tmp}/srp-libxml2-android"
OUT="$PWD/libxml2/android-arm64"
rm -rf "$WORK" && mkdir -p "$WORK"
curl -fsSL -o "$WORK/libxml2.tar.xz" "https://download.gnome.org/sources/libxml2/$SERIES/libxml2-$VERSION.tar.xz"
curl -fsSL -o "$WORK/libxml2.sha256sum" "https://download.gnome.org/sources/libxml2/$SERIES/libxml2-$VERSION.sha256sum"
expected=$(awk '/\.tar\.xz$/ {print $1}' "$WORK/libxml2.sha256sum")
actual=$(shasum -a 256 "$WORK/libxml2.tar.xz" | awk '{print $1}')
[ -n "$expected" ] && [ "$expected" = "$actual" ] || { echo "checksum mismatch: $actual, expected $expected" >&2; exit 1; }
tar -xJf "$WORK/libxml2.tar.xz" -C "$WORK"
"$CMAKE" -S "$WORK/libxml2-$VERSION" -B "$WORK/build" -G "Unix Makefiles" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=26 \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX="$WORK/install" -DCMAKE_INSTALL_SYSCONFDIR=/etc \
    -DLIBXML2_WITH_ICONV=OFF -DLIBXML2_WITH_ICU=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ZLIB=OFF \
    -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_PROGRAMS=OFF -DLIBXML2_WITH_TESTS=OFF > "$WORK/configure.log" 2>&1
"$CMAKE" --build "$WORK/build" -j"$(sysctl -n hw.ncpu)" > "$WORK/make.log" 2>&1
"$CMAKE" --install "$WORK/build" > "$WORK/install.log" 2>&1
rm -rf "$OUT" && mkdir -p "$OUT/lib"
cp "$WORK/install/lib/libxml2.a" "$OUT/lib/"
# The NDK's toolchain file builds with -g; the app strips its libraries anyway, so the archive need not carry it
"$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip" --strip-debug "$OUT/lib/libxml2.a"
cp -R "$WORK/install/include" "$OUT/include"
echo "built libxml2 $VERSION ($actual) into $OUT"
