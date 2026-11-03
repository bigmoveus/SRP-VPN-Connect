#!/bin/bash
# Builds libssh2 (static, OpenSSL backend) for iphoneos-arm64 and macosx-arm64
# by direct compilation (no autotools — its OpenSSL detection can't handle our
# prefixed srpse_* build). Links the prefixed OpenSSL from ../SoftEther/openssl/.
# Output: build/<platform>/libSRPSSH2.a
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
SE="$ROOT/../SoftEther"

SOURCES="agent.c bcrypt_pbkdf.c channel.c comp.c chacha.c cipher-chachapoly.c \
crypt.c crypto.c global.c hostkey.c keepalive.c kex.c knownhost.c mac.c misc.c \
openssl.c packet.c pem.c poly1305.c publickey.c scp.c session.c sftp.c \
transport.c userauth.c userauth_kbd_packet.c version.c"

write_config () {  # $1 = output dir
    cat > "$1/libssh2_config.h" <<'EOF'
/* Hand-written config for Darwin (iOS/macOS) builds — replaces autotools. */
#ifndef LIBSSH2_CONFIG_H
#define LIBSSH2_CONFIG_H

#define LIBSSH2_OPENSSL 1

#define HAVE_UNISTD_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_SYS_UIO_H 1
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_IOCTL_H 1
#define HAVE_SYS_TIME_H 1
#define HAVE_SYS_UN_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1

#define HAVE_GETTIMEOFDAY 1
#define HAVE_STRTOLL 1
#define HAVE_SNPRINTF 1
#define HAVE_MEMSET_S 1
#define HAVE_POLL 1
#define HAVE_SELECT 1

#define HAVE_O_NONBLOCK 1
#define HAVE_FIONBIO 1

#endif
EOF
}

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

    local B=/tmp/ssh-obj-$PLAT
    rm -rf "$B" && mkdir -p "$B"
    write_config "$B"

    local objs=""
    for src in $SOURCES; do
        local obj="$B/${src%.c}.o"
        xcrun clang -arch arm64 -isysroot "$SYSROOT" $MIN -O2 -w \
            -DLIBSSH2_LIBRARY -DHAVE_CONFIG_H \
            -I"$B" -I"$ROOT/libssh2/include" -I"$ROOT/libssh2/src" \
            -I"$OSSL/include" -include "$SE/openssl/openssl-prefix.h" \
            -c "$ROOT/libssh2/src/$src" -o "$obj"
        objs="$objs $obj"
    done
    libtool -static -o "$ROOT/build/$PLAT/libSRPSSH2.a" $objs
    echo "BUILT build/$PLAT/libSRPSSH2.a"
}

mkdir -p build/iphoneos build/macosx
build_one iphoneos
build_one macosx
echo ALL_DONE
