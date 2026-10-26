#!/bin/bash
# Builds libSECore.a (SoftEther client protocol core) for iOS arm64 and macOS arm64.
# Sources: vendored upstream Mayaqua + client-side Cedar subset.
# OpenSSL symbols are prefixed (srpse_) via openssl/openssl-prefix.h so the static
# OpenSSL 3.0 linked here can coexist with the BoringSSL libs used by the SSTP core.
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
UP="$ROOT/upstream"
OSSLPREFIX="$ROOT/openssl/openssl-prefix.h"
WARN=(-w -fno-strict-aliasing)
DEFS=(-DUNIX -DOS_UNIX -DUNIX_BSD -DUNIX_MACOS -DSKIP_CPU_FEATURES -DNO_VLAN -DSRP_IOS -DSKIP_OQS_PROVIDER)

MAYAQUA_SRCS="Cfg DNS Encoding Encrypt FileIO HTTP Internat Kernel Mayaqua Memory Network OS Object Pack Proxy Secure Str Table TcpIp Tick64 Tracking Unix"
CEDAR_EXCLUDE="Proto_WireGuard VLanUnix VLanWin32 BridgeWin32 Console Command"
HAMCORE_SRCS="Hamcore FileSystem Memory"

compile_tree () {  # $1=sdk $2=arch $3=minflag $4=platform(iphoneos|macosx)
    local SDK=$1 ARCH=$2 MIN=$3 PLAT=$4
    local OUTDIR=$4
    local CC; CC="$(xcrun -sdk $SDK -f clang)"
    local SYSROOT; SYSROOT="$(xcrun -sdk $SDK --show-sdk-path)"
    local OBJD="$ROOT/build/obj-$OUTDIR"
    rm -rf "$OBJD"; mkdir -p "$OBJD"
    local CFLAGS=(-arch "$ARCH" -isysroot "$SYSROOT" "$MIN" -Os "${WARN[@]}" "${DEFS[@]}"
        -I"$UP" -I"$UP/Mayaqua" -I"$UP/Cedar" -I"$UP/libhamcore/include"
        -I"$ROOT/openssl/$PLAT/include" -I"$ROOT/shim"
        -include "$OSSLPREFIX")
    local objs=()
    for m in $MAYAQUA_SRCS; do
        "$CC" "${CFLAGS[@]}" -c "$UP/Mayaqua/$m.c" -o "$OBJD/mq_$m.o"
        objs+=("$OBJD/mq_$m.o")
    done
    "$CC" "${CFLAGS[@]}" -c "$UP/Mayaqua/Crypto/Key.c" -o "$OBJD/mq_Key.o"
    objs+=("$OBJD/mq_Key.o")
    for h in $HAMCORE_SRCS; do
        "$CC" "${CFLAGS[@]}" -c "$UP/libhamcore/$h.c" -o "$OBJD/hc_$h.o"
        objs+=("$OBJD/hc_$h.o")
    done
    # TLS write-splitting filter BIO (shared with the OpenConnect build)
    "$CC" "${CFLAGS[@]}" -c "$ROOT/../Core/SRPCore/SRPFragBio.c" -o "$OBJD/br_SRPFragBio.o"
    objs+=("$OBJD/br_SRPFragBio.o")
    for b in SRPSEAdapter SRPSEClient SRPSEStubs; do
        "$CC" "${CFLAGS[@]}" -I"$ROOT/bridge" -I"$ROOT/../Core/SRPCore" -c "$ROOT/bridge/$b.c" -o "$OBJD/br_$b.o"
        objs+=("$OBJD/br_$b.o")
    done
    for c in $CEDAR_SRCS; do :; done
    for f in "$UP/Cedar/"*.c; do
        c="$(basename "$f" .c)"
        case " $CEDAR_EXCLUDE " in *" $c "*) continue;; esac
        "$CC" "${CFLAGS[@]}" -c "$f" -o "$OBJD/cd_$c.o"
        objs+=("$OBJD/cd_$c.o")
    done
    mkdir -p "$ROOT/build/$PLAT"
    libtool -static -o "$ROOT/build/$PLAT/libSECore.a" "${objs[@]}"
    echo "BUILT build/$PLAT/libSECore.a"
}

compile_tree iphoneos arm64 "-miphoneos-version-min=15.0" iphoneos
compile_tree macosx arm64 "-mmacosx-version-min=12.0" macosx
echo ALL_DONE
