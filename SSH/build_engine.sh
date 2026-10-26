#!/bin/bash
# Builds the SSH VPN packet engine (hev-socks5-tunnel + lwIP + hev-task-system
# + hev-socks5-core, pinned in upstream/) as a static lib per platform.
#
# Two-pass build: pass 1 compiles normally, we extract every global symbol and
# generate srpssh-prefix.h (#define sym srpssh_sym), pass 2 recompiles with
# -include srpssh-prefix.h. This isolates the engine's lwIP/globals from the
# SSTP stack's unprefixed lwIP already linked into the extension.
#
# Output: build/<platform>/libSRPSSHEngine.a
set -e
cd "$(dirname "$0")"
ROOT="$PWD"
# Build from a space-free copy (the repo path contains a space; xcrun clang
# include flags are space-sensitive)
UP="/tmp/ssheng-upstream"
rm -rf "$UP"
cp -R "$ROOT/upstream" "$UP"

engine_cflags () {  # $1 = iphoneos|macosx  -> prints flags
    local PLAT=$1 SDK MIN
    if [ "$PLAT" = iphoneos ]; then SDK=iphoneos; MIN="-miphoneos-version-min=15.0"; else SDK=macosx; MIN="-mmacosx-version-min=12.0"; fi
    local DEBUG_FLAGS=""
    if [ "${ENGINE_DEBUG:-0}" = "1" ]; then
        DEBUG_FLAGS="-DLWIP_DEBUG -DIP_DEBUG=LWIP_DBG_ON -DTCP_DEBUG=LWIP_DBG_ON -DTCP_INPUT_DEBUG=LWIP_DBG_ON -DLWIP_DBG_MIN_LEVEL=0"
    fi
    echo "-arch arm64 -isysroot $(xcrun -sdk $SDK --show-sdk-path) $MIN -O2 -w -DENABLE_LIBRARY \
        $DEBUG_FLAGS \
        -DENABLE_STACK_OVERFLOW_DETECTION -DENABLE_STACK_OVERFLOW_DETECTOR -DENABLE_MEMALLOC_SLICE \
        -DENABLE_IO_SPLICE_SYSCALL -DCONFIG_STACK_BACKEND=STACK_MMAP -DCONFIG_STACK_OVERFLOW_DETECTION=1 \
        -DCONFIG_MEMALLOC_SLICE_ALIGN=16 -DCONFIG_MEMALLOC_SLICE_MAX_SIZE=4096 \
        -DCONFIG_MEMALLOC_SLICE_MAX_COUNT=1000 -DCONFIG_SCHED_CLOCK=CLOCK_NONE \
        -DYAML_VERSION_MAJOR=0 -DYAML_VERSION_MINOR=2 -DYAML_VERSION_PATCH=5 \
        "-DYAML_VERSION_STRING=\"0.2.5\"" \
        -I$UP/src -I$UP/src/misc -I$UP/src/core/include \
        -I$UP/third-part/yaml/include \
        -I$UP/third-part/lwip/src/include -I$UP/third-part/lwip/src/ports/include \
        -I$UP/third-part/hev-task-system/include -I$UP/third-part/hev-task-system/src"
}

collect_sources () {
    # tunnel sources (no CLI/JNI/non-apple tunnel backends)
    echo "$UP/src/hev-config.c"
    echo "$UP/src/hev-mapped-dns.c"
    echo "$UP/src/hev-socks5-session.c"
    echo "$UP/src/hev-socks5-session-tcp.c"
    echo "$UP/src/hev-socks5-session-udp.c"
    echo "$UP/src/hev-socks5-tunnel.c"
    echo "$UP/src/hev-tunnel-macos.c"
    echo "$UP/src/hev-main.c"   # ENABLE_LIBRARY strips main(); provides main_from_str lifecycle
    # misc helpers (logger, lists, ring buffer, utils)
    for f in "$UP/src/misc/"*.c; do
        case "$f" in
            *hev-wintun.c) ;;  # windows-only
            *) echo "$f" ;;
        esac
    done
    # socks5 core (client + misc)
    find "$UP/src/core/src" -name '*.c'
    # task system (C + the context-switch assembly — never prefixed)
    find "$UP/third-part/hev-task-system/src" -name '*.c'
    echo "$UP/third-part/hev-task-system/src/kern/task/hev-task-execute.S"
    # yaml (config string parser)
    find "$UP/third-part/yaml/src" -name '*.c'
    # lwip core + api + unix port (lwip_port_rand) + ports/lib
    find "$UP/third-part/lwip/src/core" "$UP/third-part/lwip/src/api" -name '*.c'
    echo "$UP/third-part/lwip/src/ports/lib/mem.c"
    echo "$UP/third-part/lwip/src/ports/unix/lib/sys_arch.c"
    # glue for lwIP helpers suppressed by the prefix macros
    echo "$ROOT/srpssh-glue.c"
}

compile_all () {  # $1 = platform  $2 = objdir  $3 = extra flags
    local PLAT=$1 B=$2 EXTRA=$3
    rm -rf "$B" && mkdir -p "$B"
    local objs=()
    local src rel obj
    while IFS= read -r src; do
        rel=${src#$UP/}
        obj="$B/$(echo "$rel" | tr '/ ' '__')"
        obj="${obj%.*}.o"
        case "$src" in
            *.S)  # assembly: no prefix header (the preprocessor macros are C)
                xcrun clang $(engine_cflags $PLAT) -c "$src" -o "$obj" ;;
            *)
                xcrun clang $(engine_cflags $PLAT) $EXTRA -c "$src" -o "$obj" ;;
        esac
        objs+=("$obj")
    done < <(collect_sources)
    printf '%s\n' "${objs[@]}"
}

build_one () {  # $1 = iphoneos|macosx
    local PLAT=$1
    local B=/tmp/ssheng-obj-$PLAT
    local PREFIX_H="/tmp/ssheng-prefix.h"

    # pass 1: plain objects
    local objs1=()
    while IFS= read -r o; do objs1+=("$o"); done < <(compile_all $PLAT "$B-p1" "")
    libtool -static -o "$B-p1/libengine.a" "${objs1[@]}"

    # generate the prefix header from every defined global symbol
    if [ "$PLAT" = iphoneos ]; then
        {
            echo "/* Auto-generated: rename every engine global to srpssh_* */"
            echo "/* (avoid clashes with the SSTP stack's unprefixed lwIP) */"
            nm -g --defined-only "$B-p1/libengine.a" 2>/dev/null \
                | awk '{for(i=1;i<=NF;i++) if ($i ~ /^_[A-Za-z]/) print substr($i,2)}' \
                | sort -u | grep -v '^hev_task_execute$' | grep -v '^srpssh_' \
                | awk '{printf "#define %s srpssh_%s\n", $1, $1}'
            # lwIP declares these functions under #ifndef guards in
            # lwip/def.h; our object-like macros would suppress those
            # declarations, so declare the renamed functions ourselves.
            echo "#include <stdint.h>"
            echo "#include <stddef.h>"
            echo "uint16_t srpssh_lwip_htons(uint16_t x);"
            echo "uint32_t srpssh_lwip_htonl(uint32_t x);"
            echo "void srpssh_lwip_itoa(char* result, size_t bufsize, int number);"
            echo "int srpssh_lwip_strnicmp(const char* str1, const char* str2, size_t len);"
            echo "int srpssh_lwip_stricmp(const char* str1, const char* str2);"
            echo "char* srpssh_lwip_strnstr(const char* buffer, const char* token, size_t n);"
            echo "char* srpssh_lwip_strnistr(const char* buffer, const char* token, size_t n);"
            echo "int srpssh_lwip_memcmp_consttime(const void* s1, const void* s2, size_t len);"
        } > "$PREFIX_H"
    fi

    # pass 2: prefixed objects
    local objs2=()
    while IFS= read -r o; do objs2+=("$o"); done < <(compile_all $PLAT "$B-p2" "-include $PREFIX_H")
    libtool -static -o "$ROOT/build/$PLAT/libSRPSSHEngine.a" "${objs2[@]}"
    cp "$PREFIX_H" "$ROOT/build/srpssh-prefix.h"
    echo "BUILT build/$PLAT/libSRPSSHEngine.a"
}

mkdir -p build/iphoneos build/macosx
build_one iphoneos
build_one macosx
echo ALL_DONE
