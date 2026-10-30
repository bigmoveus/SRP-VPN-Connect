#!/bin/bash
# Full OpenSSL prefixed build pipeline (v3).
# - Prefixes all OpenSSL symbols with srpse_ (coexists with BoringSSL in SRPCore).
# - Patches a handful of OpenSSL source files where #undef / #ifndef tricks
#   would otherwise escape the prefix (bn_asm.c, cpuid.c, md4/md5/rmd dgst).
set -e
cd /tmp/sebuild
OUT=/tmp/sebuild/out
CONF_FLAGS="no-asm no-shared no-dso no-engine no-tests no-comp"
HDR=/tmp/sebuild/openssl-prefix.h

patch_tree () {  # $1 = build dir
    local d=$1
    # bn_asm.c: drop the #undef lines so the global prefix applies to definitions
    sed -i '' -e '/^# undef bn_mul_comba8/d' -e '/^# undef bn_mul_comba4/d' \
              -e '/^# undef bn_sqr_comba8/d' -e '/^# undef bn_sqr_comba4/d' "$d/crypto/bn/bn_asm.c"
    # cpuid.c: same for CRYPTO_memcmp
    sed -i '' -e '/^# undef CRYPTO_memcmp/d' "$d/crypto/cpuid.c"
    # md4/md5/ripemd160: #ifndef <sym> would skip the C definition once the
    # symbol is a macro; force the C implementation (we build no-asm anyway)
    sed -i '' -e 's/^#ifndef md4_block_data_order/#if 1 \/* SRP: forced C impl *\//' "$d/crypto/md4/md4_dgst.c"
    sed -i '' -e 's/^#ifndef md5_block_data_order/#if 1 \/* SRP: forced C impl *\//' "$d/crypto/md5/md5_dgst.c"
    sed -i '' -e 's/^#ifndef ripemd160_block_data_order/#if 1 \/* SRP: forced C impl *\//' "$d/crypto/ripemd/rmd_dgst.c"
}

# pass 1: ios plain build to collect ALL defined symbols
rm -rf build-ios-plain && cp -r openssl-3.0.15 build-ios-plain && cd build-ios-plain
export CROSS_TOP="$(xcrun --sdk iphoneos --show-sdk-platform-path)/Developer"
export CROSS_SDK="$(xcrun --sdk iphoneos --show-sdk-path | xargs basename)"
./Configure ios64-xcrun $CONF_FLAGS -miphoneos-version-min=15.0 > configure.log 2>&1
make -j$(sysctl -n hw.ncpu) build_libs > make.log 2>&1
cd /tmp/sebuild
nm -g --defined-only build-ios-plain/libssl.a build-ios-plain/libcrypto.a | awk '$2 ~ /^[TDBSR]$/{print $3}' | sed 's/^_//' | sort -u > openssl_all_syms.txt
echo "openssl symbols: $(wc -l < openssl_all_syms.txt)"
{
  echo "#ifndef SRPSE_OSSL_PREFIX_H"
  echo "#define SRPSE_OSSL_PREFIX_H"
  while read -r s; do echo "#define $s srpse_$s"; done < openssl_all_syms.txt
  echo "#endif"
} > $HDR

# pass 2: prefixed builds
rm -rf build-ios && cp -r openssl-3.0.15 build-ios && patch_tree build-ios && cd build-ios
export CROSS_TOP="$(xcrun --sdk iphoneos --show-sdk-platform-path)/Developer"
export CROSS_SDK="$(xcrun --sdk iphoneos --show-sdk-path | xargs basename)"
./Configure ios64-xcrun $CONF_FLAGS -miphoneos-version-min=15.0 "-include $HDR" > configure.log 2>&1
make -j$(sysctl -n hw.ncpu) build_libs > make.log 2>&1
mkdir -p $OUT/ios/lib $OUT/ios/include && cp libssl.a libcrypto.a $OUT/ios/lib/ && rm -rf $OUT/ios/include/openssl && cp -r include/openssl $OUT/ios/include/
echo IOS_OK

cd /tmp/sebuild
rm -rf build-mac && cp -r openssl-3.0.15 build-mac && patch_tree build-mac && cd build-mac
unset CROSS_TOP CROSS_SDK
./Configure darwin64-arm64-cc $CONF_FLAGS -mmacosx-version-min=12.0 "-include $HDR" > configure.log 2>&1
make -j$(sysctl -n hw.ncpu) build_libs > make.log 2>&1
mkdir -p $OUT/mac/lib $OUT/mac/include && cp libssl.a libcrypto.a $OUT/mac/lib/ && rm -rf $OUT/mac/include/openssl && cp -r include/openssl $OUT/mac/include/
echo MAC_OK

# verify: no unprefixed defined symbol may collide with BoringSSL
BORING="/Users/admin/Desktop/3in122 9/SRP-VPN-Connect/Core/SRPCore"
nm -g --defined-only "$BORING/ssl.xcframework/ios-arm64/libssl.a" "$BORING/crypto.xcframework/ios-arm64/libcrypto.a" | awk '$2 ~ /^[TDBSR]$/{print $3}' | sed 's/^_//' | sort -u > boring_syms.txt
nm -g --defined-only $OUT/ios/lib/libssl.a $OUT/ios/lib/libcrypto.a | awk '$2 ~ /^[TDBSR]$/{print $3}' | sed 's/^_//' | grep -v "^srpse_" | sort -u > unprefixed_ours.txt
comm -12 unprefixed_ours.txt boring_syms.txt > leftover_collisions.txt
echo "leftover collisions: $(wc -l < leftover_collisions.txt)"
cat leftover_collisions.txt
echo ALL_DONE
