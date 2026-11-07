cmake_minimum_required(VERSION 3.25)
project(SRPVPNAndroid LANGUAGES C CXX)

add_subdirectory(../../../../../WaterWall waterwall-runtime)

add_library(waterwall SHARED waterwall_jni.c)
target_link_libraries(waterwall PRIVATE SRPWaterWallBridge maxminddb sodium)
# Only the JNI functions are for outsiders: the allocator's operator new and the crypto stay private.
target_link_options(waterwall PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
set_target_properties(waterwall PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")

# SSTP: the iOS app's SSTP core and lwIP PPP with its EAP methods, with this platform's engine in sstp_jni.c. Its own
# library, so its lwIP and WaterWall's never meet; it links the same OpenSSL build as WaterWall, whose symbols carry a prefix.
set(SRP_IOS_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../iOS")
set(SSTP_LWIP "${SRP_IOS_SOURCES}/LwIP/lwip")
file(GLOB SSTP_LWIP_SOURCES CONFIGURE_DEPENDS
    "${SSTP_LWIP}/core/*.c" "${SSTP_LWIP}/core/ipv4/*.c" "${SSTP_LWIP}/core/ipv6/*.c"
    "${SSTP_LWIP}/netif/ppp/*.c" "${SSTP_LWIP}/netif/ppp/polarssl/*.c")
set(SSTP_CORE_SOURCES)
foreach(name IN ITEMS sstp-buff sstp-chap sstp-cmac sstp-fcs sstp-http sstp-packet sstp-pppd sstp-state sstp-stream
                      sstp-task sstp-util utils)
    list(APPEND SSTP_CORE_SOURCES "${SRP_IOS_SOURCES}/Core/SRPCore/sstp/${name}.c")
endforeach()
add_library(srpsstp SHARED sstp_jni.c ${SSTP_CORE_SOURCES} ${SSTP_LWIP_SOURCES}
    "${SSTP_LWIP}/netif/ethernet.c" "${SSTP_LWIP}/custom/sys_arch.c")
target_include_directories(srpsstp PRIVATE "${SRP_IOS_SOURCES}/Core/SRPCore" "${SRP_IOS_SOURCES}/Core/SRPCore/sstp"
    "${SSTP_LWIP}/include" "${SSTP_LWIP}/custom")
target_compile_definitions(srpsstp PRIVATE HAVE_PTY_H=1)
set(SRP_OPENSSL_PREFIX "${CMAKE_BINARY_DIR}/waterwall-runtime/upstream/ww/srp_openssl_prefix.h")
target_compile_options(srpsstp PRIVATE -include "${SRP_OPENSSL_PREFIX}" -Wno-unused-parameter -Wno-unused-function)
target_link_libraries(srpsstp PRIVATE OpenSSL::SSL OpenSSL::Crypto)
add_dependencies(srpsstp srp_openssl_full_prefix)
target_link_options(srpsstp PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/sstp_exports.map")
set_target_properties(srpsstp PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/sstp_exports.map")

# SoftEther: the iOS app's client core (iOS/SoftEther: Mayaqua, the client half of Cedar and the SRPSE bridge) with its own
# OpenSSL 3 (iOS/SoftEther/build_openssl_android.sh): the core reads ASN1 strings that OpenSSL 4, the WaterWall runtime's,
# made opaque. The version script keeps those symbols inside libsrpse.so. SRP_IOS turns on the same upstream patches as on
# iOS (see iOS/SoftEther/PATCHES.md).
set(SE_ROOT "${SRP_IOS_SOURCES}/SoftEther")
set(SE_UP "${SE_ROOT}/upstream")
set(SE_SOURCES "${SE_UP}/Mayaqua/Crypto/Key.c")
foreach(name IN ITEMS Cfg DNS Encoding Encrypt FileIO HTTP Internat Kernel Mayaqua Memory Network OS Object Pack Proxy Secure Str
                      Table TcpIp Tick64 Tracking Unix)
    list(APPEND SE_SOURCES "${SE_UP}/Mayaqua/${name}.c")
endforeach()
foreach(name IN ITEMS Hamcore FileSystem Memory)
    list(APPEND SE_SOURCES "${SE_UP}/libhamcore/${name}.c")
endforeach()
file(GLOB SE_CEDAR_SOURCES CONFIGURE_DEPENDS "${SE_UP}/Cedar/*.c")
list(FILTER SE_CEDAR_SOURCES EXCLUDE REGEX "/(Proto_WireGuard|VLanUnix|VLanWin32|BridgeWin32|Console|Command)\\.c$")
add_library(srpse SHARED softether_jni.c softether/iconv_shim.c ${SE_SOURCES} ${SE_CEDAR_SOURCES}
    "${SE_ROOT}/bridge/SRPSEAdapter.c" "${SE_ROOT}/bridge/SRPSEClient.c" "${SE_ROOT}/bridge/SRPSEStubs.c"
    "${SRP_IOS_SOURCES}/Core/SRPCore/SRPFragBio.c")
# softether/ first: its iconv.h stands in for Bionic's, which needs API 28
target_include_directories(srpse BEFORE PRIVATE softether)
set(SE_OPENSSL "${SE_ROOT}/openssl/android-arm64")
target_include_directories(srpse PRIVATE "${SE_OPENSSL}/include" "${SE_UP}" "${SE_UP}/Mayaqua" "${SE_UP}/Cedar" "${SE_UP}/libhamcore/include"
    "${SE_ROOT}/bridge" "${SE_ROOT}/shim" "${SRP_IOS_SOURCES}/Core/SRPCore")
target_compile_definitions(srpse PRIVATE UNIX OS_UNIX UNIX_LINUX SKIP_CPU_FEATURES NO_VLAN SRP_IOS SKIP_OQS_PROVIDER
    _REENTRANT _THREAD_SAFE _FILE_OFFSET_BITS=64)
target_compile_options(srpse PRIVATE -w -fno-strict-aliasing)
target_link_libraries(srpse PRIVATE "${SE_OPENSSL}/lib/libssl.a" "${SE_OPENSSL}/lib/libcrypto.a" z)
target_link_options(srpse PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/softether_exports.map")
set_target_properties(srpse PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/softether_exports.map")

# SSL VPN: libopenconnect as the iOS app builds it, for Android with upstream's JNI binding (LibOpenConnect.java)
# (iOS/OpenConnect/build_openconnect_android.sh), and the packet channel to the tunnel. It links the SoftEther core's
# OpenSSL 3 and its own libxml2 (iOS/OpenConnect/build_libxml2_android.sh); the version script keeps them inside.
set(OC_ROOT "${SRP_IOS_SOURCES}/OpenConnect")
add_library(srpopenconnect SHARED openconnect_tun_jni.c)
target_link_libraries(srpopenconnect PRIVATE
    "-Wl,--whole-archive" "${OC_ROOT}/build/android-arm64/libSRPOpenConnect.a" "-Wl,--no-whole-archive"
    "${OC_ROOT}/libxml2/android-arm64/lib/libxml2.a"
    "${SE_ROOT}/openssl/android-arm64/lib/libssl.a" "${SE_ROOT}/openssl/android-arm64/lib/libcrypto.a" z m log)
target_link_options(srpopenconnect PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/openconnect_exports.map")
set_target_properties(srpopenconnect PROPERTIES LINK_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/openconnect_exports.map;${OC_ROOT}/build/android-arm64/libSRPOpenConnect.a;${OC_ROOT}/libxml2/android-arm64/lib/libxml2.a")
