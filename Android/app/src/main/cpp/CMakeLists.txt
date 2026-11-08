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

# SSH VPN: the iOS app's SSH bridge (iOS/Core/SRPCore/SRPSSHBridge.c) on libssh2 1.11.1 (iOS/SSH/libssh2) and the
# hev-socks5-tunnel packet engine (iOS/SSH/upstream), from the same sources as on iOS, with the packet channel and the
# events for SshClient.kt in ssh_jni.c. libssh2 links the SoftEther core's OpenSSL 3; the engine is built with the iOS
# build's srpssh_ names (iOS/SSH/build/srpssh-prefix.h), and the version script keeps it all inside libsrpssh.so.
enable_language(ASM)
set(SSH_ROOT "${SRP_IOS_SOURCES}/SSH")
set(SSH_UP "${SSH_ROOT}/upstream")
set(SSH2_SOURCES)
foreach(name IN ITEMS agent bcrypt_pbkdf channel comp chacha cipher-chachapoly crypt crypto global hostkey keepalive kex
                      knownhost mac misc openssl packet pem poly1305 publickey scp session sftp transport userauth
                      userauth_kbd_packet version)
    list(APPEND SSH2_SOURCES "${SSH_ROOT}/libssh2/src/${name}.c")
endforeach()
set(SSH_ENGINE_SOURCES)
foreach(name IN ITEMS hev-config hev-mapped-dns hev-socks5-session hev-socks5-session-tcp hev-socks5-session-udp
                      hev-socks5-tunnel hev-tunnel-linux hev-main)
    list(APPEND SSH_ENGINE_SOURCES "${SSH_UP}/src/${name}.c")
endforeach()
file(GLOB SSH_ENGINE_MISC CONFIGURE_DEPENDS "${SSH_UP}/src/misc/*.c")
list(FILTER SSH_ENGINE_MISC EXCLUDE REGEX "/hev-wintun\\.c$")
file(GLOB_RECURSE SSH_ENGINE_DEPENDENCIES CONFIGURE_DEPENDS "${SSH_UP}/src/core/src/*.c" "${SSH_UP}/third-part/yaml/src/*.c"
    "${SSH_UP}/third-part/lwip/src/core/*.c" "${SSH_UP}/third-part/lwip/src/api/*.c")
# The task system is a library of its own, as in upstream's Android.mk and the iOS archive: its list and tree helpers
# have the same names as the engine's misc ones, and an archive keeps only the copies the link needs
file(GLOB_RECURSE SSH_TASK_SOURCES CONFIGURE_DEPENDS "${SSH_UP}/third-part/hev-task-system/src/*.c")
list(APPEND SSH_ENGINE_SOURCES ${SSH_ENGINE_MISC} ${SSH_ENGINE_DEPENDENCIES}
    "${SSH_UP}/third-part/lwip/src/ports/lib/mem.c" "${SSH_UP}/third-part/lwip/src/ports/unix/lib/sys_arch.c"
    "${SSH_ROOT}/srpssh-glue.c")
add_library(srpssh_tasks STATIC ${SSH_TASK_SOURCES} "${SSH_UP}/third-part/hev-task-system/src/kern/task/hev-task-execute.S")
set_target_properties(srpssh_tasks PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(srpssh_tasks PRIVATE "${SSH_UP}/third-part/hev-task-system/include" "${SSH_UP}/third-part/hev-task-system/src")
add_library(srpssh SHARED ssh_jni.c "${SRP_IOS_SOURCES}/Core/SRPCore/SRPSSHBridge.c" ${SSH2_SOURCES} ${SSH_ENGINE_SOURCES})
target_include_directories(srpssh PRIVATE ssh "${SE_OPENSSL}/include" "${SSH_ROOT}/libssh2/include" "${SSH_ROOT}/libssh2/src"
    "${SSH_ROOT}/build" "${SRP_IOS_SOURCES}/Core/SRPCore"
    "${SSH_UP}/src" "${SSH_UP}/src/misc" "${SSH_UP}/src/core/include" "${SSH_UP}/src/core/src"
    "${SSH_UP}/third-part/yaml/include" "${SSH_UP}/third-part/lwip/src/include" "${SSH_UP}/third-part/lwip/src/ports/include"
    "${SSH_UP}/third-part/hev-task-system/include" "${SSH_UP}/third-part/hev-task-system/src")
set(SSH_ENGINE_DEFINITIONS _GNU_SOURCE ENABLE_LIBRARY ENABLE_STACK_OVERFLOW_DETECTION ENABLE_STACK_OVERFLOW_DETECTOR
    ENABLE_MEMALLOC_SLICE ENABLE_IO_SPLICE_SYSCALL CONFIG_STACK_BACKEND=STACK_MMAP CONFIG_STACK_OVERFLOW_DETECTION=1
    CONFIG_MEMALLOC_SLICE_ALIGN=16 CONFIG_MEMALLOC_SLICE_MAX_SIZE=4096 CONFIG_MEMALLOC_SLICE_MAX_COUNT=1000
    CONFIG_SCHED_CLOCK=CLOCK_NONE YAML_VERSION_MAJOR=0 YAML_VERSION_MINOR=2 YAML_VERSION_PATCH=5 YAML_VERSION_STRING="0.2.5"
    FD_SET_DEFINED SOCKLEN_T_DEFINED)
target_compile_definitions(srpssh PRIVATE ${SSH_ENGINE_DEFINITIONS})
target_compile_definitions(srpssh_tasks PRIVATE ${SSH_ENGINE_DEFINITIONS})
target_compile_options(srpssh PRIVATE $<$<COMPILE_LANGUAGE:C>:-w>)
target_compile_options(srpssh_tasks PRIVATE $<$<COMPILE_LANGUAGE:C>:-w>)
# libssh2 reads its configuration from ssh/libssh2_config.h (the engine's yaml has a config.h of its own kind)
set_source_files_properties(${SSH2_SOURCES} PROPERTIES COMPILE_DEFINITIONS "HAVE_CONFIG_H;LIBSSH2_LIBRARY")
# The engine's names as the bridge calls them (libssh2 and the bridge's own code take no prefix)
set_source_files_properties(${SSH_ENGINE_SOURCES} ${SSH_TASK_SOURCES} PROPERTIES COMPILE_OPTIONS "-include;${SSH_ROOT}/build/srpssh-prefix.h")
target_link_libraries(srpssh PRIVATE srpssh_tasks "${SE_OPENSSL}/lib/libssl.a" "${SE_OPENSSL}/lib/libcrypto.a" z log)
target_link_options(srpssh PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/ssh_exports.map")
set_target_properties(srpssh PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/ssh_exports.map")
