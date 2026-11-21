cmake_minimum_required(VERSION 3.25)
project(SRPWaterWallRuntime LANGUAGES C CXX)
include(CTest)

set(WW_MINIMAL_NODES ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(WW_ENABLE_IPO OFF CACHE BOOL "" FORCE)
set(WCRYPTO_BACKEND_OPENSSL ON CACHE BOOL "" FORCE)
set(HAVE_PIPE2 OFF CACHE INTERNAL "Use the portable c-ares pipe/fcntl path")
set(CMAKE_UNITY_BUILD OFF CACHE BOOL "" FORCE)
# The Router sniffs names from HTTP/2 and QUIC too, as the official builds do; QUIC and HTTP are in the runtime anyway.
set(router_enable_quic_sniffing ON CACHE BOOL "" FORCE)
set(router_enable_http2_sniffing ON CACHE BOOL "" FORCE)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        set(OPENSSL_TARGET_PLATFORM "darwin64-arm64-cc" CACHE STRING "" FORCE)
    else()
        set(OPENSSL_TARGET_PLATFORM "darwin64-x86_64-cc" CACHE STRING "" FORCE)
    endif()
endif()
if(ANDROID OR (APPLE AND CMAKE_OSX_SYSROOT MATCHES "iphone"))
    # Static lwIP pools must fit within the Network Extension memory budget;
    # Android keeps the limits that were tested on iOS.
    if("${WW_LWIP_MAX_TCP_FLOWS}" STREQUAL "")
        set(WW_LWIP_MAX_TCP_FLOWS 256)
    endif()
    if("${WW_LWIP_MAX_UDP_FLOWS}" STREQUAL "")
        set(WW_LWIP_MAX_UDP_FLOWS 256)
    endif()
    # A local app may still deliver one receive window after the next tunnel
    # pauses its flow; keep that burst well inside VmessClient's bounded input queue.
    if("${WW_LWIP_TCP_WND}" STREQUAL "")
        set(WW_LWIP_TCP_WND 262144)
    endif()
endif()
set(ALLOCATOR_BYPASS ON CACHE BOOL "" FORCE)
# The symbol-prefix header cannot rename assembly, so OpenSSL must build without asm.
# The iOS toolchain seeds a normal OPENSSL_CONFIGURE_OPTIONS during project(), which
# shadows a cache entry on a fresh configure; extend the variable in scope instead.
list(APPEND OPENSSL_CONFIGURE_OPTIONS no-asm)
if(ANDROID)
    # Without this OpenSSL takes the NDK's newest API level instead of the app's minSdk.
    list(APPEND OPENSSL_CONFIGURE_OPTIONS "-D__ANDROID_API__=${ANDROID_PLATFORM_LEVEL}")
endif()
# The node types of the app's WaterWall: the INCLUDE_ option of each and its library.
set(SRP_NODES
    NE_PACKET_DEVICE:NEPacketDevice
    PACKET_TO_CONNECTION:PacketsToConnection
    PACKETS_TO_STREAM:PacketsToStream
    TCP_UDP_CONNECTOR:TcpUdpConnector
    TCPCONNECTOR:TcpConnector
    UDP_CONNECTOR:UdpConnector
    DOMAIN_RESOLVER:DomainResolver
    ROUTER:Router
    STREAM_FRAGMENTER:StreamFragmenter
    VLESS_CLIENT:VlessClient
    VMESS_CLIENT:VmessClient
    TROJAN_CLIENT:TrojanClient
    SOCKS5_CLIENT:Socks5Client
    HTTP_PROXY_CLIENT:HttpProxyClient
    WIREGUARD_CLIENT:WireGuardClient
    TLS_CLIENT:TlsClient
    REALITY_CLIENT:RealityClient
    HTTP_CLIENT:HttpClient
    QUIC_CLIENT:QuicClient
    KCP_CLIENT:KcpClient
    UDP_OVER_TCP_CLIENT:UdpOverTcpClient
    MUX_CLIENT:MuxClient
    BGP4_CLIENT:Bgp4Client
    OBFUSCATOR_CLIENT:ObfuscatorClient
    ENCRYPTION_CLIENT:EncryptionClient
    AUTHENTICATION_CLIENT:AuthenticationClient
    USER_CONTROLLER:UserController
    HEADER_CLIENT:HeaderClient
    KEEPALIVE_CLIENT:KeepAliveClient
    HALFDUPLEX_CLIENT:HalfDuplexClient
    CONNECTIONSTRIPE_CLIENT:ConnectionStripeClient
    RTMP_CLIENT:RtmpClient
    ENET_CLIENT:EnetClient
    GNS_CLIENT:GnsClient
    CONNECTION_FISHER_CLIENT:ConnectionFisherClient
    BLACKHOLE:BlackHole
    SPEEDLIMIT:SpeedLimit
    DISTURBER:Disturber
    JUNK_DATAGRAM_SENDER:JunkDatagramSender
    LOGGER_TUNNEL:LoggerTunnel
    CONNECTION_TO_PACKETS:ConnectionToPackets
    # The app's local SOCKS5 and HTTP proxy inputs.
    TCP_LISTENER:TcpListener
    UDP_LISTENER:UdpListener
    TCP_UDP_LISTENER:TcpUdpListener
    SOCKS_5_SERVER:Socks5Server
    HTTP_PROXY_SERVER:HttpProxyServer
)
set(WW_MINIMAL_ALLOWED_NODES)
set(SRP_NODE_DEFINITIONS)
set(SRP_NODE_LIBRARIES)
foreach(node IN LISTS SRP_NODES)
    string(REPLACE ":" ";" node "${node}")
    list(GET node 0 option)
    list(GET node 1 library)
    list(APPEND WW_MINIMAL_ALLOWED_NODES INCLUDE_${option})
    list(APPEND SRP_NODE_DEFINITIONS INCLUDE_${option}=1)
    list(APPEND SRP_NODE_LIBRARIES ${library})
endforeach()
add_subdirectory(upstream)
set(BUILD_TESTING ON CACHE BOOL "" FORCE)
add_dependencies(ww srp_openssl_full_prefix)
add_dependencies(VmessCommon srp_openssl_full_prefix)
add_dependencies(VmessClient srp_openssl_full_prefix)
target_include_directories(kcp_fec PRIVATE upstream/ww/libc)
# The Router's QUIC sniffing calls OpenSSL itself, and this build's OpenSSL symbols carry the prefix.
target_compile_options(RouterQuicSniffing PRIVATE -include "${CMAKE_CURRENT_BINARY_DIR}/upstream/ww/srp_openssl_prefix.h")
add_dependencies(RouterQuicSniffing srp_openssl_full_prefix)

add_library(SRPWaterWallBridge STATIC
    native/SRPWaterWallBridge.c
    native/hosted_runtime.c
    upstream/core/core_settings.c
    upstream/core/imported_tunnels.c
    upstream/core/os_helpers.c
)
target_compile_definitions(SRPWaterWallBridge PRIVATE ${SRP_NODE_DEFINITIONS})
target_include_directories(SRPWaterWallBridge PUBLIC
    native
    upstream
    upstream/core
    upstream/ww
)
target_link_libraries(SRPWaterWallBridge PUBLIC ${SRP_NODE_LIBRARIES} ww)

# Android links a shared library from the bridge target; the rest packs Apple's static archive.
if(ANDROID)
    return()
endif()

# The archive holds every static and object library the bridge links, directly or through another library.
function(srp_waterwall_collect target)
    if(NOT TARGET "${target}")
        if("${target}" MATCHES "\\.a$")
            set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_INPUTS "${target}")
        endif()
        return()
    endif()
    get_target_property(aliased "${target}" ALIASED_TARGET)
    if(aliased)
        set(target "${aliased}")
    endif()
    get_property(seen GLOBAL PROPERTY SRP_ARCHIVE_TARGETS)
    if("${target}" IN_LIST seen)
        return()
    endif()
    set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_TARGETS "${target}")
    get_target_property(kind "${target}" TYPE)
    if(kind STREQUAL "STATIC_LIBRARY")
        set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_INPUTS "$<TARGET_FILE:${target}>")
    elseif(kind STREQUAL "OBJECT_LIBRARY")
        set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_INPUTS "$<TARGET_OBJECTS:${target}>")
    endif()
    foreach(property IN ITEMS LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
        get_target_property(libraries "${target}" ${property})
        foreach(library IN LISTS libraries)
            string(REGEX REPLACE "^\\$<LINK_ONLY:(.+)>$" "\\1" library "${library}")
            srp_waterwall_collect("${library}")
        endforeach()
    endforeach()
endfunction()
srp_waterwall_collect(SRPWaterWallBridge)
# OpenSSL comes from an imported target of unknown kind, and BoringSSL's FIPS objects are named by a generator expression.
foreach(target IN ITEMS OpenSSL::SSL OpenSSL::Crypto)
    set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_INPUTS "$<TARGET_FILE:${target}>")
endforeach()
set_property(GLOBAL APPEND PROPERTY SRP_ARCHIVE_INPUTS "$<TARGET_OBJECTS:fipsmodule>")
get_property(SRP_ARCHIVE_INPUTS GLOBAL PROPERTY SRP_ARCHIVE_INPUTS)
get_property(SRP_ARCHIVE_TARGETS GLOBAL PROPERTY SRP_ARCHIVE_TARGETS)
list(REMOVE_DUPLICATES SRP_ARCHIVE_INPUTS)

set(SRP_RUNTIME_ARCHIVE ${CMAKE_CURRENT_BINARY_DIR}/libSRPWaterWallRuntime.a)
set(SRP_LWIP_PREFIX_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/upstream/ww/lwip/srp_lwip_prefix.h)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_custom_command(
    OUTPUT ${SRP_RUNTIME_ARCHIVE}
    COMMAND /usr/bin/libtool -static -o ${SRP_RUNTIME_ARCHIVE} ${SRP_ARCHIVE_INPUTS}
    # The other protocols link their own lwIP, so none of WaterWall's may stay unprefixed.
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/lwip_prefix_contract.py
        ${SRP_LWIP_PREFIX_HEADER} $<TARGET_FILE:ww_lwip> ${SRP_RUNTIME_ARCHIVE}
    DEPENDS ${SRP_ARCHIVE_TARGETS} fipsmodule OpenSSL::SSL OpenSSL::Crypto
    COMMAND_EXPAND_LISTS
    COMMENT "Packing the self-contained WaterWall runtime archive"
)
add_custom_target(SRPWaterWallRuntime ALL DEPENDS ${SRP_RUNTIME_ARCHIVE})
add_test(NAME srp_openssl_prefix_contract
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/openssl_prefix_contract.py
                 $<TARGET_FILE:OpenSSL::SSL> $<TARGET_FILE:OpenSSL::Crypto>)
add_test(NAME srp_lwip_prefix_contract
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/lwip_prefix_contract.py
                 ${SRP_LWIP_PREFIX_HEADER} $<TARGET_FILE:ww_lwip> ${SRP_RUNTIME_ARCHIVE})

if(BUILD_TESTING AND CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    add_executable(srp_waterwall_host_poc tests/host_poc.c)
    target_link_libraries(srp_waterwall_host_poc PRIVATE SRPWaterWallBridge)
    add_test(NAME srp_waterwall_host_poc COMMAND srp_waterwall_host_poc)
    set_tests_properties(srp_waterwall_host_poc PROPERTIES TIMEOUT 60)
    add_executable(srp_waterwall_expanded_chain_poc tests/expanded_chain_poc.c)
    target_link_libraries(srp_waterwall_expanded_chain_poc PRIVATE SRPWaterWallBridge)
    add_test(NAME srp_waterwall_expanded_chain_poc COMMAND srp_waterwall_expanded_chain_poc)
    set_tests_properties(srp_waterwall_expanded_chain_poc PROPERTIES TIMEOUT 120)
    add_executable(srp_waterwall_vless_mux_udp_poc tests/vless_mux_udp_poc.c)
    target_link_libraries(srp_waterwall_vless_mux_udp_poc PRIVATE SRPWaterWallBridge)
    add_test(NAME srp_waterwall_vless_mux_udp_poc COMMAND srp_waterwall_vless_mux_udp_poc)
    set_tests_properties(srp_waterwall_vless_mux_udp_poc PROPERTIES TIMEOUT 60)
endif()
