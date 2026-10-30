cmake_minimum_required(VERSION 3.25)
project(SRPWaterWallRuntime LANGUAGES C CXX)
include(CTest)

set(WW_MINIMAL_NODES ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(WW_ENABLE_IPO OFF CACHE BOOL "" FORCE)
set(WCRYPTO_BACKEND_OPENSSL ON CACHE BOOL "" FORCE)
set(HAVE_PIPE2 OFF CACHE INTERNAL "Use the portable c-ares pipe/fcntl path")
set(CMAKE_UNITY_BUILD OFF CACHE BOOL "" FORCE)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    if(CMAKE_HOST_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$")
        set(OPENSSL_TARGET_PLATFORM "darwin64-arm64-cc" CACHE STRING "" FORCE)
    else()
        set(OPENSSL_TARGET_PLATFORM "darwin64-x86_64-cc" CACHE STRING "" FORCE)
    endif()
endif()
if(APPLE AND CMAKE_OSX_SYSROOT MATCHES "iphone")
    # Static lwIP pools must fit within the Network Extension memory budget.
    if("${WW_LWIP_MAX_TCP_FLOWS}" STREQUAL "")
        set(WW_LWIP_MAX_TCP_FLOWS 256)
    endif()
    if("${WW_LWIP_MAX_UDP_FLOWS}" STREQUAL "")
        set(WW_LWIP_MAX_UDP_FLOWS 256)
    endif()
endif()
set(ALLOCATOR_BYPASS ON CACHE BOOL "" FORCE)
set(OPENSSL_CONFIGURE_OPTIONS no-asm CACHE STRING "" FORCE)
add_subdirectory(upstream)
set(BUILD_TESTING ON CACHE BOOL "" FORCE)
add_dependencies(ww srp_openssl_full_prefix)
add_dependencies(VmessCommon srp_openssl_full_prefix)
add_dependencies(VmessClient srp_openssl_full_prefix)
target_include_directories(tcp_over_udp_fec PRIVATE upstream/ww/libc)

add_library(SRPWaterWallBridge STATIC
    ../Core/SRPCore/SRPWaterWallBridge.c
    native/hosted_runtime.c
    upstream/core/core_settings.c
    upstream/core/imported_tunnels.c
    upstream/core/os_helpers.c
)
target_compile_definitions(SRPWaterWallBridge PRIVATE
    INCLUDE_NE_PACKET_DEVICE=1
    INCLUDE_PACKET_TO_CONNECTION=1
    INCLUDE_TCP_UDP_CONNECTOR=1
    INCLUDE_TCPCONNECTOR=1
    INCLUDE_UDP_CONNECTOR=1
    INCLUDE_DOMAIN_RESOLVER=1
    INCLUDE_STREAM_FRAGMENTER=1
    INCLUDE_VLESS_CLIENT=1
    INCLUDE_VMESS_CLIENT=1
    INCLUDE_TROJAN_CLIENT=1
    INCLUDE_BGP4_CLIENT=1
    INCLUDE_SOCKS5_CLIENT=1
    INCLUDE_HTTP_PROXY_CLIENT=1
    INCLUDE_TLS_CLIENT=1
    INCLUDE_MUX_CLIENT=1
    INCLUDE_WIREGUARD_DEVICE=1
    INCLUDE_UDP_STATELESS_SOCKET=1
    INCLUDE_AUTHENTICATION_CLIENT=1
    INCLUDE_USER_CONTROLLER=1
    INCLUDE_REALITY_CLIENT=1
    INCLUDE_ENCRYPTION_CLIENT=1
    INCLUDE_PACKETS_TO_STREAM=1
    INCLUDE_ROUTER=1
    INCLUDE_QUIC_CLIENT=1
    INCLUDE_HTTP_CLIENT=1
    INCLUDE_OBFUSCATOR_CLIENT=1
    INCLUDE_TCP_OVER_UDP_CLIENT=1
)
target_include_directories(SRPWaterWallBridge PUBLIC
    ../Core/SRPCore
    native
    upstream
    upstream/core
    upstream/ww
)
target_link_libraries(SRPWaterWallBridge PUBLIC
    NEPacketDevice
    PacketsToConnection
    TcpUdpConnector
    TcpConnector
    UdpConnector
    DomainResolver
    StreamFragmenter
    VlessClient
    VmessClient
    VmessCommon
    TrojanClient
    Bgp4Client
    Socks5Client
    HttpProxyClient
    TlsClient
    MuxClient
    WireGuardDevice
    UdpStatelessSocket
    AuthenticationClient
    UserController
    RealityClient
    RealityCommon
    EncryptionClient
    PacketsToStream
    Router
    QuicClient
    QuicCommon
    HttpClient
    ObfuscatorClient
    TcpOverUdpClient
    waterwall_quiche
    ww
)

set(SRP_QUIC_ARCHIVE_FILES)
set(SRP_QUIC_ARCHIVE_TARGETS)
function(srp_waterwall_collect_static_libraries directory)
    get_property(targets DIRECTORY "${directory}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(target IN LISTS targets)
        get_target_property(kind ${target} TYPE)
        if(kind STREQUAL "STATIC_LIBRARY")
            list(APPEND SRP_QUIC_ARCHIVE_FILES $<TARGET_FILE:${target}>)
            list(APPEND SRP_QUIC_ARCHIVE_TARGETS ${target})
        endif()
    endforeach()
    get_property(children DIRECTORY "${directory}" PROPERTY SUBDIRECTORIES)
    foreach(child IN LISTS children)
        srp_waterwall_collect_static_libraries("${child}")
    endforeach()
    set(SRP_QUIC_ARCHIVE_FILES ${SRP_QUIC_ARCHIVE_FILES} PARENT_SCOPE)
    set(SRP_QUIC_ARCHIVE_TARGETS ${SRP_QUIC_ARCHIVE_TARGETS} PARENT_SCOPE)
endfunction()
foreach(directory IN ITEMS abseil protobuf zlib)
    srp_waterwall_collect_static_libraries("${CMAKE_CURRENT_BINARY_DIR}/ww-dependencies/${directory}")
endforeach()
list(APPEND SRP_QUIC_ARCHIVE_FILES
    $<TARGET_FILE:QuicClient>
    $<TARGET_FILE:QuicCommon>
    $<TARGET_FILE:waterwall_quiche>
    $<TARGET_FILE:waterwall_googleurl>
)
list(APPEND SRP_QUIC_ARCHIVE_TARGETS QuicClient QuicCommon waterwall_quiche waterwall_googleurl)
list(REMOVE_DUPLICATES SRP_QUIC_ARCHIVE_FILES)
list(REMOVE_DUPLICATES SRP_QUIC_ARCHIVE_TARGETS)

set(SRP_RUNTIME_ARCHIVE ${CMAKE_CURRENT_BINARY_DIR}/libSRPWaterWallRuntime.a)
add_custom_command(
    OUTPUT ${SRP_RUNTIME_ARCHIVE}
    COMMAND /usr/bin/libtool -static -o ${SRP_RUNTIME_ARCHIVE}
        $<TARGET_FILE:SRPWaterWallBridge>
        $<TARGET_FILE:NEPacketDevice>
        $<TARGET_FILE:PacketsToConnection>
        $<TARGET_FILE:TcpUdpConnector>
        $<TARGET_FILE:TcpConnector>
        $<TARGET_FILE:UdpConnector>
        $<TARGET_FILE:DomainResolver>
        $<TARGET_FILE:StreamFragmenter>
        $<TARGET_FILE:VlessClient>
        $<TARGET_FILE:VmessClient>
        $<TARGET_FILE:VmessCommon>
        $<TARGET_FILE:TrojanClient>
        $<TARGET_FILE:Bgp4Client>
        $<TARGET_FILE:Socks5Client>
        $<TARGET_FILE:HttpProxyClient>
        $<TARGET_FILE:HttpProxyCommon>
        $<TARGET_FILE:TlsClient>
        $<TARGET_FILE:MuxClient>
        $<TARGET_FILE:MuxCommon>
        $<TARGET_FILE:TlsRecordShapingCommon>
        $<TARGET_FILE:WireGuardDevice>
        $<TARGET_FILE:UdpStatelessSocket>
        $<TARGET_FILE:AuthenticationClient>
        $<TARGET_FILE:UserController>
        $<TARGET_FILE:RealityClient>
        $<TARGET_FILE:RealityCommon>
        $<TARGET_FILE:EncryptionClient>
        $<TARGET_FILE:PacketsToStream>
        $<TARGET_FILE:Router>
        $<TARGET_FILE:HttpClient>
        $<TARGET_FILE:HttpCommon>
        $<TARGET_FILE:ObfuscatorClient>
        $<TARGET_FILE:TcpOverUdpClient>
        $<TARGET_OBJECTS:http_client_def>
        $<TARGET_OBJECTS:tcp_over_udp_fec>
        $<TARGET_OBJECTS:tcp_over_udp_client_kcp>
        $<TARGET_FILE:nghttp2_static>
        $<TARGET_FILE:ssl>
        $<TARGET_FILE:crypto>
        $<TARGET_OBJECTS:fipsmodule>
        $<TARGET_FILE:OpenSSL::SSL>
        $<TARGET_FILE:OpenSSL::Crypto>
        $<TARGET_FILE:ww>
        $<TARGET_FILE:ww_lwip>
        $<TARGET_FILE:ww_packet_batch>
        $<TARGET_FILE:mimalloc-static>
        $<TARGET_FILE:maxminddb>
        $<TARGET_FILE:c-ares>
        $<TARGET_FILE:sodium>
        $<TARGET_FILE:ww_xz_decoder>
        $<TARGET_FILE:xz_embedded>
        $<TARGET_FILE:libuuid>
        $<TARGET_FILE:waterwall_cpp_allocator>
        ${SRP_QUIC_ARCHIVE_FILES}
    DEPENDS
        SRPWaterWallBridge
        NEPacketDevice
        PacketsToConnection
        TcpUdpConnector
        TcpConnector
        UdpConnector
        DomainResolver
        StreamFragmenter
        VlessClient
        VmessClient
        VmessCommon
        TrojanClient
        Bgp4Client
        Socks5Client
        HttpProxyClient
        HttpProxyCommon
        TlsClient
        MuxClient
        MuxCommon
        TlsRecordShapingCommon
        WireGuardDevice
        UdpStatelessSocket
        AuthenticationClient
        UserController
        RealityClient
        RealityCommon
        EncryptionClient
        PacketsToStream
        Router
        HttpClient
        HttpCommon
        ObfuscatorClient
        TcpOverUdpClient
        http_client_def
        tcp_over_udp_fec
        tcp_over_udp_client_kcp
        nghttp2_static
        ssl
        crypto
        fipsmodule
        OpenSSL::SSL
        OpenSSL::Crypto
        ww
        ww_lwip
        ww_packet_batch
        mimalloc-static
        maxminddb
        c-ares
        sodium
        ww_xz_decoder
        xz_embedded
        libuuid
        waterwall_cpp_allocator
        ${SRP_QUIC_ARCHIVE_TARGETS}
    COMMAND_EXPAND_LISTS
    COMMENT "Packing the self-contained WaterWall runtime archive"
)
add_custom_target(SRPWaterWallRuntime ALL DEPENDS ${SRP_RUNTIME_ARCHIVE})
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME srp_openssl_prefix_contract
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/openssl_prefix_contract.py
                 $<TARGET_FILE:OpenSSL::SSL> $<TARGET_FILE:OpenSSL::Crypto>)

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
