cmake_minimum_required(VERSION 3.25)
project(SRPVPNAndroid LANGUAGES C CXX)

add_subdirectory(../../../../../WaterWall waterwall-runtime)

add_library(waterwall SHARED waterwall_jni.c)
target_link_libraries(waterwall PRIVATE SRPWaterWallBridge maxminddb sodium)
# Only the JNI functions are for outsiders: the allocator's operator new and the crypto stay private.
target_link_options(waterwall PRIVATE "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
set_target_properties(waterwall PROPERTIES LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/exports.map")
