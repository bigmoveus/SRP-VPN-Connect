add_library(NEPacketDevice STATIC
    create.c
    node.c
    queue.c
    start.c
    stop.c
    submit.c
    write.c
)

target_include_directories(NEPacketDevice PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)
target_link_libraries(NEPacketDevice ww)
set_target_properties(NEPacketDevice PROPERTIES UNITY_BUILD OFF)
