cmake_minimum_required(VERSION 3.16)
project(probe-manager CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/main.cpp
    src/config.cpp
    src/epoll_server.cpp
    src/probe_connection.cpp
    src/cloud_client.cpp
    src/rule_manager.cpp
    src/log_aggregator.cpp
)

add_executable(probe-manager ${SOURCES})

target_include_directories(probe-manager PRIVATE
    include
    ${CMAKE_SOURCE_DIR}/common/include
)

target_link_libraries(probe-manager PRIVATE probe_common)
