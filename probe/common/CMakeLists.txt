cmake_minimum_required(VERSION 3.16)
project(probe-common CXX)

add_library(probe_common
    src/protocol.cpp
)

target_include_directories(probe_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
