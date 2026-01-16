# NIDS 探针
cmake_minimum_required(VERSION 3.16)
project(nids-probe CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找依赖
find_package(Threads REQUIRED)

# 源文件
set(SOURCES
    src/main.cpp
    src/nids_probe.cpp
    src/suricata_manager.cpp
    src/eve_parser.cpp
    src/socket_client.cpp
)

# 可执行文件
add_executable(nids-probe ${SOURCES})

target_include_directories(nids-probe PRIVATE
    include
    ${CMAKE_SOURCE_DIR}/common/include
)

target_link_libraries(nids-probe PRIVATE
    Threads::Threads
    probe_common
)

# 安装
install(TARGETS nids-probe DESTINATION bin)
