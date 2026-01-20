cmake_minimum_required(VERSION 3.16)

project(attack_tool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(CURL REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/attack_tool.cpp
    src/socket_client.cpp
    src/task_executor.cpp
    src/generators/http_generator.cpp
    src/generators/tcp_generator.cpp
    src/generators/udp_generator.cpp
)

# Create executable
add_executable(attack_tool ${SOURCES})

# Include directories
target_include_directories(attack_tool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/include
    ${CURL_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(attack_tool PRIVATE
    probe_common
    ${CURL_LIBRARIES}
)

# Install
install(TARGETS attack_tool DESTINATION bin)
