cmake_minimum_required(VERSION 3.16)
project(ai-idps-probe CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(common)
add_subdirectory(manager)
add_subdirectory(nids)
add_subdirectory(attack_tool)
