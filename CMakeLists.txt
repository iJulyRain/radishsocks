PROJECT(radishsocks)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

add_definitions(-DDAEMON_MODE)
add_definitions(-DVER_RELEASE)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(CMAKE_C_FLAGS "-Wall -O2")

include_directories(${PROJECT_SOURCE_DIR}/radishsocks/)

link_directories(${PROJECT_SOURCE_DIR}/radishsocks/)

add_subdirectory(radishsocks)
