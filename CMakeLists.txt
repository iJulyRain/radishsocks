PROJECT(radishsocks)

cmake_minimum_required(VERSION 2.8)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

add_definitions(-DDAEMON_MODE)
add_definitions(-DVER_RELEASE)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/output)
set(CMAKE_C_FLAGS "-Wall -g ")

include_directories(
${PROJECT_SOURCE_DIR}/radishsocks/
${PROJECT_SOURCE_DIR}/libevent/include/
${PROJECT_SOURCE_DIR}/tcmalloc/include/
)

link_directories(
${PROJECT_SOURCE_DIR}/radishsocks/
${PROJECT_SOURCE_DIR}/libevent/lib/
${PROJECT_SOURCE_DIR}/tcmalloc/lib/
)

add_subdirectory(radishsocks)
