include_directories(
${PROJECT_SOURCE_DIR}/radishsocks/crypto
${PROJECT_SOURCE_DIR}/radishsocks/camouflage)

link_directories(
${PROJECT_SOURCE_DIR}/radishsocks/crypto
${PROJECT_SOURCE_DIR}/radishsocks/camouflage
)

add_subdirectory(crypto)
add_subdirectory(camouflage)

add_executable(rsserver server.c log.c)
target_link_libraries(rsserver rscrypto rscamouflage event)

add_executable(rsclient client.c log.c)
target_link_libraries(rsclient rscrypto rscamouflage event)
