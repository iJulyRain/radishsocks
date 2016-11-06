add_executable(rsserver server.c log.c cipher.c)
target_link_libraries(rsserver event)

add_executable(rsclient client.c log.c cipher.c)
target_link_libraries(rsclient event)
