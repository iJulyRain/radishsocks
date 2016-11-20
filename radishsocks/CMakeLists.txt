AUX_SOURCE_DIRECTORY(. SRC)

add_executable(rssocks ${SRC})
target_link_libraries(rssocks event tcmalloc)
