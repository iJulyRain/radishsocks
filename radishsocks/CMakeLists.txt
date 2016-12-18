AUX_SOURCE_DIRECTORY(. SRC)

add_executable(rssocks ${SRC})

if (TCMALLOC)
    target_link_libraries(rssocks event tcmalloc_minimal)
else()
    target_link_libraries(rssocks event)
endif()
