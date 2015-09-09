file(GLOB LIBDANENET_SOURCES *.h *.cpp)
add_library(dane_net ${LIBDANENET_SOURCES})
target_link_libraries(dane_net dane)
