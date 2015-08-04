# Use ASIO standalone, with no dependency on Boost
add_definitions(-DASIO_STANDALONE)

file(GLOB DANETOOL_SOURCES *.h *.cpp)
add_executable(danetool ${DANETOOL_SOURCES})
target_link_libraries(danetool dane ssl crypto ldns)
