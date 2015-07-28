file(GLOB DANETOOL_SOURCES *.h *.cpp)
add_executable(danetool ${DANETOOL_SOURCES})
target_link_libraries(danetool dane ssl crypto ldns)
