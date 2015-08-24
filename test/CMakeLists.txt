# Don't flood the normal output directories with test binaries
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}/test)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/test)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/test)

# All files called test_*.cpp should be turned into test targets
# Target names are based on the files' relative paths from this directory,
# with any slashes replaced with underscores
file(GLOB TEST_SOURCES */test_*.cpp)
foreach (path ${TEST_SOURCES})
	string(REGEX REPLACE "^${CMAKE_CURRENT_LIST_DIR}/" "" relpath ${path})
	string(REGEX REPLACE "/+" "_" target ${relpath})
	string(REGEX REPLACE ".cpp" "" target ${target})
	add_executable(${target} main.cpp resources.cpp ${path})
	target_link_libraries(${target} dane dane_net ssl crypto ldns)
	add_test(NAME ${target} COMMAND ${target})
endforeach()
