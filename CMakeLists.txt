cmake_minimum_required(VERSION 3.1)
project(libdane VERSION 1.0.0)

set (CMAKE_CXX_STANDARD 11)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include(${CMAKE_SOURCE_DIR}/vendor/includes.cmake)
include_directories(include)

# Use ASIO standalone, with no dependency on Boost
add_definitions(-DASIO_STANDALONE)

add_subdirectory(vendor)
add_subdirectory(src)

enable_testing()
add_subdirectory(test)

# Custom `make check` target, that dumps output on test failute
if (CMAKE_CONFIGURATION_TYPES)
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} 
        --force-new-ctest-process --output-on-failure 
        --build-config "$<CONFIGURATION>")
else()
    add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} 
        --force-new-ctest-process --output-on-failure)
endif()
