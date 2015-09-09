set(VENDOR_DIR ${CMAKE_CURRENT_LIST_DIR})
set(VENDOR_BUILD_DIR ${CMAKE_BINARY_DIR}/vendor)

if(APPLE)
	# Use OpenSSL from Homebrew on OSX
	include_directories(/usr/local/opt/openssl/include)
	link_directories(/usr/local/opt/openssl/lib)
endif()

include_directories(${VENDOR_DIR}/asio/asio/include)
include_directories(${VENDOR_DIR}/catch/include)
include_directories(${VENDOR_BUILD_DIR}/libldns-prefix/include)
