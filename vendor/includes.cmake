set(VENDOR_DIR ${CMAKE_CURRENT_LIST_DIR})

if(APPLE)
	# Use OpenSSL from Homebrew on OSX
	include_directories(/usr/local/opt/openssl/include)
	link_directories(/usr/local/opt/openssl/lib)
endif()

include_directories(${VENDOR_DIR}/asio/asio/include)
include_directories(${VENDOR_DIR}/libldns-prefix/include)
