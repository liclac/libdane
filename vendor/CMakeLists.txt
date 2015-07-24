include(ExternalProject)

# 
# --> libldns
# 
if(APPLE)
	# Use OpenSSL from Homebrew on OSX
	list(APPEND EXTRA_LDNS_CONFIGURE_FLAGS "--with-ssl=/usr/local/opt/openssl")
endif()

ExternalProject_Add(libldns
	URL "http://www.nlnetlabs.nl/downloads/ldns/ldns-1.6.17.tar.gz"
	URL_HASH SHA1=4218897b3c002aadfc7280b3f40cda829e05c9a4
	CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR> ${EXTRA_LDNS_CONFIGURE_FLAGS}
	BUILD_COMMAND make
	INSTALL_COMMAND make install
)
ExternalProject_Get_Property(libldns INSTALL_DIR)

add_library(ldns STATIC IMPORTED GLOBAL)
set_target_properties(ldns PROPERTIES IMPORTED_LOCATION ${INSTALL_DIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}ldns${CMAKE_STATIC_LIBRARY_SUFFIX})
