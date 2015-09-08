/**
 * internal/openssl.h
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_INTERNAL_OPENSSL_H
#define LIBDANE_INTERNAL_OPENSSL_H

/**
 * \file
 * Includes and initializes OpenSSL.
 * 
 * Heavily based off the following files from ASIO:
 * 
 * - asio/ssl/detail/openssl_types.hpp
 * - asio/ssl/detail/openssl_init.hpp
 * - asio/ssl/detail/impl/openssl_init.ipp
 */

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#ifndef LIBDANE_NO_INIT_OPENSSL
namespace libdane
{
	namespace internal
	{
		namespace initializers
		{
			/**
			 * Initializes OpenSSL.
			 * 
			 * To prevent this from happening, define `LIBDANE_NO_INIT_OPENSSL`
			 * prior to including any libdane files - possibly in a prefix
			 * header or a compiler flag.
			 */
			class openssl
			{
			public:
				/**
				 * Initializes the OpenSSL library.
				 */
				openssl()
				{
					::SSL_library_init();
					::SSL_load_error_strings();
					::OpenSSL_add_all_algorithms();
				}
			};
			
			/// Static initializer object
			static openssl _init_openssl;
		}
	}
}
#endif

#endif
