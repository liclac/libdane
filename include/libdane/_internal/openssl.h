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
			class openssl
			{
			public:
				openssl()
				{
					::SSL_library_init();
					::SSL_load_error_strings();
					::OpenSSL_add_all_algorithms();
				}
			};
			
			static openssl _init_openssl;
		}
	}
}
#endif

#endif
