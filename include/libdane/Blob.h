#ifndef LIBDANE_BLOB_H
#define LIBDANE_BLOB_H

#include <vector>
#include <asio/ssl.hpp>
#include "common.h"

namespace libdane
{
	/**
	 * Container for operating on binary data.
	 */
	class Blob
	{
	public:
		/**
		 * Default constructor.
		 */
		Blob();
		
		/**
		 * Constructs a blob by copying existing data.
		 */
		Blob(const unsigned char *data, unsigned int size);
		
		/**
		 * Constructs a blob by copying existing data.
		 */
		Blob(const std::vector<unsigned char> &data);
		
		/**
		 * Destructor.
		 */
		virtual ~Blob();
		
		
		
		/**
		 * Returns a reference to the underlying data.
		 */
		const std::vector<unsigned char>& data() const;
		
		/**
		 * Sets the underlying data.
		 */
		void setData(const std::vector<unsigned char> &v);
		
		
		
		/**
		 * Returns the SHA256 hash of the data.
		 */
		Blob sha256() const;
		
		/**
		 * Returns the SHA512 hash of the data.
		 */
		Blob sha512() const;
		
		/**
		 * Returns the match data for the given matching type.
		 * 
		 * @see Blob::sha256()
		 * @see Blob::sha512()
		 */
		Blob match(MatchingType mtype) const;
		
		
		
		/**
		 * Returns the data as a hexadecimal string.
		 */
		std::string hex() const;
		
	protected:
		/**
		 * Common implementation for the hash functions.
		 * 
		 * https://www.openssl.org/docs/crypto/EVP_DigestInit.html
		 * 
		 * @param  type A hash type function
		 * @return      A hash of the requested type
		 */
		Blob hash(const EVP_MD *type) const;
		
	private:
		std::vector<unsigned char> m_data;
	};
}

#endif
