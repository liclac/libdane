#ifndef LIBDANE_X509_H
#define LIBDANE_X509_H

#include <asio/ssl.hpp>
#include "Blob.h"

namespace libdane
{
	/**
	 * Wrapper around an OpenSSL certificate.
	 */
	class Certificate
	{
	public:
		/**
		 * Constructor.
		 * 
		 * @param x509 Underlying representation
		 */
		Certificate(X509 *x509 = nullptr);
		
		/**
		 * Destructor.
		 */
		virtual ~Certificate();
		
		/**
		 * Returns the underlying representation.
		 */
		X509 *x509() const;
		
		/**
		 * Returns the certificate's Subject Name as a DN string.
		 */
		std::string subjectDN() const;
		
		/**
		 * Returns the certificate's Issuer Name as a DN string.
		 */
		std::string issuerDN() const;
		
		/**
		 * Returns the public key.
		 */
		Blob publicKey() const;
		
		/**
		 * A certificate is truthy if it has an underlying representation.
		 */
		explicit operator bool() const { return m_x509 != nullptr; };
		
	protected:
		/**
		 * Turns an X509_NAME* into a string.
		 * 
		 * @param  name A name to represent
		 * @return      The result of X509_NAME_oneline()
		 */
		std::string nameStr(X509_NAME *name) const;
		
	private:
		X509 *m_x509;
	};
}

#endif
