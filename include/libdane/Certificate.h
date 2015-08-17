#ifndef LIBDANE_X509_H
#define LIBDANE_X509_H

#include <asio/ssl.hpp>
#include "Blob.h"
#include "common.h"

namespace libdane
{
	/**
	 * Wrapper around an OpenSSL certificate.
	 */
	class Certificate
	{
	public:
		/**
		 * Creates a certificate from an X509 object.
		 * 
		 * The certificate is copied, and destroyed with this object.
		 * 
		 * @param x509 Underlying representation
		 */
		Certificate(X509 *x509 = nullptr);
		
		/**
		 * Copy constructor.
		 */
		Certificate(const Certificate &other);
		
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
		 * Returns the certificate's public key.
		 */
		Blob publicKey() const;
		
		/**
		 * Returns the DER representation of the certificate.
		 */
		Blob encoded() const;
		
		/**
		 * Returns the data matching the given selector.
		 * 
		 * @see Certificate::publicKey()
		 * @see Certificate::data()
		 */
		Blob select(Selector sel) const;
		
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
