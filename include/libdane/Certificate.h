#ifndef LIBDANE_X509_H
#define LIBDANE_X509_H

#include <asio/ssl.hpp>
#include "Blob.h"
#include "common.h"
#include <deque>

namespace libdane
{
	/**
	 * Wrapper around an OpenSSL certificate.
	 */
	class Certificate
	{
	public:
		/**
		 * Parses a PEM file into a list of Certificates.
		 * 
		 * A PEM file can contain multiple certificates, but only one at a time
		 * can be parsed. This is a convenience function that splits a PEM file
		 * into multiple pieces and parses each one.
		 * 
		 * @param pem A PEM-encoded certificate or certificate chain
		 */
		static std::deque<Certificate> parsePEM(const std::string &pem);
		
		/**
		 * Creates a certificate from an X509 object.
		 * 
		 * The certificate is copied, and destroyed with this object.
		 * 
		 * @todo Increment the reference count instead of duplicating
		 * 
		 * @param x509 Underlying representation
		 */
		Certificate(X509 *x509 = nullptr);
		
		/**
		 * Creates a certificate from a PEM string.
		 * 
		 * @param pem The PEM-encoded certificate
		 */
		Certificate(const std::string &pem);
		
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
		 * Verifies that the certificate was issued by another one.
		 * 
		 * @param  other Another certificate
		 * @return       true if other was used to issue this
		 */
		bool verify(const Certificate &other) const;
		
		/**
		 * A certificate is truthy if it has an underlying representation.
		 */
		explicit operator bool() const { return m_x509 != nullptr; };
		
		/**
		 * Two certificates are equal if the underlying certs are.
		 */
		inline bool operator==(const Certificate &other) const { return X509_cmp(m_x509, other.x509()) == 0; };
		
		/// Negated operator==
		inline bool operator!=(const Certificate &other) const { return !(*this == other); };
		
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
