#ifndef LIBDANE_VERIFYCONTEXT_H
#define LIBDANE_VERIFYCONTEXT_H

#include "Certificate.h"
#include <asio/ssl.hpp>
#include <deque>

namespace libdane
{
	/**
	 * Wrapper around an OpenSSL certificate store.
	 * 
	 * Note that this class does not store any data itself - everything is
	 * stored as additional data on the context itself, with the exception of
	 * the certificate chain, which is retained and cached to prevent weirdness
	 * with the reference count of the certificates.
	 * 
	 * \todo Make Certificate retain native representations instead.
	 */
	class VerifyContext
	{
	public:
		/**
		 * Constructor.
		 * 
		 * @param ctx Underlying context
		 */
		VerifyContext(X509_STORE_CTX *ctx = nullptr);
		
		/**
		 * Convenience constructor.
		 * 
		 * This is the same as calling `VerifyContext(vc.native_handle())`.
		 */
		VerifyContext(asio::ssl::verify_context &vc);
		
		/**
		 * Copy constructor.
		 */
		VerifyContext(const VerifyContext &store);
		
		/**
		 * Destructor.
		 */
		virtual ~VerifyContext();
		
		/**
		 * Returns the underlying context for the store.
		 */
		X509_STORE_CTX *ctx() const;
		
		/**
		 * Returns the chain of certificates in the store.
		 */
		std::deque<Certificate> chain() const;
		
		/**
		 * Returns the currently operating certificate.
		 */
		Certificate currentCert() const;
		
		/**
		 * A context is truthy if it has a valid underlying context.
		 */
		explicit operator bool() const { return m_ctx != nullptr; };
		
	private:
		X509_STORE_CTX *m_ctx = nullptr;
		
		STACK_OF(X509) *m_chain_stack = nullptr;
		std::deque<Certificate> m_chain;
	};
}

#endif
