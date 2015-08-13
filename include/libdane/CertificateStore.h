#ifndef LIBDANE_CERTIFICATESTORE_H
#define LIBDANE_CERTIFICATESTORE_H

#include "Certificate.h"
#include <asio/ssl.hpp>
#include <deque>

namespace libdane
{
	class CertificateStore
	{
	public:
		CertificateStore(X509_STORE_CTX *ctx = nullptr);
		CertificateStore(asio::ssl::verify_context &vc);
		virtual ~CertificateStore();
		
		X509_STORE_CTX *ctx() const;
		
		Certificate currentCert() const;
		std::deque<Certificate> chain() const;
		
		explicit operator bool() const { return m_ctx != nullptr; };
		
	private:
		X509_STORE_CTX *m_ctx = nullptr;
		STACK_OF(X509) *m_chain_stack = nullptr;
		
		Certificate m_currentCert;
		std::deque<Certificate> m_chain;
	};
}

#endif
