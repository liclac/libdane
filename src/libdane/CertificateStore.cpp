#include <libdane/CertificateStore.h>

using namespace libdane;

CertificateStore::CertificateStore(X509_STORE_CTX *ctx):
	m_ctx(ctx)
{
	m_currentCert = X509_STORE_CTX_get_current_cert(ctx);
	
	m_chain_stack = X509_STORE_CTX_get1_chain(m_ctx);
	for (int i = 0; i < sk_X509_num(m_chain_stack); ++i) {
		X509 *cert = sk_X509_value(m_chain_stack, i);
		m_chain.emplace_back(cert);
	}
}

CertificateStore::CertificateStore(asio::ssl::verify_context &vc):
	CertificateStore(vc.native_handle()) {}

CertificateStore::~CertificateStore()
{
	sk_X509_pop_free(m_chain_stack, X509_free);
}



X509_STORE_CTX* CertificateStore::ctx() const { return m_ctx; }
Certificate CertificateStore::currentCert() const { return m_currentCert; }
std::deque<Certificate> CertificateStore::chain() const { return m_chain; }
