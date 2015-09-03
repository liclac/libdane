#include <libdane/VerifyContext.h>

using namespace libdane;

VerifyContext::VerifyContext(X509_STORE_CTX *ctx):
	m_ctx(ctx)
{
	m_chain_stack = X509_STORE_CTX_get1_chain(m_ctx);
	for (int i = 0; i < sk_X509_num(m_chain_stack); ++i) {
		X509 *cert = sk_X509_value(m_chain_stack, i);
		m_chain.emplace_back(cert);
	}
}

VerifyContext::VerifyContext(const VerifyContext &store):
	VerifyContext(store.ctx()) {}

VerifyContext::~VerifyContext()
{
	sk_X509_pop_free(m_chain_stack, X509_free);
}



X509_STORE_CTX* VerifyContext::ctx() const { return m_ctx; }
std::deque<Certificate> VerifyContext::chain() const { return m_chain; }

Certificate VerifyContext::currentCert() const
{
	return X509_STORE_CTX_get_current_cert(m_ctx);
}
