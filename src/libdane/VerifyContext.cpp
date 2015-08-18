#include <libdane/VerifyContext.h>

using namespace libdane;

int VerifyContext::ctx_data_idx = X509_STORE_CTX_get_ex_new_index(0, NULL, VerifyContext::ctx_data_t_new_func, NULL, VerifyContext::ctx_data_t_free_func);

VerifyContext::VerifyContext(X509_STORE_CTX *ctx):
	m_ctx(ctx)
{
	m_chain_stack = X509_STORE_CTX_get1_chain(m_ctx);
	for (int i = 0; i < sk_X509_num(m_chain_stack); ++i) {
		X509 *cert = sk_X509_value(m_chain_stack, i);
		m_chain.emplace_back(cert);
	}
}

VerifyContext::VerifyContext(asio::ssl::verify_context &vc):
	VerifyContext(vc.native_handle()) {}

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


bool VerifyContext::shouldPassAllChecks() const
{
	return this->data()->pass_all_checks;
}

void VerifyContext::setShouldPassAllChecks(bool v)
{
	this->data()->pass_all_checks = v;
}



VerifyContext::ctx_data_t* VerifyContext::data() const
{
	void *ptr = X509_STORE_CTX_get_ex_data(m_ctx, ctx_data_idx);
	return static_cast<ctx_data_t*>(ptr);
}

int VerifyContext::ctx_data_t_new_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	auto ctx = static_cast<X509_STORE_CTX*>(parent);
	auto data = new VerifyContext::ctx_data_t;
	
	if (!X509_STORE_CTX_set_ex_data(ctx, idx, data)) {
		throw std::runtime_error("A X509_STORE_CTX was created, but a VerifyContext::ctx_data_t could not be attached to it.");
	}
	
	return 0; // The returned value is ignored
}

void VerifyContext::ctx_data_t_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	delete static_cast<VerifyContext::ctx_data_t*>(ptr);
}
