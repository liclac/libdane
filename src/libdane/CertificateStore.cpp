#include <libdane/CertificateStore.h>

using namespace libdane;

int CertificateStore::ctx_data_idx = X509_STORE_CTX_get_ex_new_index(0, NULL, CertificateStore::ctx_data_t_new_func, NULL, CertificateStore::ctx_data_t_free_func);

CertificateStore::CertificateStore(X509_STORE_CTX *ctx):
	m_ctx(ctx)
{
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
std::deque<Certificate> CertificateStore::chain() const { return m_chain; }

Certificate CertificateStore::currentCert() const
{
	return X509_STORE_CTX_get_current_cert(m_ctx);
}


bool CertificateStore::shouldPassAllChecks() const
{
	return this->data()->pass_all_checks;
}

void CertificateStore::setShouldPassAllChecks(bool v)
{
	this->data()->pass_all_checks = v;
}



CertificateStore::ctx_data_t* CertificateStore::data() const
{
	void *ptr = X509_STORE_CTX_get_ex_data(m_ctx, ctx_data_idx);
	return static_cast<ctx_data_t*>(ptr);
}

int CertificateStore::ctx_data_t_new_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	auto ctx = static_cast<X509_STORE_CTX*>(parent);
	auto data = new CertificateStore::ctx_data_t;
	
	if (!X509_STORE_CTX_set_ex_data(ctx, idx, data)) {
		throw std::runtime_error("A X509_STORE_CTX was created, but a CertificateStore::ctx_data_t could not be attached to it.");
	}
	
	return 0; // The returned value is ignored
}

void CertificateStore::ctx_data_t_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	delete static_cast<CertificateStore::ctx_data_t*>(ptr);
}
