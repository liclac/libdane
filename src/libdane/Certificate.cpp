#include <libdane/Certificate.h>

using namespace libdane;

Certificate::Certificate(X509 *x509):
	m_x509(X509_dup(x509))
{
	
}

Certificate::Certificate(const Certificate &other):
	Certificate(other.x509()) {}

Certificate::Certificate(const std::string &pem)
{
	std::vector<char> tmp(pem.data(), pem.data() + pem.size());
	auto bio = std::shared_ptr<BIO>(BIO_new_mem_buf(static_cast<void*>(tmp.data()), tmp.size()), BIO_free);
	m_x509 = PEM_read_bio_X509(&*bio, NULL, NULL, NULL);
}

Certificate::~Certificate()
{
	X509_free(m_x509);
}



X509* Certificate::x509() const { return m_x509; }

std::string Certificate::subjectDN() const
{
	return this->nameStr(X509_get_subject_name(m_x509));
}

std::string Certificate::issuerDN() const
{
	return this->nameStr(X509_get_issuer_name(m_x509));
}

Blob Certificate::publicKey() const
{
	unsigned char *buf = NULL;
	EVP_PKEY *pkey = X509_get_pubkey(m_x509);
	int size = i2d_PUBKEY(pkey, &buf);
	Blob blob(buf, size);
	free(buf);
	
	return blob;
}

Blob Certificate::encoded() const
{
	unsigned char *buf = NULL;
	int size = i2d_X509(m_x509, &buf);
	Blob blob(buf, size);
	free(buf);
	
	return blob;
}

Blob Certificate::select(Selector sel) const
{
	switch (sel) {
		case FullCertificate:
			return this->encoded();
		case SubjectPublicKeyInfo:
			return this->publicKey();
		default:
			throw std::runtime_error("Unknown selector");
	}
}



std::string Certificate::nameStr(X509_NAME *name) const
{
	char *c_str = X509_NAME_oneline(name, NULL, 0);
	std::string str(c_str);
	free(c_str);
	
	return str;
}
