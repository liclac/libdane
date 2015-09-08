/**
 * Certificate.cpp
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <libdane/Certificate.h>
#include <regex>

using namespace libdane;

std::deque<Certificate> Certificate::parsePEM(const std::string &pem)
{
	static std::regex pemex("([-]+BEGIN CERTIFICATE[-]+\\n[A-Za-z0-9\\+\\/\n\\=]+\\n[-]+END CERTIFICATE[-]+)");
	
	std::deque<Certificate> certs;
	
	auto begin = std::sregex_iterator(pem.begin(), pem.end(), pemex);
	auto end = std::sregex_iterator();
	for (auto it = begin; it != end; ++it) {
		std::smatch match = *it;
		std::string str = match.str();
		certs.emplace_back(str);
	}
	
	return certs;
}



Certificate::Certificate(X509 *x509):
	m_x509(x509 ? X509_dup(x509) : NULL)
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
	if (m_x509) {
		X509_free(m_x509);
	}
}



X509* Certificate::x509() const { return m_x509; }

std::string Certificate::subjectDN() const
{
	if (!m_x509) {
		return std::string();
	}
	
	return this->nameStr(X509_get_subject_name(m_x509));
}

std::string Certificate::issuerDN() const
{
	if (!m_x509) {
		return std::string();
	}
	
	return this->nameStr(X509_get_issuer_name(m_x509));
}

Blob Certificate::publicKey() const
{
	if (!m_x509) {
		return Blob();
	}
	
	unsigned char *buf = NULL;
	EVP_PKEY *pkey = X509_get_pubkey(m_x509);
	int size = i2d_PUBKEY(pkey, &buf);
	Blob blob(buf, size);
	free(buf);
	
	return blob;
}

Blob Certificate::encoded() const
{
	if (!m_x509) {
		return Blob();
	}
	
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

bool Certificate::verify(const Certificate &other) const
{
	auto pkey = std::shared_ptr<EVP_PKEY>(X509_get_pubkey(other.x509()), EVP_PKEY_free);
	int result = X509_verify(m_x509, &*pkey);
	return result > 0;
}



std::string Certificate::nameStr(X509_NAME *name) const
{
	char *c_str = X509_NAME_oneline(name, NULL, 0);
	std::string str(c_str);
	free(c_str);
	
	return str;
}
