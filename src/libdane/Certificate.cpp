#include <libdane/Certificate.h>

using namespace libdane;

Certificate::Certificate(X509 *x509):
	m_x509(x509)
{
	
}

Certificate::~Certificate()
{
	
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



std::string Certificate::nameStr(X509_NAME *name) const
{
	char *c_str = X509_NAME_oneline(name, NULL, 0);
	std::string str(c_str);
	free(c_str);
	
	return str;
}
