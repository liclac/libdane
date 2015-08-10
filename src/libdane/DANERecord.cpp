#include <libdane/DANERecord.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>

using namespace libdane;
using namespace std::placeholders;

int DANERecord::store_ctx_data_idx = X509_STORE_CTX_get_ex_new_index(0, NULL, DANERecord::store_ctx_data_t_new_func, NULL, DANERecord::store_ctx_data_t_free_func);

DANERecord::DANERecord()
{
	
}

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType mtype, std::vector<unsigned char> data):
	usage(usage), selector(selector), mtype(mtype), data(data)
{
	
}

DANERecord::~DANERecord()
{
	
}

std::string DANERecord::dataString() const
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (auto it = data.begin(); it != data.end(); ++it) {
		ss << std::setw(2) << static_cast<int>(*it);
	}
	return ss.str();
}

bool DANERecord::verify(bool preverified, asio::ssl::verify_context &vc) const
{
	X509_STORE_CTX *ctx = vc.native_handle();
	X509* cert = X509_STORE_CTX_get_current_cert(ctx);
	if (!cert) {
		return false;
	}
	
	store_ctx_data_t *data = dataForContext(vc);
	if (data->pass_all_checks) {
		return true;
	}
	
	switch (usage) {
		case CAConstraints:
			return verifyCAConstraints(preverified, vc);
		case ServiceCertificateConstraint:
			return verifyServiceCertificateConstraint(preverified, vc);
		case TrustAnchorAssertion:
			return verifyTrustAnchorAssertion(preverified, vc);
		case DomainIssuedCertificate:
			return verifyDomainIssuedCertificate(preverified, vc);
		default:
			throw std::runtime_error("Invalid certificate usage");
	}
	
	return false;
}

std::string DANERecord::toString() const
{
	std::stringstream ss;
	ss << "DANERecord(";
	
	switch (usage) {
		case CAConstraints:
			ss << "CAConstraints";
			break;
		case ServiceCertificateConstraint:
			ss << "ServiceCertificateConstraint";
			break;
		case TrustAnchorAssertion:
			ss << "TrustAnchorAssertion";
			break;
		case DomainIssuedCertificate:
			ss << "DomainIssuedCertificate";
			break;
		default:
			ss << "???";
	}
	
	ss << ", ";
	
	switch (selector) {
		case FullCertificate:
			ss << "FullCertificate";
			break;
		case SubjectPublicKeyInfo:
			ss << "SubjectPublicKeyInfo";
			break;
	}
	
	ss << ", ";
	
	switch (mtype) {
		case ExactMatch:
			ss << "ExactMatch";
			break;
		case SHA256:
			ss << "SHA256";
			break;
		case SHA512:
			ss << "SHA512";
			break;
	}
	
	ss << ", \"" << dataString() << "\")";
	
	return ss.str();
}

bool DANERecord::verifyCAConstraints(bool preverified, asio::ssl::verify_context &vc) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyServiceCertificateConstraint(bool preverified, asio::ssl::verify_context &vc) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyTrustAnchorAssertion(bool preverified, asio::ssl::verify_context &vc) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyDomainIssuedCertificate(bool preverified, asio::ssl::verify_context &vc) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

DANERecord::store_ctx_data_t* DANERecord::dataForContext(asio::ssl::verify_context &vc) const
{
	X509_STORE_CTX *ctx = vc.native_handle();
	void *ptr = X509_STORE_CTX_get_ex_data(ctx, store_ctx_data_idx);
	return static_cast<store_ctx_data_t*>(ptr);
}

int DANERecord::store_ctx_data_t_new_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	auto ctx = static_cast<X509_STORE_CTX*>(parent);
	auto data = new DANERecord::store_ctx_data_t;
	bool status = X509_STORE_CTX_set_ex_data(ctx, idx, data);
	
	if (!status) {
		throw std::runtime_error("A X509_STORE_CTX was created, but a DANERecord::store_ctx_data_t could not be attached to it.");
	}
	
	return 0; // The returned value is ignored
}

void DANERecord::store_ctx_data_t_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	delete static_cast<DANERecord::store_ctx_data_t*>(ptr);
}
