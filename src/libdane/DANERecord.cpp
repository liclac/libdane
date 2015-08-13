#include <libdane/DANERecord.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>

using namespace libdane;
using namespace std::placeholders;

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

bool DANERecord::verify(bool preverified, asio::ssl::verify_context &vc) const
{
	CertificateStore store(vc);
	if (!store.currentCert()) {
		return false;
	}
	
	if (store.shouldPassAllChecks()) {
		return true;
	}
	
	switch (usage) {
		case CAConstraints:
			return verifyCAConstraints(preverified, store);
		case ServiceCertificateConstraint:
			return verifyServiceCertificateConstraint(preverified, store);
		case TrustAnchorAssertion:
			return verifyTrustAnchorAssertion(preverified, store);
		case DomainIssuedCertificate:
			return verifyDomainIssuedCertificate(preverified, store);
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
	
	ss << ", \"" << data.hex() << "\")";
	
	return ss.str();
}

bool DANERecord::verifyCAConstraints(bool preverified, CertificateStore store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyServiceCertificateConstraint(bool preverified, CertificateStore store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyTrustAnchorAssertion(bool preverified, CertificateStore store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyDomainIssuedCertificate(bool preverified, CertificateStore store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}
