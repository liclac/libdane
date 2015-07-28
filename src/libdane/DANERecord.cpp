#include <libdane/DANERecord.h>
#include <sstream>

using namespace libdane;

DANERecord::DANERecord()
{
	
}

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType mtype, const std::string &data):
	usage(usage), selector(selector), mtype(mtype), data(data)
{
	
}

DANERecord::~DANERecord()
{
	
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
	
	ss << ", \"" << data << "\")";
	
	return ss.str();
}
