#include <libdane/DANERecord.h>
#include <sstream>

using namespace libdane;

DANERecord::DANERecord()
{
	
}

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType mtype, std::vector<char> data):
	usage(usage), selector(selector), mtype(mtype), data(data)
{
	
}

DANERecord::~DANERecord()
{
	
}

std::string DANERecord::dataString() const
{
	std::stringstream ss;
	ss << std::hex;
	for (auto it = data.begin(); it != data.end(); ++it) {
		// Cast to uint8_t to make it the right sign, then to int to make it
		// display as hex - a uint8_t on its own is printed as a char
		ss << static_cast<int>(static_cast<uint8_t>(*it));
	}
	return ss.str();
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
