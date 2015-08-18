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

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType matching, std::vector<unsigned char> data):
	m_usage(usage), m_selector(selector), m_matching(matching), m_data(data)
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
	
	switch (m_usage) {
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
	
	switch (m_usage) {
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
	
	switch (m_selector) {
		case FullCertificate:
			ss << "FullCertificate";
			break;
		case SubjectPublicKeyInfo:
			ss << "SubjectPublicKeyInfo";
			break;
	}
	
	ss << ", ";
	
	switch (m_matching) {
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
	
	ss << ", \"" << m_data.hex() << "\")";
	
	return ss.str();
}



Usage DANERecord::usage() const { return m_usage; }
void DANERecord::setUsage(Usage v) { m_usage = v; }

Selector DANERecord::selector() const { return m_selector; }
void DANERecord::setSelector(Selector v) { m_selector = v; }

MatchingType DANERecord::matching() const { return m_matching; }
void DANERecord::setMatching(MatchingType v) { m_matching = v; }

Blob DANERecord::data() const { return m_data; }
void DANERecord::setData(Blob v) { m_data = v; }



bool DANERecord::verifyCAConstraints(bool preverified, CertificateStore &store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyServiceCertificateConstraint(bool preverified, CertificateStore &store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyTrustAnchorAssertion(bool preverified, CertificateStore &store) const
{
	throw std::runtime_error("Not yet implemented!");
	return false;
}

bool DANERecord::verifyDomainIssuedCertificate(bool preverified, CertificateStore &store) const
{
	std::deque<Certificate> chain = store.chain();
	Certificate &cert = chain.front();
	Blob match = cert.select(m_selector).match(m_matching);
	return match == m_data;
}
