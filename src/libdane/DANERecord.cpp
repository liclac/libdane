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

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType matching, Blob data):
	m_usage(usage), m_selector(selector), m_matching(matching), m_data(data)
{
	
}

DANERecord::~DANERecord()
{
	
}

DANERecord::VerifyResult DANERecord::verify(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	switch (m_usage) {
		case CAConstraints:
			return verifyCAConstraints(preverified, cert, chain);
		case ServiceCertificateConstraint:
			return verifyServiceCertificateConstraint(preverified, cert, chain);
		case TrustAnchorAssertion:
			return verifyTrustAnchorAssertion(preverified, cert, chain);
		case DomainIssuedCertificate:
			return verifyDomainIssuedCertificate(preverified, cert, chain);
		default:
			throw std::runtime_error("Invalid certificate usage");
	}
}

bool DANERecord::verify(bool preverified, asio::ssl::verify_context &vc) const
{
	VerifyContext ctx(vc);
	if (!ctx.currentCert()) {
		return false;
	}
	
	if (ctx.shouldPassAllChecks()) {
		return true;
	}
	
	Certificate cert = ctx.currentCert();
	std::deque<Certificate> chain = ctx.chain();
	VerifyResult result = verify(preverified, cert, chain);
	
	switch (result) {;
		case Fail:
			return false;
		case Pass:
			return true;
		case PassAll:
			ctx.setShouldPassAllChecks(true);
			return true;
		default:
			throw std::runtime_error("Invalid verification result");
	}
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
		case SHA256Hash:
			ss << "SHA256Hash";
			break;
		case SHA512Hash:
			ss << "SHA512Hash";
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



DANERecord::VerifyResult DANERecord::verifyCAConstraints(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	throw std::runtime_error("Not yet implemented!");
	return Fail;
}

DANERecord::VerifyResult DANERecord::verifyServiceCertificateConstraint(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	throw std::runtime_error("Not yet implemented!");
	return Fail;
}

DANERecord::VerifyResult DANERecord::verifyTrustAnchorAssertion(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	throw std::runtime_error("Not yet implemented!");
	return Fail;
}

DANERecord::VerifyResult DANERecord::verifyDomainIssuedCertificate(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	const Certificate &domainCert = chain.front();
	Blob match = domainCert.select(m_selector).match(m_matching);
	return match == m_data ? PassAll : Fail;
}
