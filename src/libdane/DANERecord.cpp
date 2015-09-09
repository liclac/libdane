/**
 * DANERecord.cpp
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <libdane/DANERecord.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <functional>
#include <algorithm>
#include <stdexcept>

using namespace libdane;
using namespace std::placeholders;

DANERecord::DANERecord()
{
	
}

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType matching, Blob data):
	m_usage(usage), m_selector(selector), m_matching(matching), m_data(data)
{
	
}

DANERecord::DANERecord(Usage usage, Selector selector, MatchingType matching, const Certificate &cert):
	DANERecord(usage, selector, matching, cert.select(selector).match(matching)) {}

DANERecord::~DANERecord()
{
	
}

bool DANERecord::verify(bool preverified, const VerifyContext &ctx) const
{
	if (!ctx.currentCert()) {
		return false;
	}
	
	Certificate cert = ctx.currentCert();
	std::deque<Certificate> chain = ctx.chain();
	
	auto it = std::find(chain.begin(), chain.end(), cert);
	if (it == chain.end()) {
		// The certificate isn't even in the chain, wtf
		return false;
	} else if (it != chain.end() - 1) {
		// Verify that the current cert was in fact issued by the previous cert
		const Certificate &prev = *(it + 1);
		if (!cert.verify(prev)) {
			return false;
		}
	}
	
	return verify(preverified, cert, chain);
}

bool DANERecord::verify(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
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

bool DANERecord::verify(const Certificate &cert) const
{
	return cert.select(m_selector).match(m_matching) == m_data;
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



bool DANERecord::verifyCAConstraints(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	// Reject untrusted certificates
	if (!preverified) {
		return false;
	}
	
	return this->verifyTrustAnchorAssertion(preverified, cert, chain);
}

bool DANERecord::verifyServiceCertificateConstraint(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	// Reject untrusted certificates
	if (!preverified) {
		return false;
	}
	
	return this->verifyDomainIssuedCertificate(preverified, cert, chain);
}

bool DANERecord::verifyTrustAnchorAssertion(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	// Pass non-root certificates; it's already been verified to be issued by
	// the previous one, which means we only need to care about the root cert
	if (cert != chain.back()) {
		return true;
	}
	
	// It's the root certificate; verify it against the record
	return this->verify(cert);
}

bool DANERecord::verifyDomainIssuedCertificate(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const
{
	// Fast-forward to the final (front) certificate in the chain
	if (cert != chain.front()) {
		return true;
	}
	
	// It's the domain certificate; verify it against the record
	return this->verify(cert);
}
