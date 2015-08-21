#include <catch.hpp>
#include <libdane/DANERecord.h>
#include <libdane/Certificate.h>
#include "../resources.h"

using namespace libdane;

constexpr DANERecord::VerifyResult Fail = DANERecord::Fail;
constexpr DANERecord::VerifyResult Pass = DANERecord::Pass;
constexpr DANERecord::VerifyResult PassAll = DANERecord::PassAll;

SCENARIO("Lone certificates can be verified")
{
	Certificate cert = Certificate::parsePEM(resources::googlePEM).front();
	
	WHEN("Different selectors are used")
	{
		GIVEN("Full Certificate")
		{
			DANERecord rec(DomainIssuedCertificate, FullCertificate, ExactMatch, cert);
			CHECK(rec.verify(cert));
		}
		
		GIVEN("Public Key")
		{
			DANERecord rec(DomainIssuedCertificate, SubjectPublicKeyInfo, ExactMatch, cert);
			CHECK(rec.verify(cert));
		}
	}
	
	WHEN("Different matching types are used")
	{
		GIVEN("SHA256Hash")
		{
			DANERecord rec(DomainIssuedCertificate, FullCertificate, SHA256Hash, cert);
			CHECK(rec.verify(cert));
		}
		
		GIVEN("SHA512Hash")
		{
			DANERecord rec(DomainIssuedCertificate, FullCertificate, SHA512Hash, cert);
			CHECK(rec.verify(cert));
		}
	}
}

SCENARIO("Certificates can be verified, callback-style")
{
	std::deque<Certificate> chain = Certificate::parsePEM(resources::googlePEM);
	REQUIRE(chain.size() == 3);
	
	std::deque<Certificate> other = Certificate::parsePEM(resources::microsoftPEM);
	REQUIRE(other.size() == 2);
	
	GIVEN("A DomainIssuedCertificate record")
	{
		DANERecord rec(DomainIssuedCertificate, FullCertificate, SHA256Hash, chain[0]);
		
		THEN("A correct chain should pass verification")
		{
			CHECK(rec.verify(true, chain[2], chain) == Pass);
			CHECK(rec.verify(true, chain[1], chain) == Pass);
			CHECK(rec.verify(true, chain[0], chain) == Pass);
			
			THEN("Preverification is ignored")
			{
				CHECK(rec.verify(false, chain[0], chain) == Pass);
			}
		}
		
		THEN("An invalid chain should fail at the last step")
		{
			CHECK(rec.verify(true, other[1], other) == Pass);
			CHECK(rec.verify(true, other[0], other) == Fail);
		}
	}
	
	GIVEN("A TrustAnchorAssertion record")
	{
		DANERecord rec(TrustAnchorAssertion, FullCertificate, SHA256Hash, chain[2]);
		
		THEN("A correctly issued root certificate should pass verification")
		{
			CHECK(rec.verify(true, chain[2], chain) == Pass);
			CHECK(rec.verify(true, chain[1], chain) == Pass);
			CHECK(rec.verify(true, chain[0], chain) == Pass);
			
			THEN("Preverification is ignored")
			{
				CHECK(rec.verify(false, chain[2], chain) == Pass);
			}
		}
		
		THEN("A chain with a different root should fail verification")
		{
			CHECK(rec.verify(true, other[1], other) == Fail);
			
			THEN("A valid continued chain should pass (should never happen)")
			{
				CHECK(rec.verify(true, other[0], other) == Pass);
			}
		}
	}
}
