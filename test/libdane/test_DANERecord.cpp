#include <catch.hpp>
#include <libdane/DANERecord.h>
#include <libdane/Certificate.h>
#include "../resources.h"

using namespace libdane;

SCENARIO("Verifying records works")
{
	GIVEN("The certificate chain for google.com")
	{
		std::deque<Certificate> chain = Certificate::parsePEM(resources::googlePEM);
		const Certificate &cert = chain.back();
		
		GIVEN("A passing DomainIssuedCertificate record")
		{
			DANERecord rec(DomainIssuedCertificate, FullCertificate, SHA256Hash, chain.front().select(FullCertificate).match(SHA256Hash));
			
			THEN("Verification should succeed")
			{
				CHECK(rec.verify(true, cert, chain) == DANERecord::PassAll);
			}
			
			THEN("Preverification should be ignored")
			{
				CHECK(rec.verify(false, cert, chain) == DANERecord::PassAll);
			}
		}
		
		GIVEN("A failing DomainIssuedCertificate record")
		{
			// Note the mismatched hash algorithm
			DANERecord rec(DomainIssuedCertificate, FullCertificate, SHA256Hash, chain.front().select(FullCertificate).match(SHA512Hash));
			
			THEN("Verification should fail")
			{
				CHECK(rec.verify(false, cert, chain) == DANERecord::Fail);
			}
		}
	}
}
