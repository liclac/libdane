#include <catch.hpp>
#include <libdane/net/Util.h>

using namespace libdane;
using namespace libdane::net;

SCENARIO("Records can be parsed from TLSA RRs")
{
	GIVEN("Different Usages")
	{
		GIVEN("CAConstraints")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == CAConstraints);
		}
		
		GIVEN("ServiceCertificateConstraint")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(ServiceCertificateConstraint, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == ServiceCertificateConstraint);
		}
		
		GIVEN("TrustAnchorAssertion")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(TrustAnchorAssertion, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == TrustAnchorAssertion);
		}
		
		GIVEN("DomainIssuedCertificate")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(DomainIssuedCertificate, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == DomainIssuedCertificate);
		}
	}
	
	GIVEN("Different Selectors")
	{
		GIVEN("FullCertificate")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.selector() == FullCertificate);
		}
		
		GIVEN("SubjectPublicKeyInfo")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, SubjectPublicKeyInfo, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.selector() == SubjectPublicKeyInfo);
		}
	}
	
	GIVEN("Different Matching Types")
	{
		GIVEN("ExactMatch")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, ExactMatch, Blob({ 0xFE })));
			REQUIRE(rec.matching() == ExactMatch);
		}
		
		GIVEN("SHA256Hash")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.matching() == SHA256Hash);
		}
		
		GIVEN("SHA512Hash")
		{
			DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, SHA512Hash, Blob({ 0xFE })));
			REQUIRE(rec.matching() == SHA512Hash);
		}
	}
	
	GIVEN("Some binary data")
	{
		DANERecord rec = record_from_tlsa(make_tlsa(CAConstraints, FullCertificate, SHA512Hash, Blob({ 0xFE })));
		REQUIRE(rec.data().hex() == "fe");
	}
}
