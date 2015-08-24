#include <catch.hpp>
#include <libdane/net/Util.h>

using namespace libdane;
using namespace libdane::net;

inline std::shared_ptr<ldns_rr> make_tlsa_rr(Usage u, Selector sel, MatchingType mt, Blob data)
{
	auto rr = std::shared_ptr<ldns_rr>(ldns_rr_new(), ldns_rr_free);
	ldns_rr_set_type(&*rr, LDNS_RR_TYPE_TLSA);
	
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(u), &u));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(sel), &sel));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(mt), &mt));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, data.data().size(), data.data().data()));
	
	return rr;
}

SCENARIO("Records can be parsed from TLSA RRs")
{
	GIVEN("Different Usages")
	{
		GIVEN("CAConstraints")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == CAConstraints);
		}
		
		GIVEN("ServiceCertificateConstraint")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(ServiceCertificateConstraint, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == ServiceCertificateConstraint);
		}
		
		GIVEN("TrustAnchorAssertion")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(TrustAnchorAssertion, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == TrustAnchorAssertion);
		}
		
		GIVEN("DomainIssuedCertificate")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(DomainIssuedCertificate, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.usage() == DomainIssuedCertificate);
		}
	}
	
	GIVEN("Different Selectors")
	{
		GIVEN("FullCertificate")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.selector() == FullCertificate);
		}
		
		GIVEN("SubjectPublicKeyInfo")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, SubjectPublicKeyInfo, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.selector() == SubjectPublicKeyInfo);
		}
	}
	
	GIVEN("Different Matching Types")
	{
		GIVEN("ExactMatch")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, ExactMatch, Blob({ 0xFE })));
			REQUIRE(rec.matching() == ExactMatch);
		}
		
		GIVEN("SHA256Hash")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE })));
			REQUIRE(rec.matching() == SHA256Hash);
		}
		
		GIVEN("SHA512Hash")
		{
			DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, SHA512Hash, Blob({ 0xFE })));
			REQUIRE(rec.matching() == SHA512Hash);
		}
	}
	
	GIVEN("Some binary data")
	{
		DANERecord rec = record_from_tlsa(make_tlsa_rr(CAConstraints, FullCertificate, SHA512Hash, Blob({ 0xFE })));
		REQUIRE(rec.data().hex() == "fe");
	}
}
