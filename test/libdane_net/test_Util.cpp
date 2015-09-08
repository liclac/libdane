/**
 * test_Util.cpp
 * test_libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <catch.hpp>
#include <libdane/net/Util.h>

using namespace libdane;
using namespace libdane::net;

SCENARIO("TLSA RRs can be created")
{
	GIVEN("A set of parameters")
	{
		std::shared_ptr<ldns_rr> rr = make_tlsa(CAConstraints, FullCertificate, SHA256Hash, Blob({ 0xFE, 0xEF }));
		
		THEN("The rdf count should be correct")
		{
			REQUIRE(ldns_rr_rd_count(&*rr) == 4);
		}
		
		THEN("The usage should be correct")
		{
			ldns_rdf *usage_rd = ldns_rr_rdf(&*rr, 0);
			REQUIRE(ldns_rdf_get_type(usage_rd) == LDNS_RDF_TYPE_INT8);
			REQUIRE(ldns_rdf_size(usage_rd) == 1);
			REQUIRE(ldns_rdf_data(usage_rd)[0] == CAConstraints);
		}
		
		THEN("The selector should be correct")
		{
			ldns_rdf *selector_rd = ldns_rr_rdf(&*rr, 1);
			REQUIRE(ldns_rdf_get_type(selector_rd) == LDNS_RDF_TYPE_INT8);
			REQUIRE(ldns_rdf_size(selector_rd) == 1);
			REQUIRE(ldns_rdf_data(selector_rd)[0] == FullCertificate);
		}
		
		THEN("The matching should be correct")
		{
			ldns_rdf *matching_rd = ldns_rr_rdf(&*rr, 2);
			REQUIRE(ldns_rdf_get_type(matching_rd) == LDNS_RDF_TYPE_INT8);
			REQUIRE(ldns_rdf_size(matching_rd) == 1);
			REQUIRE(ldns_rdf_data(matching_rd)[0] == SHA256Hash);
		}
		
		THEN("The data should be correct")
		{
			ldns_rdf *data_rd = ldns_rr_rdf(&*rr, 3);
			REQUIRE(ldns_rdf_get_type(data_rd) == LDNS_RDF_TYPE_HEX);
			REQUIRE(ldns_rdf_size(data_rd) == 2);
			REQUIRE(ldns_rdf_data(data_rd)[0] == 0xFE);
			REQUIRE(ldns_rdf_data(data_rd)[1] == 0xEF);
		}
	}
}

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
