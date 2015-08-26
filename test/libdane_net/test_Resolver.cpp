#include <catch.hpp>
#include <libdane/net/Resolver.h>

using namespace libdane;
using namespace libdane::net;

SCENARIO("Query construction works")
{
	asio::io_service service;
	Resolver res(service);
	
	GIVEN("A valid set of query parameters")
	{
		auto pkt = res.makeQuery("google.com", LDNS_RR_TYPE_A);
		
		THEN("Packet metadata should be correct")
		{
			REQUIRE(ldns_pkt_get_opcode(&*pkt) == LDNS_PACKET_QUERY);
			
			CHECK(ldns_pkt_qr(&*pkt) == 0); 	// Set for all queries
			CHECK(ldns_pkt_aa(&*pkt) == 0);
			CHECK(ldns_pkt_tc(&*pkt) == 0);
			CHECK(ldns_pkt_rd(&*pkt) == 1);		// This is a default
			CHECK(ldns_pkt_cd(&*pkt) == 0);
			CHECK(ldns_pkt_ra(&*pkt) == 0);
			CHECK(ldns_pkt_ad(&*pkt) == 0);
			
			CHECK(ldns_pkt_qdcount(&*pkt) == 1);
			CHECK(ldns_pkt_ancount(&*pkt) == 0);
			CHECK(ldns_pkt_nscount(&*pkt) == 0);
			CHECK(ldns_pkt_arcount(&*pkt) == 0);
		}
		
		THEN("It should contain (only) the expected query item")
		{
			ldns_rr_list *q = ldns_pkt_question(&*pkt);
			REQUIRE(ldns_rr_list_rr_count(q));
			
			ldns_rr *rr = ldns_rr_list_rr(q, 0);
			CHECK(ldns_rr_is_question(rr));
			CHECK(ldns_rr_get_type(rr) == LDNS_RR_TYPE_A);
			CHECK(ldns_rr_get_class(rr) == LDNS_RR_CLASS_IN);	// This is a default
		}
	}
}
