#include <catch.hpp>
#include <libdane/net/Resolver.h>
#include <libdane/Blob.h>
#include <algorithm>

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

SCENARIO("Wire encoding works")
{
	asio::io_service service;
	Resolver res(service);
	
	GIVEN("A valid packet")
	{
		auto pkt = res.makeQuery("google.com", LDNS_RR_TYPE_A);
		
		WHEN("Encoded for UDP")
		{
			std::vector<unsigned char> udp = res.wire(pkt, false);
			
			THEN("The checksum should be correct")
			{
				REQUIRE(Blob(udp).sha256().hex() == "cc43d1338bffcc384219754b99618efa4cec609b32776d6d0b8c9fdf9aa69001");
			}
			
			THEN("Encoded for TCP")
			{
				std::vector<unsigned char> tcp = res.wire(pkt, true);
				
				THEN("It should just add a prefix")
				{
					REQUIRE(tcp.size() == udp.size() + 2);
					REQUIRE(std::equal(udp.begin(), udp.end(), tcp.begin() + 2));
				}
				
				THEN("The length prefix should be correct")
				{
					uint16_t len;
					std::copy(tcp.begin(), tcp.begin() + 2, reinterpret_cast<unsigned char*>(&len));
					len = ntohs(len);
					
					REQUIRE(len == udp.size());
				}
			}
		}
	}
}
