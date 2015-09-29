/**
 * mock/test_MockResolver.cpp
 * test_libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <catch.hpp>
#include <libdane/net/mock/MockResolver.h>

using namespace libdane::net::mock;

SCENARIO("Mock functions can be enqueued")
{
	asio::io_service service;
	MockResolver res(service);
	
	GIVEN("No mock functions")
	{
		WHEN("An invocation is attempted")
		{
			REQUIRE_THROWS_AS(res.invokeMock(nullptr), std::range_error);
		}
	}
	
	GIVEN("A mock function")
	{
		std::shared_ptr<ldns_pkt> pkt = nullptr;
		res.mock([&pkt](std::shared_ptr<ldns_pkt> q) -> std::shared_ptr<ldns_pkt> {
			pkt = q;
			return nullptr;
		});
		
		WHEN("It is manually invoked")
		{
			auto query = res.makeQuery("google.com", LDNS_RR_TYPE_A);
			auto answer = res.invokeMock(query);
			
			THEN("It should return the right thing")
			{
				CHECK(answer == nullptr);
			}
			
			THEN("The decoded packet should be correct")
			{
				ldns_rr_list *qs1 = ldns_pkt_question(&*query);
				ldns_rr_list *qs2 = ldns_pkt_question(&*pkt);
				REQUIRE(ldns_rr_list_rr_count(qs1) == ldns_rr_list_rr_count(qs2));
				
				ldns_rr *q1 = ldns_rr_list_rr(qs1, 0);
				ldns_rr *q2 = ldns_rr_list_rr(qs2, 0);
				REQUIRE(ldns_rr_compare(q1, q2) == 0);
			}
			
			THEN("It should be removed from the stack")
			{
				REQUIRE_THROWS_AS(res.invokeMock(nullptr), std::range_error);
			}
		}
	}
	
	GIVEN("Multiple mock functions")
	{
		bool invoked_1 = false;
		bool invoked_2 = false;
		res.mock([&invoked_1](std::shared_ptr<ldns_pkt> q) -> std::shared_ptr<ldns_pkt> {
			invoked_1 = true;
			return nullptr;
		});
		res.mock([&invoked_2](std::shared_ptr<ldns_pkt> q) -> std::shared_ptr<ldns_pkt> {
			invoked_2 = true;
			return nullptr;
		});
		
		WHEN("The first is invoked")
		{
			res.invokeMock(nullptr);
			REQUIRE(invoked_1);
			REQUIRE_FALSE(invoked_2);
			
			WHEN("The second is invoked")
			{
				res.invokeMock(nullptr);
				REQUIRE(invoked_1);
				REQUIRE(invoked_2);
				
				WHEN("A third invocation is attempted")
				{
					REQUIRE_THROWS_AS(res.invokeMock(nullptr), std::range_error);
				}
			}
		}
	}
}
