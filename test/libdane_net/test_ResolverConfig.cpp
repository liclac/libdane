/**
 * test_ResolverConfig.cpp
 * test_libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <catch.hpp>
#include <libdane/net/Resolver.h>
#include <libdane/Util.h>

using namespace libdane;
using namespace libdane::net;

SCENARIO("Constructors are working")
{
	WHEN("A config object is default-constructed")
	{
		ResolverConfig conf;
		
		THEN("It should default to Google's DNS servers")
		{
			auto addrs = conf.nameServers();
			REQUIRE(addrs.size() == 4);
			
			CHECK(addrs[0].to_string() == "2001:4860:4860::8888");
			CHECK(addrs[1].to_string() == "2001:4860:4860::8844");
			CHECK(addrs[2].to_string() == "8.8.8.8");
			CHECK(addrs[3].to_string() == "8.8.4.4");
		}
	}
}

SCENARIO("Parsing resolv.conf files works")
{
	GIVEN("An empty string")
	{
		std::string str;
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should be empty")
		{
			REQUIRE(conf.nameServers().size() == 0);
		}
	}
	
	GIVEN("Gibberish")
	{
		std::string str("asdsfgdhfjhisfuiydutcfigudbh\ndsafyghkjnnfd");
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should be empty")
		{
			REQUIRE(conf.nameServers().size() == 0);
		}
	}
	
	GIVEN("Two IPv4 nameservers")
	{
		std::string str(
			"nameserver 192.168.0.100\n"
			"nameserver 192.168.0.101\n"
		);
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should contain the given entries")
		{
			REQUIRE(conf.nameServers().size() == 2);
			CHECK(conf.nameServers()[0].to_string() == "192.168.0.100");
			CHECK(conf.nameServers()[1].to_string() == "192.168.0.101");
		}
	}
	
	GIVEN("Two IPv6 nameservers")
	{
		std::string str(
			"nameserver 2001:db8::ff00:42:8328\n"
			"nameserver 2001:db8::ff00:42:8329\n"
		);
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should contain the given entries")
		{
			REQUIRE(conf.nameServers().size() == 2);
			CHECK(conf.nameServers()[0].to_string() == "2001:db8::ff00:42:8328");
			CHECK(conf.nameServers()[1].to_string() == "2001:db8::ff00:42:8329");
		}
	}
	
	GIVEN("No trailing newline")
	{
		std::string str(
			"nameserver 192.168.0.100\n"
			"nameserver 192.168.0.101"
		);
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should contain the given entries")
		{
			REQUIRE(conf.nameServers().size() == 2);
			CHECK(conf.nameServers()[0].to_string() == "192.168.0.100");
			CHECK(conf.nameServers()[1].to_string() == "192.168.0.101");
		}
	}
	
	GIVEN("A file with comments")
	{
		std::string str(
			"# Header comment\n"
			"nameserver 192.168.0.100\n"
			"nameserver 192.168.0.101\n"
			"# Footer comment\n"
		);
		ResolverConfig conf;
		REQUIRE(conf.parseResolvConf(str));
		
		THEN("The nameserver list should contain the given entries")
		{
			REQUIRE(conf.nameServers().size() == 2);
			CHECK(conf.nameServers()[0].to_string() == "192.168.0.100");
			CHECK(conf.nameServers()[1].to_string() == "192.168.0.101");
		}
	}
}
