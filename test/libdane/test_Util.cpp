/**
 * test_Util.cpp
 * test_libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <catch.hpp>
#include <libdane/Util.h>
#include <stdexcept>

using namespace libdane;

SCENARIO("Formatting of binary data works")
{
	GIVEN("0x1337")
	{
		std::vector<unsigned char> data({ 0x13, 0x37 });
		THEN("The hex string should be 1337")
		{
			REQUIRE(to_hex(data) == "1337");
		}
	}
	
	GIVEN("0xF00D")
	{
		std::vector<unsigned char> data({ 0xF0, 0x0D });
		THEN("The hex string should be f00d")
		{
			REQUIRE(to_hex(data) == "f00d");
		}
	}
}

SCENARIO("Decoding of hex strings works")
{
	GIVEN("0x1337")
	{
		std::vector<unsigned char> data = from_hex("1337");
		
		THEN("The hex string should be 1337")
		{
			REQUIRE(to_hex(data) == "1337");
		}
	}
	
	GIVEN("0xF00D")
	{
		std::vector<unsigned char> data = from_hex("F00D");
		
		THEN("The hex string should be f00d")
		{
			REQUIRE(to_hex(data) == "f00d");
		}
	}
	
	GIVEN("Garbage data")
	{
		std::vector<unsigned char> data = from_hex("lorem ipsum dolor sit amet");
		
		THEN("The resulting blob should be full of zeroes, not crash")
		{
			REQUIRE(to_hex(data) == "0000000000000d000000000a0e");
		}
	}
}

SCENARIO("Hashing works")
{
	GIVEN("A string")
	{
		std::string str("lorem ipsum dolor sit amet");
		
		THEN("Calculated checksums should be correct")
		{
			CHECK(to_hex(hash(EVP_sha256(), str)) == "2f8586076db2559d3e72a43c4ae8a1f5957abb23ca4a1f46e380dd640536eedb");
			CHECK(to_hex(hash(EVP_sha512(), str)) == "bafa0732d3b1a1d95431bd6fff46b35ac6b60c64ac8ea8b11cb05f7c1a706469aa04c181172bd5e303c3a1f19eef35469500fe9866e6b4c7bbc12759fee8e735");
		}
		
		THEN("A match() should return the correct value")
		{
			WHEN("Using an exact match")
			{
				std::vector<char> exact = match<char>(ExactMatch, str);
				CHECK(std::string(exact.begin(), exact.end()) == str);
			}
			
			WHEN("Using a hash")
			{
				CHECK(match(SHA256Hash, str) == hash(EVP_sha256(), str));
				CHECK(match(SHA512Hash, str) == hash(EVP_sha512(), str));
			}
		}
		
		THEN("Requesting an invalid type should throw an exception")
		{
			CHECK_THROWS_AS(match(static_cast<MatchingType>(255), str), std::runtime_error);
		}
	}
}
