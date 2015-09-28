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

SCENARIO("to_hex() works")
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

SCENARIO("All to_hex() overloads work")
{
	std::vector<unsigned char> data({ 0x13, 0x37 });
	
	WHEN("Using to_hex(IterT, IterT)")
	{
		REQUIRE(to_hex(data.begin(), data.end()) == "1337");
	}
	
	WHEN("Using to_hex(const ContainerT&)")
	{
		REQUIRE(to_hex(data) == "1337");
	}
}

SCENARIO("from_hex() works")
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

SCENARIO("All from_hex() overloads work")
{
	WHEN("Using from_hex(OutputIt, StringIt, StringIt)")
	{
		GIVEN("A hex string")
		{
			std::vector<unsigned char> data;
			std::string str("1337");
			auto it = from_hex(back_inserter(data), str.begin(), str.end());
			
			THEN("The extracted data should be correct")
			{
				REQUIRE(data.size() == 2);
				CHECK(data[0] == 0x13);
				CHECK(data[1] == 0x37);
			}
			
			THEN("It should return a past-the-end insert iterator")
			{
				*it = 0x01;
				REQUIRE(data.size() == 3);
				CHECK(data[2] == 0x01);
			}
		}
		
		GIVEN("An empty string")
		{
			std::vector<unsigned char> data;
			std::string str;
			auto it = from_hex(back_inserter(data), str.begin(), str.end());
			
			THEN("It should extract no data")
			{
				REQUIRE(data.size() == 0);
			}
			
			THEN("It should return the untouched iterator")
			{
				*it = 0x01;
				REQUIRE(data.size() == 1);
				CHECK(data[0] == 0x01);
			}
		}
		
		GIVEN("A hex string and different cast types")
		{
			std::string str("ff");
			
			WHEN("Casting to int through char")
			{
				std::vector<int> data;
				from_hex<char>(back_inserter(data), str.begin(), str.end());
				REQUIRE(data.size() == 1);
				CHECK(data[0] == -1);
			}
			
			WHEN("Casting to unsigned int through unsigned char")
			{
				std::vector<unsigned int> data;
				from_hex<unsigned char>(back_inserter(data), str.begin(), str.end());
				REQUIRE(data.size() == 1);
				CHECK(data[0] == 255);
			}
		}
	}
	
	WHEN("Using from_hex(StringIt, StringIt)")
	{
		GIVEN("A hex string")
		{
			std::string str("1337");
			auto data = from_hex(str.begin(), str.end());
			
			THEN("The extracted data should be correct")
			{
				REQUIRE(data.size() == 2);
				CHECK(data[0] == 0x13);
				CHECK(data[1] == 0x37);
			}
		}
		
		GIVEN("A hex string and a container type")
		{
			std::string str("1337");
			std::deque<unsigned char> data = from_hex<unsigned char, std::deque<unsigned char>>(str.begin(), str.end());
			
			THEN("The extracted data should be correct")
			{
				REQUIRE(data.size() == 2);
				CHECK(data[0] == 0x13);
				CHECK(data[1] == 0x37);
			}
		}
		
		GIVEN("An empty string")
		{
			std::string str;
			auto data = from_hex(str.begin(), str.end());
			
			THEN("It should return an empty vector")
			{
				REQUIRE(data.size() == 0);
			}
		}
	}
	
	WHEN("Using from_hex(const std::basic_string<CharT>&)")
	{
		GIVEN("A hex string")
		{
			std::string str("1337");
			auto data = from_hex(str);
			
			THEN("The extracted data should be correct")
			{
				REQUIRE(data.size() == 2);
				CHECK(data[0] == 0x13);
				CHECK(data[1] == 0x37);
			}
		}
		
		GIVEN("An empty string")
		{
			std::string str;
			auto data = from_hex(str);
			
			THEN("It should return an empty vector")
			{
				REQUIRE(data.size() == 0);
			}
		}
	}
	
	WHEN("Using from_hex(const CharT*)")
	{
		GIVEN("A hex string")
		{
			const char *str = "1337";
			auto data = from_hex(str);
			
			THEN("The extracted data should be correct")
			{
				REQUIRE(data.size() == 2);
				CHECK(data[0] == 0x13);
				CHECK(data[1] == 0x37);
			}
		}
		
		GIVEN("An empty string")
		{
			const char *str = "";
			auto data = from_hex(str);
			
			THEN("It should return an empty vector")
			{
				REQUIRE(data.size() == 0);
			}
		}
		
		GIVEN("A NULL")
		{
			const char *str = NULL;
			auto data = from_hex(str);
			
			THEN("It should return an empty vector")
			{
				REQUIRE(data.size() == 0);
			}
		}
	}
}

SCENARIO("hash() works")
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

SCENARIO("All hash() overloads work")
{
	const EVP_MD *md = EVP_sha256();
	
	WHEN("Using hash(const EVP_MD*, OutputIt, std::vector<T>::const_iterator, std::vector<T>::const_iterator)")
	{
		GIVEN("No MD")
		{
			std::vector<unsigned char> data { 0x13, 0x37 };
			std::vector<unsigned char> res;
			auto it = hash(nullptr, back_inserter(res), data.begin(), data.end());
			
			THEN("It should return the data untouched")
			{
				REQUIRE(res.size() == 2);
				CHECK(res[0] == 0x13);
				CHECK(res[1] == 0x37);
			}
			
			THEN("It should return the insert iterator")
			{
				*it = 0x01;
				REQUIRE(res.size() == 3);
				CHECK(res[2] == 0x01);
			}
		}
		
		GIVEN("Some data")
		{
			std::vector<unsigned char> data { 0x13, 0x37 };
			std::vector<unsigned char> res;
			auto it = hash(md, back_inserter(res), data.begin(), data.end());
			
			THEN("The calculated checksum should be correct")
			{
				CHECK(res.size() == 32);
				CHECK(to_hex(res) == "158760c856e5ea1ba97e2e2a456736c4bf30d964559afa6d748cf05694a636ff");
			}
			
			THEN("It should return a past-the-end insert iterator")
			{
				*it = 0x01;
				REQUIRE(res.size() == 33);
				CHECK(res[32] == 0x01);
			}
		}
		
		GIVEN("No data")
		{
			std::vector<unsigned char> data;
			std::vector<unsigned char> res;
			auto it = hash(md, back_inserter(res), data.begin(), data.end());
			
			THEN("The checksum should be correct")
			{
				CHECK(res.size() == 32);
				CHECK(to_hex(res) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
			}
		}
	}
	
	WHEN("Using hash(const EVP_MD*, OutputIt, IterT, IterT)")
	{
		GIVEN("A non-vector source")
		{
			std::deque<unsigned char> data { 0x13, 0x37 };
			std::deque<unsigned char> res;
			
			THEN("It should still compile")
			{
				auto it = hash(md, back_inserter(res), data.begin(), data.end());
			}
		}
	}
	
	WHEN("Using hash(const EVP_MD*, IterT, IterT)")
	{
		GIVEN("Some data")
		{
			std::deque<unsigned char> data { 0x13, 0x37 };
			
			THEN("It should work")
			{
				auto res = hash(md, data.begin(), data.end());
				REQUIRE(to_hex(res) == "158760c856e5ea1ba97e2e2a456736c4bf30d964559afa6d748cf05694a636ff");
			}
		}
	}
	
	WHEN("Using hash(const EVP_MD*, const std::vector<T>&)")
	{
		GIVEN("Some data")
		{
			std::vector<unsigned char> data { 0x13, 0x37 };
			
			THEN("It should work")
			{
				auto res = hash(md, data);
				REQUIRE(to_hex(res) == "158760c856e5ea1ba97e2e2a456736c4bf30d964559afa6d748cf05694a636ff");
			}
		}
		
		GIVEN("No data")
		{
			REQUIRE(to_hex(hash(md, {})) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		}
	}
	
	WHEN("Using hash(const EVP_MD*, const std::basic_string<CharT>&)")
	{
		THEN("Strings should be hashable")
		{
			std::string str("test");
			REQUIRE(to_hex(hash(md, str)) == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
		}
		
		THEN("Empty strings should be hashable")
		{
			std::string str;
			REQUIRE(to_hex(hash(md, str)) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		}
	}
	
	WHEN("Using hash(const EVP_MD*, const CharT*)")
	{
		THEN("Strings should be hashable")
		{
			const char *str = "test";
			REQUIRE(to_hex(hash(md, str)) == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
		}
		
		THEN("Empty strings should be hashable")
		{
			const char *str = "";
			REQUIRE(to_hex(hash(md, str)) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		}
		
		THEN("NULLs should be treated as empty strings")
		{
			const char *str = NULL;
			REQUIRE(to_hex(hash(md, str)) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		}
	}
}

SCENARIO("md_from_matching_type() works")
{
	GIVEN("Hash types")
	{
		THEN("It should return the correct function")
		{
			CHECK(md_from_matching_type(SHA256Hash) == EVP_sha256());
			CHECK(md_from_matching_type(SHA512Hash) == EVP_sha512());
		}
	}
	
	GIVEN("ExactMatch")
	{
		THEN("It should return null")
		{
			CHECK(md_from_matching_type(ExactMatch) == nullptr);
		}
	}
	
	GIVEN("An invalid type")
	{
		THEN("It should throw an exception")
		{
			CHECK_THROWS_AS(md_from_matching_type(static_cast<MatchingType>(255)), std::runtime_error);
		}
	}
}

SCENARIO("match() works")
{
	GIVEN("A string")
	{
		std::string str("lorem ipsum dolor sit amet");
		std::vector<unsigned char> vec(str.begin(), str.end());
		
		WHEN("Using ExactMatch")
		{
			auto data = match(ExactMatch, vec.begin(), vec.end());
			
			THEN("It should return the original data")
			{
				REQUIRE(data == vec);
			}
		}
		
		WHEN("Using hashes")
		{
			auto data256 = match(SHA256Hash, vec.begin(), vec.end());
			auto data512 = match(SHA512Hash, vec.begin(), vec.end());
			
			THEN("It should return the hashed data")
			{
				CHECK(data256 == hash(EVP_sha256(), vec.begin(), vec.end()));
				CHECK(data512 == hash(EVP_sha512(), vec.begin(), vec.end()));
			}
		}
		
		WHEN("Using an invalid type")
		{
			MatchingType type = static_cast<MatchingType>(255);
			
			THEN("It should throw a std::runtime_error")
			{
				CHECK_THROWS_AS(match(type, vec.begin(), vec.end()), std::runtime_error);
			}
		}
	}
	
	GIVEN("No data")
	{
		std::vector<char> vec;
		
		WHEN("Using ExactMatch")
		{
			auto data = match(ExactMatch, vec.begin(), vec.end());
			
			THEN("It should return nothing")
			{
				REQUIRE(data.size() == 0);
			}
		}
	}
}

SCENARIO("All match() overloads work")
{
	std::string str("lorem ipsum dolor sit amet");
	std::vector<unsigned char> data(str.begin(), str.end());
	
	WHEN("Using match(MatchingType, OutputIt, IterT, IterT)")
	{
		std::vector<unsigned char> res;
		auto it = match(ExactMatch, back_inserter(res), data.begin(), data.end());
		
		THEN("The data should be correct")
		{
			REQUIRE(res == data);
		}
		
		THEN("It should return a back inserter")
		{
			REQUIRE(res.size() == 26);
			*it++ = 0x01;
			REQUIRE(res.size() == 27);
			REQUIRE(res[26] == 0x01);
		}
	}
	
	WHEN("Using match(MatchingType type, IterT begin, IterT end)")
	{
		REQUIRE(match(ExactMatch, data.begin(), data.end()) == data);
	}
	
	WHEN("Using match(MatchingType, const std::basic_string<CharT>&)")
	{
		REQUIRE(match(ExactMatch, str.begin(), str.end()) == data);
	}
	
	WHEN("Using match(MatchingType, const CharT*)")
	{
		REQUIRE(match(ExactMatch, str.c_str()) == data);
	}
}
