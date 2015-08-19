#include <catch.hpp>
#include <libdane/Blob.h>

using namespace libdane;

SCENARIO("Formatting of binary data works")
{
	GIVEN("0x1337")
	{
		Blob blob({ 0x13, 0x37 });
		THEN("The hex string should be 1337")
		{
			REQUIRE(blob.hex() == "1337");
		}
	}
	
	GIVEN("0xF00D")
	{
		Blob blob({ 0xF0, 0x0D });
		THEN("The hex string should be f00d")
		{
			REQUIRE(blob.hex() == "f00d");
		}
	}
}

SCENARIO("Decoding of hex strings works")
{
	GIVEN("0x1337")
	{
		Blob blob = Blob::fromHex("1337");
		
		THEN("The hex string should be 1337")
		{
			REQUIRE(blob.hex() == "1337");
		}
	}
	
	GIVEN("0xF00D")
	{
		Blob blob = Blob::fromHex("F00D");
		
		THEN("The hex string should be f00d")
		{
			REQUIRE(blob.hex() == "f00d");
		}
	}
	
	GIVEN("Garbage data")
	{
		Blob blob = Blob::fromHex("lorem ipsum dolor sit amet");
		
		THEN("The resulting blob should be full of zeroes, not crash")
		{
			REQUIRE(blob.hex() == "00000000000000000000000000");
		}
	}
}

SCENARIO("Initialization works")
{
	GIVEN("A string")
	{
		Blob blob("test");
		
		THEN("Only the characters should be stored")
		{
			REQUIRE(blob.data().size() == 4);
			REQUIRE(blob.hex() == "74657374");
		}
	}
}

SCENARIO("Hashing works")
{
	GIVEN("A string")
	{
		Blob blob("lorem ipsum dolor sit amet");
		
		THEN("Calculated checksums should be correct")
		{
			CHECK(blob.sha256().hex() == "2f8586076db2559d3e72a43c4ae8a1f5957abb23ca4a1f46e380dd640536eedb");
			CHECK(blob.sha512().hex() == "bafa0732d3b1a1d95431bd6fff46b35ac6b60c64ac8ea8b11cb05f7c1a706469aa04c181172bd5e303c3a1f19eef35469500fe9866e6b4c7bbc12759fee8e735");
		}
		
		THEN("A match() should always return the correct value")
		{
			CHECK(blob.match(ExactMatch) == blob);
			CHECK(blob.match(SHA256Hash) == blob.sha256());
			CHECK(blob.match(SHA512Hash) == blob.sha512());
			CHECK_THROWS_AS(blob.match(static_cast<MatchingType>(255)), std::runtime_error);
		}
	}
}
