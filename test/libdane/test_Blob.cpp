#include <catch.hpp>
#include <libdane/Blob.h>

using namespace libdane;

SCENARIO ("Formatting of binary data works")
{
	GIVEN ("0x1337")
	{
		Blob blob({ 0x13, 0x37 });
		THEN ("The dataString() should be 1337")
		{
			REQUIRE (blob.hex() == "1337");
		}
	}
	
	GIVEN ("0xF00D")
	{
		Blob blob({ 0xF0, 0x0D });
		THEN ("The dataString() should be f00d")
		{
			REQUIRE (blob.hex() == "f00d");
		}
	}
}

SCENARIO ("Initialization works")
{
	GIVEN ("A string")
	{
		Blob blob("test");
		
		THEN ("Only the characters should be stored")
		{
			REQUIRE (blob.data().size() == 4);
			REQUIRE (blob.hex() == "74657374");
		}
	}
}
