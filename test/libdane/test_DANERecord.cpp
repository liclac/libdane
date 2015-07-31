#include <catch.hpp>
#include <libdane/DANERecord.h>

using namespace libdane;

SCENARIO ("Formatting of binary data works")
{
	GIVEN ("0x1337")
	{
		DANERecord rec(DANERecord::CAConstraints, DANERecord::FullCertificate, DANERecord::ExactMatch, { 0x13, 0x37 });
		THEN ("The dataString() should be 1337")
		{
			REQUIRE (rec.dataString() == "1337");
		}
	}
	
	GIVEN ("0xF00D")
	{
		DANERecord rec(DANERecord::CAConstraints, DANERecord::FullCertificate, DANERecord::ExactMatch, { 0xF0, 0x0D });
		THEN ("The dataString() should be f00d")
		{
			REQUIRE (rec.dataString() == "f00d");
		}
	}
}
