#include <catch.hpp>
#include <libdane/DANERecord.h>

using namespace libdane;

SCENARIO ("Formatting of binary data works")
{
	GIVEN ("Some data")
	{
		DANERecord rec(DANERecord::CAConstraints, DANERecord::FullCertificate, DANERecord::ExactMatch, { 0x13, 0x37 });
		THEN ("The readable output should be correct")
		{
			REQUIRE (rec.dataString() == "1337");
		}
	}
}
