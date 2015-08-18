#include <catch.hpp>
#include <libdane/Certificate.h>
#include "../resources.h"

using namespace libdane;

SCENARIO ("Accessors work")
{
	GIVEN ("The certificate for google.com")
	{
		Certificate cert(resources::googlePEM);
		
		THEN ("Issuer and Subject should be correct")
		{
			CHECK(cert.issuerDN() == "/C=US/O=Google Inc/CN=Google Internet Authority G2");
			CHECK(cert.subjectDN() == "/C=US/ST=California/L=Mountain View/O=Google Inc/CN=*.google.com");
		}
	}
}
