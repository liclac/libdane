/**
 * common.h
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_COMMON_H
#define LIBDANE_COMMON_H

namespace libdane
{
	/**
	 * Certificate Usage constants.
	 * 
	 * @see https://tools.ietf.org/html/rfc6698#section-2.1.1
	 */
	enum Usage {
		/**
		 * The root certificate is verified against the record.
		 * 
		 * It must also be trusted by the system's trust store to pass.
		 */
		CAConstraints = 0,
		
		/**
		 * The topmost certificate is verified against the record.
		 * 
		 * It must also be trusted by the system's trust store to pass.
		 */
		ServiceCertificateConstraint = 1,
		
		/**
		 * Like CAConstraints, but the certificate is implicitly trusted.
		 */
		TrustAnchorAssertion = 2,
		
		/**
		 * Like ServerCertificateConstraint, but the certificate is implicitly trusted.
		 */
		DomainIssuedCertificate = 3,
	};
	
	/**
	 * Selector constants.
	 * 
	 * @see https://tools.ietf.org/html/rfc6698#section-2.1.2
	 */
	enum Selector {
		FullCertificate = 0,		///< The DER-encoded certificate
		SubjectPublicKeyInfo = 1,	///< The DER-encoded public key
	};
	
	/**
	 * Matching Type constants.
	 * 
	 * @see https://tools.ietf.org/html/rfc6698#section-2.1.3
	 */
	enum MatchingType {
		ExactMatch = 0,				///< Exact contents match
		SHA256Hash = 1,				///< SHA-256 checksums match
		SHA512Hash = 2,				///< SHA-512 checksums match
	};
}

#endif
