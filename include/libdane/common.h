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
		 * Only the given CA certificate or public key may be used to issue
		 * certificates for this server, the CA is not implicitly trusted
		 * if it's not in the system's trust store.
		 */
		CAConstraints = 0,
		
		/**
		 * Only the specified certificate or public key may be used, it
		 * must be valid and accepted by the system's trust store.
		 */
		ServiceCertificateConstraint = 1,
		
		/**
		 * The given certificate or public key must be a trust anchor, and
		 * is implicitly trusted regardless of the system's trust store.
		 */
		TrustAnchorAssertion = 2,
		
		/**
		 * Like ServerCertificateConstraint, but the system's trust store
		 * doesn't have to accept it.
		 */
		DomainIssuedCertificate = 3,
	};
	
	/**
	 * Selector constants.
	 * 
	 * @see https://tools.ietf.org/html/rfc6698#section-2.1.2
	 */
	enum Selector {
		FullCertificate = 0,		///< The binary certificate.
		SubjectPublicKeyInfo = 1,	///< The DER-encoded public key.
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
