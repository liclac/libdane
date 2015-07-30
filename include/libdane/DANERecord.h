#ifndef DANERECORD_H
#define DANERECORD_H

#include <string>
#include <vector>

namespace libdane
{
	/**
	 * Represents a single DANE DNS record.
	 */
	class DANERecord
	{
	public:
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
			SHA256 = 1,					///< SHA-256 checksums match
			SHA512 = 2,					///< SHA-512 checksums match
		};
		
		
		
		/**
		 * Constructs a blank DANE Record.
		 */
		DANERecord();
		
		/**
		 * Constructs a DANE record with the given values.
		 */
		DANERecord(Usage usage, Selector selector, MatchingType mtype, std::vector<unsigned char> data);
		
		/**
		 * Destructor.
		 */
		virtual ~DANERecord();
		
		/**
		 * Returns the record's data as a hexadecimal string.
		 */
		std::string dataString() const;
		
		/**
		 * Returns a human-readable representation of the record.
		 * 
		 * This is not standardized, and meant only for debugging purposes.
		 */
		std::string toString() const;
		
		
		
		Usage usage;						///< Certificate Usage
		Selector selector;					///< Selector
		MatchingType mtype;					///< Matching Type
		std::vector<unsigned char> data;	///< Binary data
	};
}

#endif
