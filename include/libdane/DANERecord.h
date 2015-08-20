#ifndef LIBDANE_DANERECORD_H
#define LIBDANE_DANERECORD_H

#include <string>
#include <vector>
#include <asio/ssl.hpp>
#include "VerifyContext.h"
#include "Blob.h"
#include "common.h"

namespace libdane
{
	/**
	 * Represents a single DANE DNS record.
	 */
	class DANERecord
	{
	public:
		/**
		 * Result of a verification operation.
		 */
		enum VerifyResult {
			/**
			 * Verification failed, abort.
			 * No further verification should be done.
			 */
			Fail = 0,
			
			/**
			 * Verification passed, proceed.
			 * Verify the next certificate in the chain with another call.
			 */
			Pass = 1,
			
			/**
			 * Verification passed, ignore remainder.
			 * Sufficient verification has already been done, and examining
			 * further certificates would be a waste of time, so don't do it.
			 */
			PassAll = 2,
		};
		
		/**
		 * Constructs a blank DANE Record.
		 */
		DANERecord();
		
		/**
		 * Constructs a DANE record with the given values.
		 */
		DANERecord(Usage usage, Selector selector, MatchingType matching, Blob data);
		
		/**
		 * Destructor.
		 */
		virtual ~DANERecord();
		
		/**
		 * Verifies the presented certificate and chain against this record.
		 * 
		 * @param  preverified Is the certificate trusted by the system?
		 * @param  cert        Current certificate to process
		 * @param  chain       Full certificate chain
		 * @return             A verification result
		 */
		VerifyResult verify(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/**
		 * Verifies the presented context against this record.
		 * 
		 * This is a convenience function for easily using records to verify
		 * certificates in an OpenSSL callback.
		 * 
		 * @param  preverified Is the certificate trusted by the system?
		 * @param  vc          The active verification context
		 * @return             Whether the verification passed or not
		 */
		bool verify(bool preverified, asio::ssl::verify_context &vc) const;
		
		/**
		 * Verifies a given certificate against the record's data.
		 * 
		 * @param  cert A certificate to verify
		 * @return      Whether the verification passed or not
		 */
		bool verify(const Certificate &cert) const;
		
		/**
		 * Returns a human-readable representation of the record.
		 * 
		 * This is not standardized, and meant only for debugging purposes.
		 */
		std::string toString() const;
		
		
		
		Usage usage() const;				///< Certificate Usage
		void setUsage(Usage v);				///< Sets usage()
		
		Selector selector() const;			///< Selector
		void setSelector(Selector v);		///< Sets selector()
		
		MatchingType matching() const;		///< Matching Type
		void setMatching(MatchingType v);	///< Sets matching()
		
		Blob data() const;					///< Binary data
		void setData(Blob v);				///< Sets data()
		
	protected:
		/// Implementation for verify() with DANERecord::CAConstraints
		VerifyResult verifyCAConstraints(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::ServiceCertificateConstraint
		VerifyResult verifyServiceCertificateConstraint(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::TrustAnchorAssertion
		VerifyResult verifyTrustAnchorAssertion(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::DomainIssuedCertificate
		VerifyResult verifyDomainIssuedCertificate(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
	private:
		Usage m_usage;
		Selector m_selector;
		MatchingType m_matching;
		Blob m_data;
	};
}

#endif
