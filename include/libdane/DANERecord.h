/**
 * DANERecord.h
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_DANERECORD_H
#define LIBDANE_DANERECORD_H

#include <string>
#include <vector>
#include "_internal/openssl.h"
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
		 * Constructs a blank DANE Record.
		 */
		DANERecord();
		
		/**
		 * Constructs a DANE record with the given values.
		 */
		DANERecord(Usage usage, Selector selector, MatchingType matching, Blob data);
		
		/**
		 * Constructs a DANE record matching the given certificate.
		 * 
		 * This is mainly useful for testing. It will simply copy its data from
		 * the given certificate, using the selector and matching given.
		 */
		DANERecord(Usage usage, Selector selector, MatchingType matching, const Certificate &cert);
		
		/**
		 * Destructor.
		 */
		virtual ~DANERecord();
		
		/**
		 * Verifies the presented context against this record.
		 * 
		 * This is a convenience function for easily using records to verify
		 * certificates in an OpenSSL callback.
		 * 
		 * @param  preverified Is the certificate trusted by the system?
		 * @param  ctx         The active verification context
		 * @return             Whether the verification passed or not
		 */
		bool verify(bool preverified, const VerifyContext &ctx) const;
		
		/**
		 * Verifies the presented certificate and chain against this record.
		 * 
		 * @param  preverified Is the certificate trusted by the system?
		 * @param  cert        Current certificate to process
		 * @param  chain       Full certificate chain
		 * @return             A verification result
		 */
		bool verify(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
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
		bool verifyCAConstraints(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::ServiceCertificateConstraint
		bool verifyServiceCertificateConstraint(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::TrustAnchorAssertion
		bool verifyTrustAnchorAssertion(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
		/// Implementation for verify() with DANERecord::DomainIssuedCertificate
		bool verifyDomainIssuedCertificate(bool preverified, const Certificate &cert, const std::deque<Certificate> &chain) const;
		
	private:
		Usage m_usage;
		Selector m_selector;
		MatchingType m_matching;
		Blob m_data;
	};
}

#endif
