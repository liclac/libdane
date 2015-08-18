#ifndef LIBDANE_DANERECORD_H
#define LIBDANE_DANERECORD_H

#include <string>
#include <vector>
#include <asio/ssl.hpp>
#include "CertificateStore.h"
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
		DANERecord(Usage usage, Selector selector, MatchingType matching, std::vector<unsigned char> data);
		
		/**
		 * Destructor.
		 */
		virtual ~DANERecord();
		
		/**
		 * Verifies the presented context against this record.
		 */
		bool verify(bool preverified, asio::ssl::verify_context &vc) const;
		
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
		bool verifyCAConstraints(bool preverified, CertificateStore &store) const;
		
		/// Implementation for verify() with DANERecord::ServiceCertificateConstraint
		bool verifyServiceCertificateConstraint(bool preverified, CertificateStore &store) const;
		
		/// Implementation for verify() with DANERecord::TrustAnchorAssertion
		bool verifyTrustAnchorAssertion(bool preverified, CertificateStore &store) const;
		
		/// Implementation for verify() with DANERecord::DomainIssuedCertificate
		bool verifyDomainIssuedCertificate(bool preverified, CertificateStore &store) const;
		
	private:
		Usage m_usage;
		Selector m_selector;
		MatchingType m_matching;
		Blob m_data;
	};
}

#endif
