#ifndef LIBDANE_DANERECORD_H
#define LIBDANE_DANERECORD_H

#include <string>
#include <vector>
#include <asio/ssl.hpp>

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
		 * Verifies the presented context against this record.
		 */
		bool verify(bool preverified, asio::ssl::verify_context &vc) const;
		
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
		
	protected:
		/// Implementation for verify() with DANERecord::CAConstraints
		bool verifyCAConstraints(bool preverified, asio::ssl::verify_context &vc) const;
		
		/// Implementation for verify() with DANERecord::ServiceCertificateConstraint
		bool verifyServiceCertificateConstraint(bool preverified, asio::ssl::verify_context &vc) const;
		
		/// Implementation for verify() with DANERecord::TrustAnchorAssertion
		bool verifyTrustAnchorAssertion(bool preverified, asio::ssl::verify_context &vc) const;
		
		/// Implementation for verify() with DANERecord::DomainIssuedCertificate
		bool verifyDomainIssuedCertificate(bool preverified, asio::ssl::verify_context &vc) const;
		
	public:
		/**
		 * Structure for X509_STORE_CTX extra data.
		 */
		struct store_ctx_data_t {
			bool pass_all_checks = false;	///< Pass all following checks
		};
		
		/// Attachment index for a store_ctx_data_t
		static int store_ctx_data_idx;
		
		/**
		 * Returns the attached data for the given context.
		 */
		store_ctx_data_t *dataForContext(asio::ssl::verify_context &vc) const;
		
		/**
		 * Called when a X509_STORE_CTX is created.
		 * 
		 * This callback is responsible for creating a new store_ctx_data_t and
		 * attaching it to the newly created context as extra data.
		 * 
		 * @param  parent Pointer to the new X509_STORE_CTX structure
		 * @param  ptr    Garbage data, why is this even here
		 * @param  ad     Pointer to a CRYPTO_EX_DATA structure
		 * @param  idx    Index to attach the data to
		 * @param  argl   User-provided data
		 * @param  argp   User-provided data
		 * @return        An ignored value, thanks OpenSSL
		 */
		static int store_ctx_data_t_new_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
		
		/**
		 * Called when a X509_STORE_CTX is about to be deleted.
		 * 
		 * This callback is responsible for deleting a store_ctx_data_t stored
		 * as extra data in the context.
		 * 
		 * @param parent Pointer to the X509_STORE_CTX structure
		 * @param ptr    Pointer to the current store_ctx_data_t
		 * @param ad     Pointer to a CRYPTO_EX_DATA structure
		 * @param idx    Index the data is attached to
		 * @param argl   User-provided data
		 * @param argp   User-provided data
		 */
		static void store_ctx_data_t_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
	};
}

#endif
