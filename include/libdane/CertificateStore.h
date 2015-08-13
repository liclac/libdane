#ifndef LIBDANE_CERTIFICATESTORE_H
#define LIBDANE_CERTIFICATESTORE_H

#include "Certificate.h"
#include <asio/ssl.hpp>
#include <deque>

namespace libdane
{
	/**
	 * Wrapper around an OpenSSL certificate store.
	 * 
	 * Note that this class does not store any data itself - everything is
	 * stored as additional data on the context itself, with the exception of
	 * the certificate chain, which is retained and cached to prevent weirdness
	 * with the reference count of the certificates.
	 * 
	 * \todo Make Certificate retain native representations instead.
	 */
	class CertificateStore
	{
	public:
		/**
		 * Constructor.
		 * 
		 * @param ctx Underlying context
		 */
		CertificateStore(X509_STORE_CTX *ctx = nullptr);
		
		/**
		 * Convenience constructor.
		 * 
		 * This is the same as calling `CertificateStore(vc.native_handle())`.
		 */
		CertificateStore(asio::ssl::verify_context &vc);
		
		/**
		 * Destructor.
		 */
		virtual ~CertificateStore();
		
		/**
		 * Returns the underlying context for the store.
		 */
		X509_STORE_CTX *ctx() const;
		
		/**
		 * Returns the chain of certificates in the store.
		 */
		std::deque<Certificate> chain() const;
		
		/**
		 * Returns the currently operating certificate.
		 */
		Certificate currentCert() const;
		
		/**
		 * Should all future checks on this context be passed?
		 * 
		 * If this is true, then certificates further down the chain aren't
		 * even looked at, they're just passed unconditionally. Use with care.
		 */
		bool shouldPassAllChecks() const;
		
		/**
		 * Setter for shouldPassAllChecks().
		 */
		void setShouldPassAllChecks(bool v);
		
		/**
		 * A context is truthy if it has a valid underlying context.
		 */
		explicit operator bool() const { return m_ctx != nullptr; };
		
	private:
		X509_STORE_CTX *m_ctx = nullptr;
		
		STACK_OF(X509) *m_chain_stack = nullptr;
		std::deque<Certificate> m_chain;
		
	protected:
		/**
		 * Structure for extra data.
		 * 
		 * One of these are automatically inserted into new X509_STORE_CTX
		 * instances, and can be retrieved with CertificateStore::data();
		 */
		struct ctx_data_t {
			bool pass_all_checks = false;	///< Pass all following checks
		};
		
		/**
		 * Attachment index for a CertificateStore::ctx_data_t.
		 */
		static int ctx_data_idx;
		
		/**
		 * Returns the attached data for the underlying context.
		 */
		ctx_data_t *data() const;
		
		/**
		 * Called when a X509_STORE_CTX is created.
		 * 
		 * This callback is responsible for creating a new ctx_data_t and
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
		static int ctx_data_t_new_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
		
		/**
		 * Called when a X509_STORE_CTX is about to be deleted.
		 * 
		 * This callback is responsible for deleting a ctx_data_t stored
		 * as extra data in the context.
		 * 
		 * @param parent Pointer to the X509_STORE_CTX structure
		 * @param ptr    Pointer to the current ctx_data_t
		 * @param ad     Pointer to a CRYPTO_EX_DATA structure
		 * @param idx    Index the data is attached to
		 * @param argl   User-provided data
		 * @param argp   User-provided data
		 */
		static void ctx_data_t_free_func(void *parent, void *ptr, CRYPTO_EX_DATA *ad, int idx, long argl, void *argp);
	};
}

#endif
