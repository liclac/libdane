#ifndef LIBDANE_NET_RESOLVER_H
#define LIBDANE_NET_RESOLVER_H

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <deque>

namespace libdane
{
	class DANERecord;
	
	namespace net
	{
		/**
		 * Manager class for looking up DANE records.
		 * 
		 * Under the hood, this class uses libldns and ASIO (C++11 standalone or
		 * Boost) for DNS queries, and produces libdane::DANERecord objects.
		 * 
		 * @see libldns - http://www.nlnetlabs.nl/projects/ldns/
		 * @see ASIO - http://think-async.com/
		 */
		class Resolver
		{
		public:
			/**
			 * Enum for protocols in lookups.
			 */
			enum Protocol {
				TCP,			///< Transmission Control Protocol
				UDP,			///< User Datagram Protocol
			};
			
			
			
			/**
			 * Constructs a DANE Resolver running on the given ASIO Service.
			 */
			Resolver(asio::io_service &service);
			
			/**
			 * Destructor.
			 */
			virtual ~Resolver();
			
			
			
			/**
			 * Creates an SSL context from a list of records.
			 * 
			 * @param  records Records to verify against
			 * @return         A preconfigured SSL context
			 */
			static asio::ssl::context sslContextFrom(std::deque<libdane::DANERecord> records);
			
			
			
			/**
			 * Look up the DANE record for the given domain.
			 * 
			 * @param domain   Domain name to look up
			 * @param port     Port to look up a service for
			 * @param proto    Protocol to look up a service for
			 * @param callback Callback, receiving a DANERecord list
			 */
			void lookupDANE(const std::string &domain, unsigned short port, Protocol proto, std::function<void(std::deque<libdane::DANERecord>)> callback);
			
		protected:
			/**
			 * ASIO Service to run asynchronous operations on.
			 */
			asio::io_service &service;
			
		private:
			struct Impl;
			Impl *p;
		};
	}
}


#endif
