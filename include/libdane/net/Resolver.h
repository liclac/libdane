#ifndef LIBDANE_NET_RESOLVER_H
#define LIBDANE_NET_RESOLVER_H

#include "common.h"
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
			 * Constructs a DANE Resolver running on the given ASIO Service.
			 */
			Resolver(asio::io_service &service);
			
			/**
			 * Destructor.
			 */
			virtual ~Resolver();
			
			
			
			/**
			 * Look up the DANE record for the given domain.
			 * 
			 * This is equivalent to calling:
			 * 
			 *     lookupDANE(resource_record_name(domain, port, proto), callback);
			 * 
			 * @see libdane::net::resource_record_name()
			 * 
			 * @param domain   Domain name to look up
			 * @param port     Port to look up a service for
			 * @param proto    Protocol to look up a service for
			 * @param callback Callback, receiving a DANERecord list
			 */
			void lookupDANE(const std::string &domain, unsigned short port, libdane::net::Protocol proto, std::function<void(std::deque<DANERecord>)> callback);
			
			/**
			 * Look up the DANE record for the given resource.
			 * 
			 * @param record_name A record name, in the format _port._proto.domain
			 * @param callback    Callback, receiving a DANERecord list
			 */
			void lookupDANE(const std::string &record_name, std::function<void(std::deque<DANERecord>)> callback);
			
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
