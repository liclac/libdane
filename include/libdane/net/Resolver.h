#ifndef LIBDANE_NET_RESOLVER_H
#define LIBDANE_NET_RESOLVER_H

#include "_internal/include_ldns.h"
#include "common.h"
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <deque>
#include <memory>

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
			 * Callback type for lookup functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::deque<DANERecord>)> LookupCallback;
			
			
			
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
			void lookupDANE(const std::string &domain, unsigned short port, libdane::net::Protocol proto, LookupCallback callback);
			
			/**
			 * Look up the DANE record for the given resource.
			 * 
			 * @param record_name A record name, in the format _port._proto.domain
			 * @param callback    Callback, receiving a DANERecord list
			 */
			void lookupDANE(const std::string &record_name, LookupCallback callback);
			
			/**
			 * Decodes a packet into a list of records.
			 */
			std::deque<DANERecord> decode(std::shared_ptr<ldns_pkt> pkt);
			
		protected:
			/**
			 * ASIO Service to run asynchronous operations on.
			 */
			asio::io_service &service;
			
			/**
			 * A list of possible endpoints to connect to.
			 */
			std::vector<asio::ip::tcp::endpoint> endpoints;
		};
	}
}

#endif
