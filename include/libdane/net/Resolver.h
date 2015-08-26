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
			 * Callback type for query functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::shared_ptr<ldns_pkt> pkt)> QueryCallback;
			
			/**
			 * Callback type for DANE lookup functions.
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
			 * Sends an arbitrary DNS query.
			 * 
			 * @param domain   Domain to query
			 * @param rr_type  Record type to query for (eg. LDNS_RR_TYPE_A)
			 * @param rr_class Record class to query for (eg. LDNS_RR_CLASS_IN)
			 * @param flags    Query flags (eg. LDNS_RD)
			 * @param callback Callback for the results
			 */
			void query(const std::string &domain, ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags, QueryCallback callback);
			
			/**
			 * Sends an arbitrary DNS query with a default class and flag.
			 * 
			 * Since you basically only ever need to query IN-class records
			 * with the RD (Recursion Desired) flag, this is a shortcut to
			 * doing so.
			 * 
			 * @param domain   Domain to query
			 * @param rr_type  Record type to query for (eg. LDNS_RR_TYPE_A)
			 * @param callback Callback for the results
			 */
			void query(const std::string &domain, ldns_rr_type rr_type, QueryCallback callback);
			
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
			std::deque<DANERecord> decodeTLSA(std::shared_ptr<ldns_pkt> pkt);
			
			/**
			 * Constructs a query packet.
			 * 
			 * @param  domain Domain to query
			 * @param  rr_type  Record type to query for (eg. LDNS_RR_TYPE_A)
			 * @param  rr_class Record class to query for (eg. LDNS_RR_CLASS_IN)
			 * @param  flags    Query flags (eg. LDNS_RD)
			 * @return A DNS packet structure
			 */
			std::shared_ptr<ldns_pkt> makeQuery(const std::string &domain, ldns_rr_type rr_type, ldns_rr_class rr_class = LDNS_RR_CLASS_IN, uint16_t flags = LDNS_RD);
			
			/**
			 * Formats a DNS packet to wire format.
			 * 
			 * @param  pkt A DNS packet to format
			 * @param  tcp Format for TCP (with a length prefix)
			 * @return The packet in binary wire format
			 */
			std::vector<unsigned char> wire(std::shared_ptr<ldns_pkt> pkt, bool tcp = true);
			
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
