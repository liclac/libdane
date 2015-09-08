/**
 * Resolver.h
 * libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_NET_RESOLVER_H
#define LIBDANE_NET_RESOLVER_H

#include "_internal/ldns.h"
#include "../_internal/openssl.h"
#include "common.h"
#include <asio.hpp>
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
			 * Callback type for multi-query functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::vector<std::shared_ptr<ldns_pkt>> pkts)> MultiQueryCallback;
			
			/**
			 * Callback type for query functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::shared_ptr<ldns_pkt> pkt)> QueryCallback;
			
			/**
			 * Callback type for DANE lookup functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::vector<DANERecord> records, bool dnssec)> DANECallback;
			
			
			
			/**
			 * Constructs a DANE Resolver running on the given ASIO Service.
			 */
			Resolver(asio::io_service &service);
			
			/**
			 * Destructor.
			 */
			virtual ~Resolver();
			
			
			
			/**
			 * Returns a reference to the ASIO service.
			 */
			asio::io_service &service() const;
			
			/**
			 * Returns a reference to the list of nameserver endpoints.
			 */
			const std::vector<asio::ip::tcp::endpoint>& endpoints() const;
			
			/**
			 * Sets the list of nameserver endpoints.
			 */
			void setEndpoints(const std::vector<asio::ip::tcp::endpoint>& v);
			
			
			/**
			 * Sends a batch of DNS query packets.
			 * 
			 * @param pkts     Packets to send
			 * @param callback Callback for the results
			 */
			void query(std::vector<std::shared_ptr<ldns_pkt>> pkts, MultiQueryCallback callback);
			
			/**
			 * Sends an arbitrary DNS query packet.
			 * 
			 * @param pkt      Packet to send
			 * @param callback Callback for the results
			 */
			void query(std::shared_ptr<ldns_pkt> pkt, QueryCallback callback);
			
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
			void lookupDANE(const std::string &domain, unsigned short port, libdane::net::Protocol proto, DANECallback callback);
			
			/**
			 * Look up the DANE record for the given resource.
			 * 
			 * @param record_name A record name, in the format _port._proto.domain
			 * @param callback    Callback, receiving a DANERecord list
			 */
			void lookupDANE(const std::string &record_name, DANECallback callback);
			
			
			
			/**
			 * Decodes a packet into a list of records.
			 */
			std::vector<DANERecord> decodeTLSA(std::shared_ptr<ldns_pkt> pkt);
			
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
			
			/**
			 * Decodes a DNS packet from wire format.
			 * 
			 * @param  wire Wire representation of the packet
			 * @return A decoded packet
			 */
			std::shared_ptr<ldns_pkt> unwire(const std::vector<unsigned char> &wire);
			
		protected:
			/**
			 * Connection context structure.
			 */
			struct ConnectionContext {
				/// Transfer buffer
				std::vector<unsigned char> buffer;
				
				/// Packets to send
				std::vector<std::shared_ptr<ldns_pkt>> pkts;
				/// Iterator to the current packet
				std::vector<std::shared_ptr<ldns_pkt>>::iterator it;
			};
			
			/**
			 * Sends a query buffer through an open socket.
			 */
			void sendQuery(std::shared_ptr<asio::ip::tcp::socket> sock, std::vector<unsigned char> &buffer, std::function<void(const asio::error_code &err)>);
			
			/**
			 * Recursively sends the queries described by a context.
			 * 
			 * This will wire-encode the packet described by ctx->it, replace
			 * it with the result, advance ctx->it and call itself again until
			 * ctx->it == ctx->pkts.end().
			 * 
			 * @param sock Socket
			 * @param ctx  Context descriptor
			 * @param cb   Callback when finished
			 */
			void sendQueryChain(std::shared_ptr<asio::ip::tcp::socket> sock, std::shared_ptr<ConnectionContext> ctx, MultiQueryCallback cb);
			
		protected:
			/**
			 * ASIO Service to run asynchronous operations on.
			 */
			asio::io_service &m_service;
			
			/**
			 * A list of possible endpoints to connect to.
			 */
			std::vector<asio::ip::tcp::endpoint> m_endpoints;
		};
	}
}

#endif
