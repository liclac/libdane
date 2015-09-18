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
#include "ResolverConfig.h"
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
			typedef std::function<void(const asio::error_code &err, std::vector<std::shared_ptr<ldns_pkt>> pkts, const std::vector<bool> dnssec)> MultiQueryCallback;
			
			/**
			 * Callback type for query functions.
			 */
			typedef std::function<void(const asio::error_code &err, std::shared_ptr<ldns_pkt> pkt, bool dnssec)> QueryCallback;
			
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
			 * Returns a reference to the current config.
			 */
			const ResolverConfig& config() const;
			
			/**
			 * Returns a reference to the current config.
			 */
			ResolverConfig& config();
			
			/**
			 * Replaces the current config.
			 */
			void setConfig(const ResolverConfig& v);
			
			
			
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
			std::vector<unsigned char> wire(std::shared_ptr<ldns_pkt> pkt, bool tcp);
			
			/**
			 * Decodes a DNS packet from wire format.
			 * 
			 * @param  wire Wire representation of the packet
			 * @return A decoded packet
			 */
			std::shared_ptr<ldns_pkt> unwire(const std::vector<unsigned char> &wire);
			
			/**
			 * Checks the packet's DNSSEC authorization status.
			 * 
			 * This will assume that the AD flag on the returned packet is
			 * trustworthy, and by extension, that the DNS server you're
			 * querying can be trusted. Choose your server wisely.
			 * 
			 * @param  pkt Packet to verify
			 * @return     DNSSEC status
			 */
			bool verifyDNSSEC(std::shared_ptr<ldns_pkt> pkt);
			
			
			
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
			
			/**
			 * Sends a query buffer through an open socket.
			 */
			void sendQuery(std::shared_ptr<asio::ip::tcp::socket> sock, std::vector<unsigned char> &buffer, std::function<void(const asio::error_code &err)>);
			
		protected:
			/**
			 * ASIO Service to run asynchronous operations on.
			 */
			asio::io_service &m_service;
			
			/**
			 * Current configuration.
			 */
			ResolverConfig m_config;
		};
	}
}

#endif
