#ifndef LIBDANE_NET_UTIL_H
#define LIBDANE_NET_UTIL_H

#include "common.h"
#include "_internal/include_ldns.h"
#include "../DANERecord.h"

namespace libdane
{
	namespace net
	{
		/**
		 * Parses a DANERecord from a resource record.
		 */
		DANERecord record_from_tlsa(ldns_rr *rr);
		
		/**
		 * Overload that takes a Shared Pointer.
		 */
		inline DANERecord record_from_tlsa(std::shared_ptr<ldns_rr> rr) {
			return record_from_tlsa(&*rr);
		}
		
		/**
		 * Constructs a record name for the given domain, port and protocol.
		 * 
		 * An example record name would be _25._tcp.mail.google.com, for the
		 * SMTP server running on Port 25 (TCP) on mail.google.com.
		 */
		std::string resource_record_name(const std::string &domain, unsigned short port, Protocol proto);
	}
}

#endif
