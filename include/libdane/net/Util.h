#ifndef LIBDANE_NET_UTIL_H
#define LIBDANE_NET_UTIL_H

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
	}
}

#endif
