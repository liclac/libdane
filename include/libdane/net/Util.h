#ifndef LIBDANE_NET_UTIL_H
#define LIBDANE_NET_UTIL_H

#include "_internal/include_ldns.h"
#include "../DANERecord.h"

namespace libdane
{
	namespace net
	{
		DANERecord record_from_tlsa(ldns_rr *rr);
		
		inline DANERecord record_from_tlsa(std::shared_ptr<ldns_rr> rr) {
			return record_from_tlsa(&*rr);
		}
	}
}

#endif
