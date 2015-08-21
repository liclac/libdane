#ifndef LIBDANE_UTIL_H
#define LIBDANE_UTIL_H

#include "VerifyContext.h"
#include "DANERecord.h"

namespace libdane
{
	/**
	 * Verifies a VerifyContext against a list of DANERecords.
	 */
	template<typename IterT>
	bool verify(bool preverified, const VerifyContext &ctx, IterT begin, IterT end)
	{
		for (IterT it = begin; it != end; ++it) {
			const DANERecord &rec = *it;
			if (rec.verify(preverified, ctx)) {
				return true;
			}
		}
		
		return false;
	}
}

#endif
