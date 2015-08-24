#ifndef LIBDANE_NET_COMMON_H
#define LIBDANE_NET_COMMON_H

namespace libdane
{
	namespace net
	{
		/**
		 * Different protocols, used for lookups.
		 */
		enum Protocol {
			TCP,			///< Transmission Control Protocol
			UDP,			///< User Datagram Protocol
		};
	}
}

#endif
