#ifndef LIBDANE_NET__DOC_H
#define LIBDANE_NET__DOC_H

namespace libdane
{
	/**
	 * Network-related functionality for libdane.
	 * 
	 * This is part of the separate `libdane_net` library, and may be excluded
	 * if you have your own way of handling DNS lookups and networking.
	 * 
	 * It depends on either ASIO or Boost::ASIO for networking, and libldns for
	 * DNS lookups and record parsing.
	 */
	namespace net
	{
		
	}
}

#endif
