/**
 * ResolverConfig.h
 * libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_NET_RESOLVERCONFIG_H
#define LIBDANE_NET_RESOLVERCONFIG_H

#include <asio.hpp>
#include <vector>

namespace libdane
{
	namespace net
	{
		class ResolverConfig
		{
		public:
			static std::vector<asio::ip::tcp::endpoint> loadResolvConf(const std::string &path = "/etc/resolv.conf");
			static std::vector<asio::ip::tcp::endpoint> parseResolvConf(const std::string &str);
			
		private:
			ResolverConfig() = delete;
			ResolverConfig(const ResolverConfig &other) = delete;
			virtual ~ResolverConfig() = 0;
		};
	}
}

#endif
