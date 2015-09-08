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
		/**
		 * Abstraction for Resolver configuration.
		 * 
		 * This reads and parses the system's /etc/resolv.conf file, but since
		 * blocking IO in a constructor is Bad, you have to manually tell it to
		 * load it.
		 * 
		 * If you don't load a resolv.conf file, default settings (using
		 * Google's public DNS servers) will be used.
		 * 
		 * @warning This class will soon be completely redesigned
		 */
		class ResolverConfig
		{
		public:
			/**
			 * Loads the system's resolv.conf file.
			 * 
			 * This is a blocking operation.
			 * 
			 * @see parseResolvConf
			 */
			static std::vector<asio::ip::tcp::endpoint> loadResolvConf(const std::string &path = "/etc/resolv.conf");
			
			/**
			 * Parses the contents of a resolv.conf file.
			 * 
			 * @see loadResolvConf
			 */
			static std::vector<asio::ip::tcp::endpoint> parseResolvConf(const std::string &str);
			
		private:
			ResolverConfig() = delete;
			ResolverConfig(const ResolverConfig &other) = delete;
			virtual ~ResolverConfig() = 0;
		};
	}
}

#endif
