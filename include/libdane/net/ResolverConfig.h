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
			 * Creates a resolver config from the system's resolv.conf file.
			 * 
			 * @param  path Path to the file to parse
			 * @return      A new resolver config
			 */
			inline static ResolverConfig fromResolvConf(const std::string &path = "/etc/resolv.conf") {
				ResolverConfig conf;
				conf.loadResolvConf(path);
				return conf;
			}
			
			
			
			/**
			 * Initializes a resolver config with default values.
			 */
			ResolverConfig();
			
			/**
			 * Destructor.
			 */
			virtual ~ResolverConfig();
			
			
			
			/**
			 * Returns a reference to the list of nameserver endpoints.
			 */
			const std::vector<asio::ip::tcp::endpoint>& endpoints() const;
			
			/**
			 * Replaces the current config.
			 */
			 void setEndpoints(const std::vector<asio::ip::tcp::endpoint>& v);
			
			
			
			/**
			 * Loads the system's resolv.conf file.
			 * 
			 * This is a blocking operation, and will replace current values.
			 * 
			 * @see parseResolvConf
			 */
			bool loadResolvConf(const std::string &path = "/etc/resolv.conf");
			
			/**
			 * Parses the contents of a resolv.conf file.
			 * 
			 * This will replace the currently stored values.
			 * 
			 * @see loadResolvConf
			 */
			bool parseResolvConf(const std::string &str);
			
		protected:
			/**
			 * A list of possible endpoints to connect to.
			 */
			std::vector<asio::ip::tcp::endpoint> m_endpoints;
		};
	}
}

#endif
