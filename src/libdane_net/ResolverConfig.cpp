/**
 * ResolverConfig.cpp
 * libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <libdane/net/ResolverConfig.h>
#include <fstream>
#include <sstream>

using namespace libdane;
using namespace libdane::net;

std::vector<asio::ip::tcp::endpoint> ResolverConfig::loadResolvConf(const std::string &path)
{
	std::fstream fs(path, std::ios::binary|std::ios::in);
	if (!fs.is_open()) {
		return {};
	}
	
	std::stringstream ss;
	ss << fs.rdbuf();
	return ResolverConfig::parseResolvConf(ss.str());
}

std::vector<asio::ip::tcp::endpoint> ResolverConfig::parseResolvConf(const std::string &str)
{
	std::vector<asio::ip::tcp::endpoint> endpoints;
	
	std::stringstream ss(str);
	std::string line;
	while (std::getline(ss, line)) {
		std::string nsprefix("nameserver");
		if (line.compare(0, nsprefix.size(), nsprefix) == 0) {
			std::string address = line.substr(nsprefix.size() + 1);
			endpoints.emplace_back(asio::ip::address::from_string(address), 53);
		}
	}
	
	return endpoints;
}
