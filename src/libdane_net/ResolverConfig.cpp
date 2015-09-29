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

ResolverConfig::ResolverConfig()
{
	m_nameServers.push_back(asio::ip::address::from_string("2001:4860:4860::8888"));
	m_nameServers.push_back(asio::ip::address::from_string("2001:4860:4860::8844"));
	m_nameServers.push_back(asio::ip::address::from_string("8.8.8.8"));
	m_nameServers.push_back(asio::ip::address::from_string("8.8.4.4"));
}

ResolverConfig::~ResolverConfig()
{
	
}

const std::vector<asio::ip::address>& ResolverConfig::nameServers() const { return m_nameServers; }
void ResolverConfig::setNameServers(const std::vector<asio::ip::address>& v) { m_nameServers = v; }

std::vector<asio::ip::tcp::endpoint> ResolverConfig::endpoints() const
{
	std::vector<asio::ip::tcp::endpoint> endpoints;
	for (auto addr : m_nameServers) {
		endpoints.emplace_back(addr, 53);
	}
	return endpoints;
}

bool ResolverConfig::load()
{
	return this->loadResolvConf();
}

bool ResolverConfig::loadResolvConf(const std::string &path)
{
	std::fstream fs(path, std::ios::binary|std::ios::in);
	if (!fs.is_open()) {
		return false;
	}
	
	std::stringstream ss;
	ss << fs.rdbuf();
	return this->parseResolvConf(ss.str());
}

bool ResolverConfig::parseResolvConf(const std::string &str)
{
	std::vector<asio::ip::address> nameServers;
	
	std::stringstream ss(str);
	std::string line;
	while (std::getline(ss, line)) {
		std::string nsprefix("nameserver");
		if (line.compare(0, nsprefix.size(), nsprefix) == 0) {
			std::string address = line.substr(nsprefix.size() + 1);
			nameServers.push_back(asio::ip::address::from_string(address));
		}
	}
	
	m_nameServers = nameServers;
	
	return true;
}
