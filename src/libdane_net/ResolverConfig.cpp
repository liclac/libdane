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
	m_endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8888"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8844"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("8.8.8.8"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("8.8.4.4"), 53);
}

ResolverConfig::~ResolverConfig()
{
	
}

const std::vector<asio::ip::tcp::endpoint>& ResolverConfig::endpoints() const { return m_endpoints; }
void ResolverConfig::setEndpoints(const std::vector<asio::ip::tcp::endpoint>& v) { m_endpoints = v; }

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
	
	m_endpoints = endpoints;
	
	return true;
}
