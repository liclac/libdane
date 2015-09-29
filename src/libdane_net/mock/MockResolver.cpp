/**
 * mock/MockResolver.cpp
 * libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <libdane/net/mock/MockResolver.h>

using namespace libdane::net::mock;

MockResolver::MockResolver(asio::io_service &service):
	Resolver(service)
{
	
}

MockResolver::~MockResolver()
{
	
}

void MockResolver::mock(MockFn fn)
{
	m_mocks.push(fn);
}

void MockResolver::mock(std::shared_ptr<ldns_pkt> pkt)
{
	this->mock([=](std::shared_ptr<ldns_pkt> q) {
		return pkt;
	});
}

std::shared_ptr<ldns_pkt> MockResolver::invokeMock(std::shared_ptr<ldns_pkt> pkt)
{
	if (m_mocks.empty()) {
		throw std::range_error("No mock functions enqueued");
	}
	
	auto fn = m_mocks.front();
	m_mocks.pop();
	return fn(pkt);
}

void MockResolver::connect(const ResolverConfig &conf, std::function<void(const asio::error_code &err, std::shared_ptr<asio::ip::tcp::socket>)> cb) const
{
	auto sock = std::make_shared<asio::ip::tcp::socket>(m_service);
	cb({}, sock);
}

void MockResolver::sendQuery(std::shared_ptr<asio::ip::tcp::socket> sock, std::vector<unsigned char> &buffer, std::function<void(const asio::error_code &err)> cb)
{
	auto pkt = this->unwire(buffer.begin() + 2, buffer.end());
	auto ret = this->invokeMock(pkt);
	auto wired = this->wire(ret, false);
	buffer.assign(wired.begin(), wired.end());
	cb({});
}
