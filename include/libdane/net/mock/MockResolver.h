/**
 * mock/MockResolver.h
 * libdane_net
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_NET_MOCK_MOCKRESOLVER_H
#define LIBDANE_NET_MOCK_MOCKRESOLVER_H

#include "../Resolver.h"
#include "../_internal/ldns.h"
#include <functional>
#include <memory>
#include <queue>

namespace libdane
{
	namespace net
	{
		namespace mock
		{
			/**
			 * Mock resolver for unit testing.
			 * 
			 * This class uses a list of mock functions, which will be invoked
			 * for one query, then removed from the list. If a query is made
			 * with no mock function enqueued, an exception will be thrown.
			 */
			class MockResolver : public Resolver
			{
			public:
				/**
				 * Mock function.
				 * 
				 * You're free to make an answer packet out of the query packet
				 * without copying it; it is not used again after a call to a
				 * mock function.
				 * 
				 * @param  q A query packet
				 * @return   An answer packet
				 */
				typedef std::function<std::shared_ptr<ldns_pkt>(std::shared_ptr<ldns_pkt> q)> MockFn;
				
				
				
				/**
				 * Constructs a mock Resolver running on the given ASIO Service.
				 */
				MockResolver(asio::io_service &service);
				
				/**
				 * Destructor.
				 */
				virtual ~MockResolver();
				
				/**
				 * Enqueues a mock function.
				 */
				void mock(MockFn fn);
				
				/**
				 * Enqueues am mock function that just returns pkt.
				 */
				void mock(std::shared_ptr<ldns_pkt> pkt);
				
				/**
				 * Invokes and pops the next queued mock function.
				 * 
				 * @param  pkt A query packet
				 * @return An answer packet
				 * @throws std::range_error if no mock function is queued
				 */
				std::shared_ptr<ldns_pkt> invokeMock(std::shared_ptr<ldns_pkt> pkt);
				
				/**
				 * Doesn't actually connect anywhere.
				 * 
				 * It will immediately yield a pointer to a newly constructed,
				 * unconnected socket.
				 * 
				 * @param conf Resolver configuration to use
				 * @param cb   Callback that receives a socket
				 */
				virtual void connect(const ResolverConfig &conf, std::function<void(const asio::error_code &err, std::shared_ptr<asio::ip::tcp::socket>)> cb) const;
				
				/**
				 * Pretends to send a query, actually just invokes a mock.
				 */
				virtual void sendQuery(std::shared_ptr<asio::ip::tcp::socket> sock, std::vector<unsigned char> &buffer, std::function<void(const asio::error_code &err)>);
				
			protected:
				/**
				 * Queued mock functions.
				 */
				std::queue<MockFn> m_mocks;
			};
		}
	}
}

#endif
