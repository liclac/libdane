#ifndef DANE_H
#define DANE_H

#include <asio.hpp>
#include <deque>

namespace libdane
{
	class DANERecord;
	class DANE
	{
	public:
		DANE(asio::io_service &service);
		virtual ~DANE();
		
		void lookupDANE(const std::string &domain, std::function<void(std::deque<DANERecord>)> callback);
		
	protected:
		asio::io_service &service;
		
		struct Impl;
		Impl *p;
	};
}


#endif
