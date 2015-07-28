#ifndef DANE_H
#define DANE_H

#include <asio.hpp>

namespace libdane
{
	class DANE
	{
	public:
		DANE(asio::io_service &service);
		virtual ~DANE();
		
		void lookupDANE(const std::string &domain);
		
	protected:
		asio::io_service &service;
		
		struct Impl;
		Impl *p;
	};
}


#endif
