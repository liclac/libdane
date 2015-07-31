#ifndef DANE_H
#define DANE_H

#include <asio.hpp>
#include <deque>

namespace libdane
{
	class DANERecord;
	
	/**
	 * Manager class for looking up DANE records.
	 * 
	 * Under the hood, this class uses libldns and ASIO (C++11 standalone or
	 * Boost) for DNS queries, and produces DANERecord objects.
	 * 
	 * @see libldns - http://www.nlnetlabs.nl/projects/ldns/
	 * @see ASIO - http://think-async.com/
	 */
	class DANE
	{
	public:
		/**
		 * Enum for protocols in lookups.
		 */
		enum Protocol {
			TCP,			///< Transmission Control Protocol
			UDP,			///< User Datagram Protocol
		};
		
		
		
		/**
		 * Constructs a DANE Manager running on the given ASIO Service.
		 */
		DANE(asio::io_service &service);
		
		/**
		 * Destructor.
		 */
		virtual ~DANE();
		
		
		
		/**
		 * Look up the DANE record for the given domain.
		 * 
		 * @param domain   Domain name to look up
		 * @param callback Callback, receiving a DANERecord list
		 */
		void lookupDANE(const std::string &domain, unsigned short port, Protocol proto, std::function<void(std::deque<DANERecord>)> callback);
		
	protected:
		/**
		 * ASIO Service to run asynchronous operations on.
		 */
		asio::io_service &service;
		
	private:
		struct Impl;
		Impl *p;
	};
}


#endif
