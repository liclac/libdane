#include "App.h"
#include <iostream>
#include <sstream>

using namespace libdane;
using namespace asio;
using namespace std::placeholders;

App::App():
	resolver(service), dane(service)
{
	
}

App::~App()
{
	
}

int App::run(const std::vector<std::string> &args_)
{
	if (!this->parseArgs(args_)) {
		this->printUsage();
		return 1;
	}
	
	// Look up the DANE record for the mail server on the domain
	dane.lookupDANE(args.domain, 25, DANE::TCP, [&](std::deque<DANERecord> records) {
		for (auto it = records.begin(); it != records.end(); ++it) {
			std::cout << it->toString() << std::endl;
		}
		
		if (args.verify) {
			this->connectSMTP(args.domain, 25, records);
		}
	});
	
	service.run();
	return 0;
}

void App::connectSMTP(const std::string &domain, unsigned short port, std::deque<libdane::DANERecord> records)
{
	ip::tcp::resolver::query q(args.domain, std::to_string(port));
	resolver.async_resolve(q, [this, records](const error_code& err, ip::tcp::resolver::iterator it) {
		if (err) {
			std::cerr << "Couldn't resolve domain: " << err.message() << std::endl;
			return;
		}
		
		auto sock = std::make_shared<ip::tcp::socket>(service);
		async_connect(*sock, it, [=](const asio::error_code &err, ip::tcp::resolver::iterator it) {
			if (err) {
				std::cerr << "Couldn't connect: " << err.message() << std::endl;
				return;
			}
			
			// Callback for reading the answer to the STARTTLS command
			auto starttls_fn = [=](std::shared_ptr<streambuf> b, const error_code &err, std::size_t size) {
				if (err) {
					std::cerr << "Couldn't read STARTTLS response: " << err.message() << std::endl;
					return;
				}
				
				// Read the response from the stream
				std::stringstream ss;
				ss << b;
				std::string response = ss.str();
				// std::cout << response;
				
				// Make sure the response was affirmative
				if (response.substr(0, 3) != "220") {
					std::cerr << "Server refuses to do STARTTLS: " << std::endl;
					std::cerr << response << std::endl;
					return;
				}
				
				this->handshake(sock, records);
			};
			
			// Callback for reading the greeting line
			auto greeting_fn = [=](std::shared_ptr<streambuf> b, const error_code &err, std::size_t size) {
				if (err) {
					std::cerr << "Couldn't read greeting: " << err.message() << std::endl;
					return;
				}
				
				// Consume all read bytes to get them out of the stream
				b->consume(size);
				
				// Or, if you want to print the greeting for debugging...
				// std::stringstream ss;
				// ss << b;
				// std::string greeting = ss.str();
				// std::cout << greeting;
				
				// Write a STARTTLS command to the stream
				auto wbuf = std::make_shared<streambuf>();
				std::ostream os(&*wbuf);
				os << "STARTTLS\r\n";
				
				async_write(*sock, *wbuf, [=](const error_code &err, std::size_t size) {
					if (err) {
						std::cerr << "Couldn't write STARTTLS: " << err.message() << std::endl;
						return;
					}
					
					auto buf = std::make_shared<streambuf>();
					async_read_until(*sock, *buf, "\r\n", std::bind(starttls_fn, buf, _1, _2));
				});
			};
			
			auto buf = std::make_shared<streambuf>();
			async_read_until(*sock, *buf, "\r\n", std::bind(greeting_fn, buf, _1, _2));
		});
	});
}

void App::handshake(std::shared_ptr<asio::ip::tcp::socket> plain_sock, std::deque<libdane::DANERecord> records)
{
	ssl::context ctx(ssl::context::sslv23);
	auto sock = std::make_shared<ssl::stream<ip::tcp::socket&>>(*plain_sock, ctx);
	sock->async_handshake(ssl::stream<ip::tcp::socket>::client, [=](const error_code &err) {
		if (err) {
			std::cerr << "SSL Handshake failed: " << err.message() << std::endl;
			return;
		}
		
		std::cout << "Success!" << std::endl;
		
		// Retain these, to prevent them from getting deleted
		auto _sock = sock;
		auto _plain_sock = plain_sock;
	});
}

bool App::parseArgs(const std::vector<std::string> &args_)
{
	// The first arg is always the program name
	progname = args_[0];
	
	// Quick, terrible arg parsing
	for (auto it = args_.begin() + 1; it != args_.end(); ++it) {
		const std::string &s = *it;
		if (s[0] == '-') {
			if (s == "--verify") {
				args.verify = true;
			} else {
				return false;
			}
		} else if (args.domain.empty()) {
			args.domain = s;
		} else {
			return false;
		}
	}
	
	if (args.domain.empty()) {
		return false;
	}
	
	return true;
}

void App::printUsage() const
{
	std::cerr << "Usage: " << this->progname << " [domain]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    --verify    Also verify the server's certificate" << std::endl;
	std::cerr << std::endl;
}
