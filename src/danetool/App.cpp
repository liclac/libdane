#include "App.h"
#include <iostream>

using namespace libdane;
using namespace asio;

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
	dane.lookupDANE(args.domain, 465, DANE::TCP, [&](std::deque<DANERecord> records) {
		for (auto it = records.begin(); it != records.end(); ++it) {
			std::cout << it->toString() << std::endl;
		}
		
		if (args.verify) {
			this->verify(records);
		}
	});
	
	service.run();
	return 0;
}

void App::verify(std::deque<libdane::DANERecord> records)
{
	ip::tcp::resolver::query q(args.domain, "465");
	resolver.async_resolve(q, [this](const error_code& err, ip::tcp::resolver::iterator it) {
		if (err) {
			std::cerr << "Couldn't resolve domain: " << err.message() << std::endl;
			return;
		}
		// std::cout << "Resolved!" << std::endl;
		
		ssl::context ctx(ssl::context::sslv23);
		auto sock = std::make_shared<ssl::stream<ip::tcp::socket>>(service, ctx);
		async_connect(sock->lowest_layer(), it, [sock](const asio::error_code& err, ip::tcp::resolver::iterator it) {
			if (err) {
				std::cerr << "Couldn't connect: " << err.message() << std::endl;
				return;
			}
			// std::cout << "Connected!" << std::endl;
			
			sock->async_handshake(ssl::stream<ip::tcp::socket>::client, [sock](const error_code &err) {
				if (err) {
					std::cerr << "SSL Handshake failed: " << err.message() << std::endl;
					return;
				} else {
					std::cout << "Success!" << std::endl;
				}
			});
		});
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
