#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <thread>
#include <functional>
#include <asio.hpp>
#include <libdane/DANE.h>
#include <libdane/DANERecord.h>

using namespace libdane;

#define WORKERS 2

void printUsage(std::string progname = "danetool")
{
	std::cerr << "Usage: " << progname << " [domain]" << std::endl;
	std::cerr << std::endl;
	std::cerr << "    --verify    Also verify the server's certificate" << std::endl;
	std::cerr << std::endl;
}

int main(int argc, char **argv)
{
	// C++ify the argument list
	std::string progname = argv[0];
	std::vector<std::string> args(argv + 1, argv + argc);
	
	// Quick, terrible arg parsing
	bool verify = false;
	std::string domain;
	for (auto it = args.begin(); it != args.end(); ++it) {
		const std::string &s = *it;
		if (s[0] == '-') {
			if (s == "--verify") {
				verify = true;
			}
		} else {
			domain = s;
		}
	}
	
	// Print usage instructions and quit if no domain is given
	if (domain.empty()) {
		printUsage(progname);
		return 1;
	}
	
	// Use ASIO for asynchronous processing
	// (TODO: Use ASIO's network facilities instead of libldns' built-in)
	asio::io_service service;
	
	// Create a DANE object
	DANE dane(service);
	
	// Look up the DANE record for the mail server on the domain
	dane.lookupDANE(std::string("_25._tcp.") + domain, [&](std::deque<DANERecord> records) {
		for (auto it = records.begin(); it != records.end(); ++it) {
			std::cout << it->toString() << std::endl;
		}
	});
	
	// Run ASIO's event loop until it runs out of work
	// (You can run this across multiple worker threads if you prefer)
	service.run();
	
	return 0;
}
