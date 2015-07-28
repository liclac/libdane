#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <functional>
#include <asio.hpp>
#include <libdane/DANE.h>

using namespace libdane;

#define WORKERS 2

int main(int argc, char **argv)
{
	// C++ify the argument list
	std::string progname = argv[0];
	std::vector<std::string> args(argv + 1, argv + argc);
	
	// Require an argument (the domain to look up)
	if (args.size() < 1) {
		std::cerr << "Usage: " << progname << " [domain]" << std::endl;
		return 1;
	}
	
	// Use ASIO for asynchronous processing
	// (TODO: Use ASIO's network facilities instead of libldns' built-in)
	asio::io_service service;
	
	// Create a DANE object
	DANE dane(service);
	
	// Look up the DANE record for the mail server on the domain
	dane.lookupDANE(std::string("_25._tcp.") + args[0]);
	
	// Run ASIO's event loop until it runs out of work
	// (You can run this across multiple worker threads if you prefer)
	service.run();
	
	return 0;
}
