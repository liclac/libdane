#include "App.h"
#include <iostream>

using namespace libdane;

App::App():
	dane(service)
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
	});
	
	service.run();
	return 0;
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
