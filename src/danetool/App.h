#ifndef DANETOOL_APP_H
#define DANETOOL_APP_H

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <libdane/DANE.h>
#include <libdane/DANERecord.h>

class App
{
public:
	/**
	 * Constructor.
	 */
	App();
	
	/**
	 * Destructor.
	 */
	virtual ~App();
	
	
	
	/**
	 * Runs the application.
	 * 
	 * @param  args Commandline arguments.
	 * @return      An exit code.
	 */
	virtual int run(const std::vector<std::string> &args);
	
protected:
	/**
	 * Verifies an endpoint's presented certificate against a list of DANE records.
	 * 
	 * @param endpoint The endpoint to connect to
	 * @param records  Records to verify against
	 * @param cb       Callback for verification results
	 */
	void verify(std::deque<libdane::DANERecord> records);
	
	/**
	 * Parses commandline arguments.
	 * 
	 * @see         App::progname
	 * @see         App::args
	 * 
	 * @param  args Commandline arguments.
	 * @return      Parse success/failure
	 */
	bool parseArgs(const std::vector<std::string> &args);
	
	/**
	 * Prints a usage message.
	 */
	void printUsage() const;
	
	
	
	asio::io_service service;			///< ASIO Service
	asio::ip::tcp::resolver resolver;	///< DNS Resolver
	libdane::DANE dane;					///< DANE manager object
	
	std::string progname;		///< Program name, as called
	struct {
		bool verify = false;		///< Verify the server's TLS certificate?
		std::string domain;			///< Domain to work with
	} args;						///< Parsed arguments
};

#endif
