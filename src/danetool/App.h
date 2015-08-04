#ifndef DANETOOL_APP_H
#define DANETOOL_APP_H

#include <libdane/DANE.h>
#include <libdane/DANERecord.h>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <memory>

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
	 * Attempts to authorize with an SMTP host using STARTTLS.
	 * 
	 * @param records A list of DANE records for the domain.
	 */
	void connectSMTP(const std::string &domain, unsigned short port, std::deque<libdane::DANERecord> records);
	
	/**
	 * Verifies an endpoint's presented certificate against a list of DANE records.
	 * 
	 * @param sock     Socket to initiate a TLS handshake on
	 * @param records  Records to verify against
	 */
	void handshake(std::shared_ptr<asio::ip::tcp::socket> sock, std::deque<libdane::DANERecord> records);
	
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
