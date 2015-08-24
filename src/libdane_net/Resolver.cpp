#include <libdane/net/Resolver.h>
#include <libdane/DANERecord.h>
#include <libdane/Util.h>
#include <libdane/net/Util.h>
#include <iostream>
#include <sstream>
#include <memory>
#include <vector>

using namespace libdane;
using namespace libdane::net;

/// @private
struct Resolver::Impl
{
	ldns_resolver *resolver = NULL;
};

Resolver::Resolver(asio::io_service &service):
	service(service),
	p(new Resolver::Impl)
{
	if (ldns_resolver_new_frm_file(&p->resolver, NULL) != LDNS_STATUS_OK) {
		throw std::runtime_error("Cannot create a resolver from /etc/resolv.conf");
	}
}

Resolver::~Resolver()
{
	ldns_resolver_deep_free(p->resolver);
	delete p;
}

void Resolver::lookupDANE(const std::string &domain, unsigned short port, Protocol proto, std::function<void(std::deque<DANERecord>)> callback)
{
	// Build a _<port>._<proto>.<domain> string for service lookup
	std::stringstream record_path_ss;
	record_path_ss << "_" << port << "._";
	switch (proto) {
		case TCP:
			record_path_ss << "tcp";
			break;
		case UDP:
			record_path_ss << "udp";
			break;
	}
	record_path_ss << "." << domain;
	std::string record_path = record_path_ss.str();
	
	// For now, just post a synchronous DNS lookup to a worker thread
	// TODO: Use ASIO's network facilities for proper asynchrony
	service.post([=] {
		std::shared_ptr<ldns_rdf> ldomain(ldns_dname_new_frm_str(record_path.c_str()), ldns_rdf_deep_free);
		if (!ldomain) {
			throw std::runtime_error(std::string("Invalid record path: ") + record_path);
		}
		
		std::shared_ptr<ldns_pkt> pkt(ldns_resolver_query(
			p->resolver, &*ldomain,
			LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN, LDNS_RD
		), ldns_pkt_free);
		if (!pkt) {
			throw std::runtime_error(std::string("Coudn't formulate a query"));
		}
		
		std::deque<DANERecord> records;
		std::shared_ptr<ldns_rr_list> tlsalist(ldns_pkt_rr_list_by_type(&*pkt, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER), ldns_rr_list_deep_free);
		for (size_t i = 0; i < ldns_rr_list_rr_count(&*tlsalist); i++) {
			ldns_rr *rr = ldns_rr_list_rr(&*tlsalist, i);
			records.push_back(record_from_tlsa(rr));
		}
		
		callback(records);
	});
}
