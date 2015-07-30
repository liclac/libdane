#include <libdane/DANE.h>
#include <libdane/DANERecord.h>
#include <iostream>
#include <sstream>
#include <memory>
#include <vector>

extern "C" {
	#define HAVE_STDBOOL_H 1
	#include <ldns/ldns.h>
}

using namespace libdane;

/// @private
struct DANE::Impl
{
	ldns_resolver *resolver = NULL;
};

DANE::DANE(asio::io_service &service):
	service(service),
	p(new DANE::Impl)
{
	if (ldns_resolver_new_frm_file(&p->resolver, NULL) != LDNS_STATUS_OK) {
		throw std::runtime_error("Cannot create a resolver from /etc/resolv.conf");
	}
}

DANE::~DANE()
{
	ldns_resolver_deep_free(p->resolver);
	delete p;
}

void DANE::lookupDANE(const std::string &domain, std::function<void(std::deque<DANERecord>)> callback)
{
	service.post([&] {
		std::shared_ptr<ldns_rdf> ldomain(ldns_dname_new_frm_str(domain.c_str()), ldns_rdf_deep_free);
		if (!ldomain) {
			throw std::runtime_error(std::string("Invalid domain: ") + domain);
		}
		
		std::shared_ptr<ldns_pkt> pkt(ldns_resolver_query(
			p->resolver, &*ldomain,
			LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN, LDNS_RD
		), ldns_pkt_free);
		if (!pkt) {
			throw std::runtime_error(std::string("Coudn't formulate a query"));
		}
		
		std::deque<DANERecord> records;
		
		std::shared_ptr<ldns_rr_list> list(ldns_pkt_rr_list_by_type(&*pkt, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER), ldns_rr_list_deep_free);
		for (size_t i = 0; i < ldns_rr_list_rr_count(&*list); i++) {
			ldns_rr *rr = ldns_rr_list_rr(&*list, i);
			
			ldns_rdf *usage_rd = ldns_rr_rdf(rr, 0);
			ldns_rdf *selector_rd = ldns_rr_rdf(rr, 1);
			ldns_rdf *mtype_rd = ldns_rr_rdf(rr, 2);
			ldns_rdf *data_rd = ldns_rr_rdf(rr, 3);
			
			DANERecord::Usage usage = static_cast<DANERecord::Usage>(ldns_rdf_data(usage_rd)[0]);
			DANERecord::Selector selector = static_cast<DANERecord::Selector>(ldns_rdf_data(selector_rd)[0]);
			DANERecord::MatchingType mtype = static_cast<DANERecord::MatchingType>(ldns_rdf_data(mtype_rd)[0]);
			uint8_t* data_ptr = ldns_rdf_data(data_rd);
			std::vector<char> data(data_ptr, data_ptr + ldns_rdf_size(data_rd));
			
			records.emplace_back(usage, selector, mtype, data);
		}
		
		callback(records);
	});
}
