#include <libdane/net/Util.h>
#include <libdane/common.h>

using namespace libdane;
using namespace libdane::net;

DANERecord libdane::net::record_from_tlsa(ldns_rr *rr)
{
	ldns_rdf *usage_rd = ldns_rr_rdf(rr, 0);
	ldns_rdf *selector_rd = ldns_rr_rdf(rr, 1);
	ldns_rdf *mtype_rd = ldns_rr_rdf(rr, 2);
	ldns_rdf *data_rd = ldns_rr_rdf(rr, 3);
	
	Usage usage = static_cast<Usage>(ldns_rdf_data(usage_rd)[0]);
	Selector selector = static_cast<Selector>(ldns_rdf_data(selector_rd)[0]);
	MatchingType mtype = static_cast<MatchingType>(ldns_rdf_data(mtype_rd)[0]);
	uint8_t* data_ptr = ldns_rdf_data(data_rd);
	std::vector<unsigned char> data(data_ptr, data_ptr + ldns_rdf_size(data_rd));
	
	return DANERecord(usage, selector, mtype, data);
}
