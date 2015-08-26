#include <libdane/net/Util.h>
#include <libdane/common.h>
#include <sstream>

using namespace libdane;
using namespace libdane::net;

std::shared_ptr<ldns_rr> libdane::net::make_tlsa(Usage u, Selector sel, MatchingType mt, const Blob &data)
{
	auto rr = std::shared_ptr<ldns_rr>(ldns_rr_new(), ldns_rr_free);
	ldns_rr_set_type(&*rr, LDNS_RR_TYPE_TLSA);
	
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(u), &u));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(sel), &sel));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8, sizeof(mt), &mt));
	ldns_rr_push_rdf(&*rr, ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX, data.data().size(), data.data().data()));
	
	return rr;
}

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

std::string libdane::net::resource_record_name(const std::string &domain, unsigned short port, Protocol proto)
{
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
	
	return record_path_ss.str();
}
