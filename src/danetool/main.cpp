extern "C" {
	#include <ldns/ldns.h>
}

#include <iostream>
#include <asio.hpp>

int main(int argc, char **argv)
{
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " [domain]" << std::endl;
		return 1;
	}
	
	/* create a new resolver from /etc/resolv.conf */
	ldns_resolver *res = NULL;
	if (ldns_resolver_new_frm_file(&res, NULL) != LDNS_STATUS_OK) {
		exit(EXIT_FAILURE);
	}
	
	/* create a rdf from the command line arg */
	ldns_rdf *domain = ldns_dname_new_frm_str(argv[1]);
	if (!domain) {
		std::cerr << "Couldn't create a domain" << std::endl;
		exit(EXIT_FAILURE);
	}
	
	/* use the resolver to send a query for the mx 
	 * records of the domain given on the command line
	 */
	ldns_pkt *p = ldns_resolver_query(res, domain, LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN, LDNS_RD);
	
	ldns_rdf_deep_free(domain);
	
	if (!p)  {
		exit(EXIT_FAILURE);
	}
	
	/* retrieve the MX records from the answer section of that
	 * packet
	 */
	ldns_rr_list *mx = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER);
	if (!mx) {
		std::cerr << "Invalid answer name after query for " << argv[1] << std::endl;
		ldns_pkt_free(p);
		ldns_resolver_deep_free(res);
		exit(EXIT_FAILURE);
	}
	
	ldns_rr_list_sort(mx);
	ldns_rr_list_print(stdout, mx);
	ldns_rr_list_deep_free(mx);
	
	ldns_pkt_free(p);
	ldns_resolver_deep_free(res);
	
	return 0;
}
