#include <libdane/net/Resolver.h>
#include <libdane/DANERecord.h>
#include <libdane/Util.h>
#include <libdane/net/Util.h>
#include <memory>
#include <vector>

using namespace libdane;
using namespace libdane::net;

Resolver::Resolver(asio::io_service &service):
	service(service)
{
	// Hardcoding Google's DNS servers for now
	// TODO: Parse /etc/resolv.conf instead
	endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8888"), 53);
	endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8844"), 53);
	endpoints.emplace_back(asio::ip::address::from_string("8.8.8.8"), 53);
	endpoints.emplace_back(asio::ip::address::from_string("8.8.4.4"), 53);
}

Resolver::~Resolver()
{
	
}

void Resolver::lookupDANE(const std::string &domain, unsigned short port, libdane::net::Protocol proto, std::function<void(std::deque<DANERecord>)> callback)
{
	std::string record_name = resource_record_name(domain, port, proto);
	this->lookupDANE(record_name, callback);
}

void Resolver::lookupDANE(const std::string &record_name, std::function<void(std::deque<DANERecord>)> cb)
{
	std::shared_ptr<ldns_pkt> pkt(ldns_pkt_query_new(
		ldns_dname_new_frm_str(record_name.c_str()),
		LDNS_RR_TYPE_TLSA, LDNS_RR_CLASS_IN, LDNS_RD),
	ldns_pkt_free);
	if (!pkt) {
		throw std::runtime_error("Couldn't create a query packet");
	}
	ldns_pkt_set_id(&*pkt, 1337);
	
	uint8_t *buf;
	std::size_t len;
	if (ldns_pkt2wire(&buf, &*pkt, &len) != LDNS_STATUS_OK) {
		throw std::runtime_error("Couldn't convert packet to wire format");
	}
	uint16_t binlen = htons(len);
	
	auto qbuf = std::make_shared<std::vector<unsigned char>>();
	qbuf->insert(qbuf->begin(), &binlen, &binlen + sizeof(binlen));
	qbuf->insert(qbuf->begin() + sizeof(binlen), buf, buf + len);
	
	free(buf);
	
	auto sock = std::make_shared<asio::ip::tcp::socket>(service);
	async_connect(*sock, endpoints.begin(), endpoints.end(), [this, sock, cb, qbuf](const asio::error_code &err, std::vector<asio::ip::tcp::endpoint>::iterator it) {
		if (err) {
			return;
		}
		
		sock->async_send(asio::buffer(*qbuf), [this, sock, cb, qbuf](const asio::error_code &err, std::size_t size) {
			if (err) {
				return;
			}
			
			auto rdbuf = std::make_shared<std::vector<unsigned char>>(sizeof(uint16_t));
			sock->async_receive(asio::buffer(*rdbuf), [this, sock, cb, rdbuf](const asio::error_code &err, std::size_t size) {
				if (err) {
					return;
				}
				
				if (size != sizeof(uint16_t)) {
					throw std::runtime_error("Invalid number of bytes read (response size)");
				}
				
				uint16_t len;
				std::copy(rdbuf->begin(), rdbuf->end(), reinterpret_cast<unsigned char*>(&len));
				
				len = ntohs(len);
				rdbuf->resize(len);
				
				sock->async_receive(asio::buffer(*rdbuf), [this, sock, cb, rdbuf, len](const asio::error_code &err, std::size_t size) {
					if (err) {
						return;
					}
					
					if (size != len) {
						throw std::runtime_error("Invalid number of bytes read (response data)");
					}
					
					ldns_pkt *packet_ptr;
					if (ldns_wire2pkt(&packet_ptr, rdbuf->data(), rdbuf->size()) != LDNS_STATUS_OK) {
						throw std::runtime_error("Failed to decode response");
					}
					std::shared_ptr<ldns_pkt> packet(packet_ptr, ldns_pkt_free);
					std::deque<DANERecord> records = this->decode(packet);
					cb(records);
				});
			});
		});
	});
}

std::deque<DANERecord> Resolver::decode(std::shared_ptr<ldns_pkt> pkt)
{
	std::deque<DANERecord> records;
	
	std::shared_ptr<ldns_rr_list> tlsas(ldns_pkt_rr_list_by_type(&*pkt, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER), ldns_rr_list_deep_free);
	for (size_t i = 0; i < ldns_rr_list_rr_count(&*tlsas); ++i) {
		ldns_rr *tlsa = ldns_rr_list_rr(&*tlsas, i);
		records.push_back(record_from_tlsa(tlsa));
	}
	
	return records;
}
