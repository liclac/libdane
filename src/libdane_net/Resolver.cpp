#include <libdane/net/Resolver.h>
#include <libdane/DANERecord.h>
#include <libdane/Util.h>
#include <libdane/net/Util.h>
#include <memory>
#include <vector>

using namespace libdane;
using namespace libdane::net;

Resolver::Resolver(asio::io_service &service):
	m_service(service)
{
	// Default to Google's DNS servers
	m_endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8888"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("2001:4860:4860::8844"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("8.8.8.8"), 53);
	m_endpoints.emplace_back(asio::ip::address::from_string("8.8.4.4"), 53);
}

Resolver::~Resolver()
{
	
}



asio::io_service& Resolver::service() const { return m_service; }

const std::vector<asio::ip::tcp::endpoint>& Resolver::endpoints() const { return m_endpoints; }
void Resolver::setEndpoints(const std::vector<asio::ip::tcp::endpoint>& v) { m_endpoints = v; }



void Resolver::query(std::vector<std::shared_ptr<ldns_pkt>> pkts, MultiQueryCallback cb)
{
	if (!pkts.size()) {
		cb({}, {});
	}
	
	auto ctx = std::make_shared<ConnectionContext>();
	ctx->pkts = pkts;
	ctx->it = ctx->pkts.begin();
	
	auto sock = std::make_shared<asio::ip::tcp::socket>(m_service);
	async_connect(*sock, m_endpoints.begin(), m_endpoints.end(), [=](const asio::error_code &err, std::vector<asio::ip::tcp::endpoint>::iterator it) {
		if (err) {
			cb(err, {});
			return;
		}
		
		this->sendQueryChain(sock, ctx, cb);
	});
}

void Resolver::query(std::shared_ptr<ldns_pkt> pkt, QueryCallback cb)
{
	this->query({pkt}, [=](const asio::error_code &err, std::vector<std::shared_ptr<ldns_pkt>> pkts) {
		cb(err, pkts.size() > 0 ? pkts[0] : nullptr);
	});
}

void Resolver::query(const std::string &domain, ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags, QueryCallback cb)
{
	std::shared_ptr<ldns_pkt> pkt(this->makeQuery(domain, rr_type, rr_class, flags));
	this->query(pkt, cb);
}

void Resolver::query(const std::string &domain, ldns_rr_type rr_type, QueryCallback cb)
{
	this->query(domain, rr_type, LDNS_RR_CLASS_IN, LDNS_RD, cb);
}

void Resolver::lookupDANE(const std::string &domain, unsigned short port, libdane::net::Protocol proto, DANECallback cb)
{
	std::string record_name = resource_record_name(domain, port, proto);
	this->lookupDANE(record_name, cb);
}

void Resolver::lookupDANE(const std::string &record_name, DANECallback cb)
{
	this->query(record_name, LDNS_RR_TYPE_TLSA, [=](const asio::error_code &err, std::shared_ptr<ldns_pkt> pkt) {
		if (err) {
			cb(err, {});
			return;
		}
		
		cb({}, this->decodeTLSA(pkt));
	});
}

std::deque<DANERecord> Resolver::decodeTLSA(std::shared_ptr<ldns_pkt> pkt)
{
	std::deque<DANERecord> records;
	
	std::shared_ptr<ldns_rr_list> tlsas(ldns_pkt_rr_list_by_type(&*pkt, LDNS_RR_TYPE_TLSA, LDNS_SECTION_ANSWER), ldns_rr_list_deep_free);
	for (size_t i = 0; i < ldns_rr_list_rr_count(&*tlsas); ++i) {
		ldns_rr *tlsa = ldns_rr_list_rr(&*tlsas, i);
		records.push_back(record_from_tlsa(tlsa));
	}
	
	return records;
}

std::shared_ptr<ldns_pkt> Resolver::makeQuery(const std::string &domain, ldns_rr_type rr_type, ldns_rr_class rr_class, uint16_t flags)
{
	ldns_rdf *dname = ldns_dname_new_frm_str(domain.c_str());
	std::shared_ptr<ldns_pkt> pkt(ldns_pkt_query_new(dname, rr_type, rr_class, flags), ldns_pkt_free);
	if (!pkt) {
		throw std::runtime_error("Couldn't create a query packet");
	}
	ldns_pkt_set_id(&*pkt, 1337);
	
	return pkt;
}

std::vector<unsigned char> Resolver::wire(std::shared_ptr<ldns_pkt> pkt, bool tcp)
{
	uint8_t *buf;
	std::size_t len;
	if (ldns_pkt2wire(&buf, &*pkt, &len) != LDNS_STATUS_OK) {
		throw std::runtime_error("Couldn't convert packet to wire format");
	}
	
	std::vector<unsigned char> wire;
	if (tcp) {
		uint16_t binlen = htons(len);
		unsigned char *binlen_ptr = reinterpret_cast<unsigned char*>(&binlen);
		wire.insert(wire.end(), binlen_ptr, binlen_ptr + sizeof(binlen));
	}
	wire.insert(wire.end(), buf, buf + len);
	
	return wire;
}

std::shared_ptr<ldns_pkt> Resolver::unwire(const std::vector<unsigned char> &wire)
{
	ldns_pkt *packet_ptr;
	if (ldns_wire2pkt(&packet_ptr, wire.data(), wire.size()) != LDNS_STATUS_OK) {
		throw std::runtime_error("Failed to decode response");
	}
	return std::shared_ptr<ldns_pkt>(packet_ptr, ldns_pkt_free);
}

void Resolver::sendQuery(std::shared_ptr<asio::ip::tcp::socket> sock, std::vector<unsigned char> &buffer, std::function<void(const asio::error_code &err)> cb)
{
	sock->async_send(asio::buffer(buffer), [sock, &buffer, cb](const asio::error_code &err, std::size_t size) mutable {
		if (err) {
			cb(err);
			return;
		}
		
		buffer.resize(sizeof(uint16_t));
		sock->async_receive(asio::buffer(buffer), [sock, &buffer, cb](const asio::error_code &err, std::size_t size) mutable {
			if (err) {
				cb(err);
				return;
			}
			
			if (size != sizeof(uint16_t)) {
				throw std::runtime_error("Invalid number of bytes read (response size)");
			}
			
			uint16_t len;
			std::copy(buffer.begin(), buffer.end(), reinterpret_cast<unsigned char*>(&len));
			
			len = ntohs(len);
			buffer.resize(len);
			
			sock->async_receive(asio::buffer(buffer), [sock, &buffer, cb, len](const asio::error_code &err, std::size_t size) mutable {
				if (err) {
					cb(err);
					return;
				}
				
				if (size != len) {
					throw std::runtime_error("Invalid number of bytes read (response data)");
				}
				
				cb({});
			});
		});
	});
}

void Resolver::sendQueryChain(std::shared_ptr<asio::ip::tcp::socket> sock, std::shared_ptr<ConnectionContext> ctx, MultiQueryCallback cb)
{
	ctx->buffer = this->wire(*ctx->it);
	this->sendQuery(sock, ctx->buffer, [=](const asio::error_code &err) mutable {
		if (err) {
			cb(err, {});
			return;
		}
		
		*(ctx->it) = this->unwire(ctx->buffer);
		++(ctx->it);
		if (ctx->it == ctx->pkts.end()) {
			cb({}, ctx->pkts);
			return;
		}
		
		this->sendQueryChain(sock, ctx, cb);
	});
}
