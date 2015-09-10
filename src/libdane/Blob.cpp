/**
 * Blob.cpp
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include <libdane/Blob.h>
#include <libdane/Util.h>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <stdexcept>

using namespace libdane;

Blob Blob::fromHex(const std::string &str)
{
	return from_hex(str.begin(), str.end());
}



Blob::Blob()
{
	
}

Blob::Blob(const unsigned char *data, unsigned int size):
	m_data(data, data + size)
{
	
}

Blob::Blob(const std::vector<unsigned char> &data):
	m_data(data)
{
	
}

Blob::Blob(const char *str):
	Blob(reinterpret_cast<const unsigned char*>(str), std::strlen(str))
{
	
}

Blob::~Blob()
{
	
}

bool Blob::operator==(const Blob &other) const
{
	return this->data() == other.data();
}



const std::vector<unsigned char>& Blob::data() const { return m_data; }
void Blob::setData(const std::vector<unsigned char> &v) { m_data = v; }



Blob Blob::sha256() const
{
	return this->hash(EVP_sha256());
}

Blob Blob::sha512() const
{
	return this->hash(EVP_sha512());
}

Blob Blob::match(MatchingType mtype) const
{
	return libdane::match(mtype, m_data.begin(), m_data.end());
}

std::string Blob::hex() const
{
	return to_hex(m_data.begin(), m_data.end());
}

Blob Blob::hash(const EVP_MD *type) const
{
	return libdane::hash(type, m_data.begin(), m_data.end());
}

std::ostream& libdane::operator<<(std::ostream& stream, const Blob &blob)
{
	std::ios::fmtflags flags = stream.flags();
	stream << std::hex << std::uppercase << std::setfill('0');
	
	stream << "Blob({";
	for (auto it = blob.data().begin(); it != blob.data().end(); ++it) {
		if (it != blob.data().begin()) {
			stream << ", ";
		}
		stream << "0x" << std::setw(2) << static_cast<int>(*it);
	}
	stream << "})";

	stream.flags(flags);
	return stream;
}
