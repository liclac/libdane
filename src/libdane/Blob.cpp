#include <libdane/Blob.h>
#include <sstream>
#include <iomanip>

using namespace libdane;

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

Blob::~Blob()
{
	
}



const std::vector<unsigned char>& Blob::data() const { return m_data; }
void Blob::setData(const std::vector<unsigned char> &v) { m_data = v; }



std::string Blob::hex() const
{
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (auto it = m_data.begin(); it != m_data.end(); ++it) {
		ss << std::setw(2) << static_cast<int>(*it);
	}
	return ss.str();
}
