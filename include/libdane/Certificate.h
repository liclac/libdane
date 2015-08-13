#ifndef LIBDANE_X509_H
#define LIBDANE_X509_H

#include <asio/ssl.hpp>

namespace libdane
{
	class Certificate
	{
	public:
		Certificate(X509 *x509 = nullptr);
		virtual ~Certificate();
		
		X509 *x509() const;
		
		std::string subjectDN() const;
		std::string issuerDN() const;
		
		explicit operator bool() const { return m_x509 != nullptr; };
		
	protected:
		std::string nameStr(X509_NAME *name) const;
		
	private:
		X509 *m_x509;
	};
}

#endif
