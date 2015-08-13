#ifndef LIBDANE_BLOB_H
#define LIBDANE_BLOB_H

#include <vector>

namespace libdane
{
	/**
	 * Container for operating on binary data.
	 */
	class Blob
	{
	public:
		/**
		 * Default constructor.
		 */
		Blob();
		
		/**
		 * Constructs a blob by copying existing data.
		 */
		Blob(const unsigned char *data, unsigned int size);
		
		/**
		 * Constructs a blob by copying existing data.
		 */
		Blob(const std::vector<unsigned char> &data);
		
		/**
		 * Destructor.
		 */
		virtual ~Blob();
		
		
		
		/**
		 * Returns a reference to the underlying data.
		 */
		const std::vector<unsigned char>& data() const;
		
		/**
		 * Sets the underlying data.
		 */
		void setData(const std::vector<unsigned char> &v);
		
		
		
		/**
		 * Returns the data as a hexadecimal string.
		 */
		std::string hex() const;
		
	private:
		std::vector<unsigned char> m_data;
	};
}

#endif
