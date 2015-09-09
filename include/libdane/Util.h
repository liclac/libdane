/**
 * Util.h
 * libdane
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#ifndef LIBDANE_UTIL_H
#define LIBDANE_UTIL_H

#include "VerifyContext.h"
#include "DANERecord.h"
#include <sstream>
#include <iomanip>
#include <iterator>
#include <memory>

namespace libdane
{
	/**
	 * Verifies a VerifyContext against a list of DANERecords.
	 */
	template<typename IterT>
	inline bool verify(bool preverified, const VerifyContext &ctx, IterT begin, IterT end)
	{
		for (IterT it = begin; it != end; ++it) {
			const DANERecord &rec = *it;
			if (rec.verify(preverified, ctx)) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Converts a sequence into a hexadecimal string.
	 * 
	 * @tparam T     Type to cast values through
	 * @param  begin Begin iterator
	 * @param  end   End iterator
	 * @return A hexadecimal string
	 */
	template<typename T = unsigned char, typename IterT>
	inline std::string to_hex(IterT begin, IterT end)
	{
		std::stringstream ss;
		ss << std::hex << std::setfill('0');
		for (auto it = begin; it != end; ++it) {
			ss << std::setw(2) << static_cast<unsigned int>(static_cast<T>(*it));
		}
		return ss.str();
	}
	
	/**
	 * Decodes a hexadecimal string.
	 * 
	 * @tparam T     Type to cast values through
	 * @param  first An insert iterator into a container
	 * @param  begin Iterator to the start of the string
	 * @param  end   Iterator to the end of the string
	 * @return Iterator past the last element inserted, or first if no elements were inserted
	 */
	template<typename T = unsigned char, typename OutputIt, typename StringIt>
	inline OutputIt from_hex(OutputIt first, StringIt begin, StringIt end)
	{
		auto it = begin;
		while (it != end) {
			std::stringstream ss;
			ss << std::hex << *it++;
			if (it != end) {
				ss << std::hex << *it++;
			} else {
				ss << '0' << *it;
			}
			
			unsigned int tmp;
			ss >> tmp;
			*first++ = static_cast<T>(tmp);
		}
		
		return first;
	}
	
	/**
	 * Decodes a hexadecimal string.
	 * 
	 * This is a convenience function for decoding straight into a newly
	 * constructed container.
	 * 
	 * @tparam T Type to cast values through
	 * @tparam ContainerT Container type to fill up
	 * @param begin Iterator to the start of the string
	 * @param end Iterator to the end of the string
	 * @return A new ContainerT with the decoded data
	 */
	template<typename T = unsigned char, typename ContainerT = std::vector<unsigned char>, typename StringIt>
	inline ContainerT from_hex(StringIt begin, StringIt end)
	{
		ContainerT container;
		container.reserve(std::distance(begin, end) / 2);
		from_hex<T>(std::back_inserter(container), begin, end);
		return container;
	}
}

#endif
