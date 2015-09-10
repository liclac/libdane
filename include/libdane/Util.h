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
#include <algorithm>
#include <stdexcept>

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
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This is the most efficient, but possibly least convenient overload to
	 * use.
	 * 
	 * @param type Type of hash to calculate
	 * @param first An insert iterator in a container
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 */
	template<typename T, typename OutputIt>
	OutputIt hash(const EVP_MD *type, OutputIt first, typename std::vector<T>::const_iterator begin, typename std::vector<T>::const_iterator end)
	{
		auto ctx = std::shared_ptr<EVP_MD_CTX>(EVP_MD_CTX_create(), EVP_MD_CTX_destroy);
		
		if (!EVP_DigestInit(&*ctx, type)) {
			throw std::runtime_error("Failed to initialize a hash context");
		}
		
		if (!EVP_DigestUpdate(&*ctx, &*begin, std::distance(begin, end))) {
			throw std::runtime_error("Failed to feed data to the hash context; out of memory?");
		}
		
		unsigned char buf[EVP_MAX_MD_SIZE];
		unsigned int len;
		if (!EVP_DigestFinal(&*ctx, buf, &len)) {
			throw std::runtime_error("Failed to finalize the hash");
		}
		
		for (auto it = buf; it < buf + len; it++) {
			*first++ = *it;
		}
		
		return first;
	}
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This overload allows non-contigious iterators, by copying the data into
	 * a contigious container before use.
	 * 
	 * @param type Type of hash to calculate
	 * @param first An insert iterator in a container
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 */
	template<typename IterT, typename OutputIt>
	OutputIt hash(const EVP_MD *type, OutputIt first, IterT begin, IterT end)
	{
		typedef typename IterT::value_type T;
		std::vector<T> vec(begin, end);
		return hash<T>(type, first, vec.begin(), vec.end());
	}
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This is a convenience overload for one-line hash calculations.
	 * 
	 * @tparam T Value type for the container
	 * @param type Type of hash to calculate
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 */
	template<typename T = unsigned char, typename IterT>
	std::vector<T> hash(const EVP_MD *type, IterT begin, IterT end)
	{
		std::vector<T> vec;
		hash(type, vec.begin(), begin, end);
		return vec;
	}
	
	/**
	 * Matches data using a MatchingType.
	 * 
	 * @param type Matching type
	 * @param first An insert iterator into a container
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 */
	template<typename IterT, typename OutputIt>
	OutputIt match(MatchingType type, OutputIt first, IterT begin, IterT end)
	{
		switch (type) {
			case ExactMatch:
				return std::copy(begin, end, first);
			case SHA256Hash:
				return hash(EVP_sha256(), first, begin, end);
			case SHA512Hash:
				return hash(EVP_sha512(), first, begin, end);
			default:
				throw std::runtime_error("Unknown MatchingType");
		}
	}
	
	/**
	 * Matches data using a MatchingType.
	 * 
	 * This is a convenience overload to allow one-line matching.
	 * 
	 * @tparam T Value type for the container
	 * @param type Matching type
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 */
	template<typename T = unsigned char, typename IterT>
	std::vector<T> match(MatchingType type, IterT begin, IterT end)
	{
		std::vector<T> vec;
		match(type, std::back_inserter(vec), begin, end);
		return vec;
	}
}

#endif
