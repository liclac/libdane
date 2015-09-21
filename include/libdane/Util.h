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
	 * Converts a sequence into a hexadecimal string.
	 * 
	 * @tparam T    Type to cast values through
	 * @param  data Data container
	 */
	template<typename T = unsigned char, typename ContainerT>
	inline std::string to_hex(const ContainerT &data)
	{
		return to_hex<T>(data.begin(), data.end());
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
	template<typename T = unsigned char, typename ContainerT = std::vector<T>, typename StringIt>
	inline ContainerT from_hex(StringIt begin, StringIt end)
	{
		ContainerT container;
		from_hex<T>(std::back_inserter(container), begin, end);
		return container;
	}
	
	/**
	 * Decodes a hexadecimal string.
	 * 
	 * This is a convenience function for decoding a string straight into a
	 * newly constructed container.
	 * 
	 * @tparam T Type to cast values through
	 * @tparam ContainerT Container type to fill up
	 * @tparam CharT Underlying character type
	 * @param str String to decode
	 * @return A new ContainerT with the decoded data
	 */
	template<typename T = unsigned char, typename ContainerT = std::vector<T>, typename CharT>
	inline ContainerT from_hex(const std::basic_string<CharT> &str)
	{
		return from_hex<T>(str.begin(), str.end());
	}
	
	/**
	 * Decodes a hexadecimal string.
	 * 
	 * This is a convenience function for decoding a string straight into a
	 * newly constructed container.
	 * 
	 * @tparam T Type to cast values through
	 * @tparam ContainerT Container type to fill up
	 * @tparam CharT Underlying character type
	 * @param str String to decode
	 * @return A new ContainerT with the decoded data
	 */
	template<typename T = unsigned char, typename ContainerT = std::vector<T>, typename CharT>
	inline ContainerT from_hex(const CharT *str)
	{
		if (str == nullptr) {
			return ContainerT();
		}
		
		return from_hex<T, ContainerT, CharT>(std::basic_string<CharT>(str));
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
	inline OutputIt hash(const EVP_MD *type, OutputIt first, typename std::vector<T>::const_iterator begin, typename std::vector<T>::const_iterator end)
	{
		if (type == nullptr) {
			return std::copy(begin, end, first);
		}
		
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
		
		return std::copy(buf, buf + len, first);
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
	inline OutputIt hash(const EVP_MD *type, OutputIt first, IterT begin, IterT end)
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
	inline std::vector<T> hash(const EVP_MD *type, IterT begin, IterT end)
	{
		std::vector<T> vec;
		hash(type, std::back_inserter(vec), begin, end);
		return vec;
	}
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This is a convenience overload for one-line hash calculations.
	 * 
	 * @tparam T Value type for the container
	 * @param type Type of hash to calculate
	 * @param vec Vector of data to hash
	 */
	template<typename T = unsigned char>
	inline std::vector<T> hash(const EVP_MD *type, const std::vector<T> &vec)
	{
		return hash(type, vec.begin(), vec.end());
	}
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This is a convenience overload for one-line hash calculations.
	 * 
	 * @tparam T Value type for the container
	 * @tparam CharT Underlying character type
	 * @param type Type of hash to calculate
	 * @param str String to hash
	 */
	template<typename T = unsigned char, typename CharT>
	inline std::vector<T> hash(const EVP_MD *type, const std::basic_string<CharT> &str)
	{
		return hash<T>(type, str.begin(), str.end());
	}
	
	/**
	 * Calculates a hash of the given data.
	 * 
	 * This is a convenience overload for one-line hash calculations.
	 * 
	 * @tparam T Value type for the container
	 * @tparam CharT Underlying character type
	 * @param type Type of hash to calculate
	 * @param str String to hash
	 */
	template<typename T = unsigned char, typename CharT>
	inline std::vector<T> hash(const EVP_MD *type, const CharT *str)
	{
		if (str == nullptr) {
			str = "";
		}
		
		return hash<T, CharT>(type, std::basic_string<CharT>(str));
	}
	
	/**
	 * Returns an EVP_MD from the given matching type.
	 * 
	 * @param  type Matching type
	 * @return      An EVP_MD, or nullptr for ExactMatch
	 * @throws      std::runtime_error for an invalid type
	 */
	inline const EVP_MD *md_from_matching_type(MatchingType type)
	{
		switch (type) {
			case ExactMatch:
				return nullptr;
			case SHA256Hash:
				return EVP_sha256();
			case SHA512Hash:
				return EVP_sha512();
			default:
				throw std::runtime_error("Unknown MatchingType");
		}
	}
	
	/**
	 * Matches data using a MatchingType.
	 * 
	 * @param type Matching type
	 * @param first An insert iterator into a container
	 * @param begin Iterator to the start of the data
	 * @param end Iterator to the end of the data
	 * @throws std::runtime_error for an invalid type
	 */
	template<typename IterT, typename OutputIt>
	inline OutputIt match(MatchingType type, OutputIt first, IterT begin, IterT end)
	{
		const EVP_MD *md = md_from_matching_type(type);
		return hash(md, first, begin, end);
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
	 * @throws std::runtime_error for an invalid type
	 */
	template<typename T = unsigned char, typename IterT>
	inline std::vector<T> match(MatchingType type, IterT begin, IterT end)
	{
		std::vector<T> vec;
		match(type, std::back_inserter(vec), begin, end);
		return vec;
	}
	
	/**
	 * Matches data using a MatchingType.
	 * 
	 * This is a convenience overload to allow one-line matching.
	 * 
	 * @tparam T Value type for the container
	 * @tparam CharT Underlying character type
	 * @param type Matching type
	 * @param str String to match
	 * @throws std::runtime_error for an invalid type
	 */
	template<typename T = unsigned char, typename CharT>
	inline std::vector<T> match(MatchingType type, const std::basic_string<CharT> &str)
	{
		return match<T>(type, str.begin(), str.end());
	}
	
	/**
	 * Matches data using a MatchingType.
	 * 
	 * This is a convenience overload to allow one-line matching.
	 * 
	 * @tparam T Value type for the container
	 * @tparam CharT Underlying character type
	 * @param type Matching type
	 * @param str String to match
	 * @throws std::runtime_error for an invalid type
	 */
	template<typename T = unsigned char, typename CharT>
	inline std::vector<T> match(MatchingType type, const CharT *str)
	{
		return match<T, CharT>(type, std::basic_string<CharT>(str));
	}
}

#endif
