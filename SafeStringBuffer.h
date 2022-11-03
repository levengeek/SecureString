/*
 * Non-copyable and non-assignable wrapper for std::basic_string<>
 * with safe release
 *
 * (C) Copyright Dov Levenglick 2022
 *
 * Use, modification and distribution are subject to the
 * Unlicense Software License (See accompanying file LICENSE or copy at
 * https://github.com/levengeek/SecureString/blob/main/LICENSE)
 *
 *  Created on: 2022-10-25
 *      Author: Dov Levenglick
 */

#ifndef SAFESTRINGBUFFER_H_
#define SAFESTRINGBUFFER_H_

/* C++ header files */
#include <string>
#include <algorithm>
#include <type_traits>


/**
 * SafeStringBuffer implements a non-copyable and non-assignable wrapper for
 * std::basic_string<> that automatically overwrites its contents prior to
 * releasing the underlying object upon destruction.
 *
 * this implementation guards the clear-text versions of a SecureStrings, by
 * making sure that their values don't remain in memory after discarding the
 * underlying std::basic_string<>.
 *
 * this template essentially only allows instantiating wrappers for
 * std::string and std::wstring.
 */
template <typename Char,
		  typename std::enable_if<std::is_same<Char, char   >::value ||
		  	  	  	  	  	  	  std::is_same<Char, wchar_t>::value
											>::type* = nullptr
		 >
class SafeStringBuffer final {
public:

	/**
	 * constructor that copies the input string into a local member
	 *
	 * @param[in]	str		string to protect
	 *
	 * @warning		the class does not protect the input string, only the
	 * 				local member
	 */
	explicit SafeStringBuffer(const std::basic_string<Char> &str) :
		m_string(str)
	{

	}

	/**
	 * destrcutor
	 *
	 * overwrites the member's content prior to releasing the object
	 */
	~SafeStringBuffer()
	{
		std::fill(m_string.begin(), m_string.end(), static_cast<Char>('\0'));
	}

	/**
	 * @return		reference to the wrapped std::basic_string<>
	 */
	const std::basic_string<Char>& string() const noexcept
	{
		return m_string;
	}


	/**
	 * @return		reference to the wrapped std::basic_string<>
	 */
	const std::basic_string<Char>& operator()() const noexcept
	{
		return m_string;
	}

	/**
	 * disable copy construction
	 */
	SafeStringBuffer(SafeStringBuffer&) = delete;

	/**
	 * disable move construction
	 */
	SafeStringBuffer(SafeStringBuffer&&) = delete;

	/**
	 * disable copy assignment
	 */
	SafeStringBuffer& operator=(SafeStringBuffer&) = delete;

	/**
	 * disable move assignment
	 */
	SafeStringBuffer& operator=(SafeStringBuffer&&) = delete;


private:

	/** wrapped string */
	std::basic_string<Char> m_string;
};



#endif /* SAFESTRINGBUFFER_H_ */
