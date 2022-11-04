/*
 * Exceptions thrown by SecureString
 *
 * (C) Copyright Dov Levenglick 2022
 *
 * Use, modification and distribution are subject to the
 * Unlicense Software License (See accompanying file LICENSE or copy at
 * https://github.com/levengeek/SecureString/blob/main/LICENSE)
 *
 *  Created on: 2022-11-04
 *      Author: Dov Levenglick
 */

#ifndef SECURESTRINGEXCEPTIONS_H_
#define SECURESTRINGEXCEPTIONS_H_

#include <stdexcept>

/**
 * exception thrown to indicate that the the Encryptor does not support
 * the required operations required by SecureString
 */
struct SecureStringEncryptorException : public std::invalid_argument {
	/**
	 * constructor
	 */
	SecureStringEncryptorException() :
		std::invalid_argument("Encryptor can't be used")
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringEncryptorException() = default;
};

/**
 * exception thrown to indicate an encryption error
 */
struct SecureStringEncryptionException : public std::runtime_error {
	/**
	 * constructor
	 *
	 * @param[in]	err		error code
	 */
	explicit SecureStringEncryptionException(const int err) :
		std::runtime_error("Ecryptor encryption returned "  + std::to_string(err))
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringEncryptionException() = default;
};

/**
 * exception thrown to indicate an decryption error
 */
struct SecureStringDecryptionException : public std::runtime_error {
	/**
	 * constructor
	 *
	 * @param[in]	err		error code
	 */
	explicit SecureStringDecryptionException(const int err) :
		std::runtime_error("Ecryptor decryption returned "  + std::to_string(err))
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringDecryptionException() = default;
};

/**
 * exception thrown to indicate that the SecureString is being constructed
 * with an empty string
 */
struct SecureStringInitializationException : public std::invalid_argument {
	SecureStringInitializationException() :
		std::invalid_argument("Illegal (empty string) initialization")
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringInitializationException() = default;
};

/**
 * exception thrown to indicate a memory allocation error
 */
struct SecureStringCapacityException : public std::runtime_error {
	/**
	 * constructor
	 *
	 * @param[in]	size	number of bytes that failed to allocate
	 */
	explicit SecureStringCapacityException(const size_t size) :
		std::runtime_error("Not enough memory to allocate " + std::to_string(size) + " bytes")
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringCapacityException() = default;
};

/**
 * exception thrown to indicate write operations on a read-only SecureString
 */
struct SecureStringReadOnlyException : public std::runtime_error {
	/**
	 * constructor
	 */
	SecureStringReadOnlyException() : std::runtime_error("SecureString is read only")
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringReadOnlyException() = default;
};

/**
 * exception thrown to indicate accessing an out-of-range offset in the SecureString
 */
struct SecureStringOffsetException: public std::out_of_range {
	/**
	 * constructor
	 *
	 * @param[in]	offset	offset to access
	 * @param[in]	size	size of SecureString
	 */
	SecureStringOffsetException(const size_t offset, const size_t size) :
		std::out_of_range("Offset " + std::to_string(offset) + " is larger than " + std::to_string(size - 1))
	{

	}

	/**
	 * destructor
	 */
	virtual ~SecureStringOffsetException() = default;
};

#endif /* SECURESTRINGEXCEPTIONS_H_ */
