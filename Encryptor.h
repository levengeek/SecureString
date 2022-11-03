/*
 * Abstract base class for encryption implementations
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

#ifndef ENCRYPTOR_H_
#define ENCRYPTOR_H_

/* C++ header files */
#include <cstdint>

/**
 * abstract base class for encryption implementations
 *
 * all implementation are required to implement all functions only to the
 * extent necessary to support the C++ SecureString implementation
 */
struct Encryptor {

	enum encryption_flags : uint32_t {
		/**
		 * encrypted memory only accessible in the same process.
		 * applications running in a different process will not be able to
		 * decrypt the data
		 */
        ACCESSIBLE_SAME_PROCESS  = 0x00,
		/**
		 * encrypted memory only accessible in the same process.
		 * applications running in a different process will be able to
		 * decrypt the data
		 */
		ACCESSIBLE_CROSS_PROCESS = 0x01,
		/**
		 * encrypted memory accessible to any application running in a different
		 * process providing the process must run as the same user that
		 * encrypted the data and in the same logon session.
		 */
		ACCESSIBLE_SAME_LOGON    = 0x02,
	};

	/**
	 * constructor - default implementation
	 */
	Encryptor()  = default;

	/**
	 * copy constructor - default implementation
	 */
	Encryptor(Encryptor&)  = default;

	/**
	 * move constructor - default implementation
	 */
	Encryptor(Encryptor&&)  = default;

	/**
	 * destructor - default implementation
	 */
	virtual ~Encryptor() = default;

	/**
	 * copy assignment - default implementation
	 */
	virtual Encryptor& operator=(Encryptor&)  = default;

	/**
	 * move assignment - default implementation
	 */
	virtual Encryptor& operator=(Encryptor&&)  = default;


	/**
	 * verification that encryption is supported on specific device
	 *
	 * @return		true if supported, false if not supported
	 */
	virtual bool encryption_supported() const noexcept = 0;

	/**
	 * encrypt a buffer
	 *
	 * @param[inout]	buffer		buffer to encrypt.
	 * 								the buffer is overwritten by the encryptor
	 * @param[in]		num_bytes	number of bytes in the buffer. must be
	 * 								aligned to the return value from block_size()
	 * @param[in]		flags		flags to the encryptor
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	virtual int encrypt(void *buffer,
						const size_t num_bytes,
						const encryption_flags flags = ACCESSIBLE_SAME_PROCESS) noexcept = 0;

	/**
	 * decrypt a buffer
	 *
	 * @param[inout]	buffer		buffer to decrypt.
	 * 								the buffer is overwritten by the encryptor
	 * @param[in]		num_bytes	number of bytes in the buffer. must be
	 * 								aligned to the return value from block_size()
	 * @param[in]		flags		flags to the encryptor.
	 * 								MUST be the same as provided to encrypt()
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	virtual int decrypt(void *buffer,
						const size_t num_bytes,
						const encryption_flags flags = ACCESSIBLE_SAME_PROCESS) noexcept = 0;

	/**
	 * encryption block size [bytes] used by encryptor. all encryption and
	 * decryption buffers MUST be aligned to this size
	 *
	 * @return			block size
	 */
	virtual size_t block_size() const noexcept = 0;
};



#endif /* ENCRYPTOR_H_ */
