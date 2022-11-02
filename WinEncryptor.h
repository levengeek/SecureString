/*
 * WinEncryptor.h
 *
 *  Created on: Oct 25, 2022
 *      Author: dovle
 */

#ifndef WINENCRYPTOR_H_
#define WINENCRYPTOR_H_

/* enable this file only when compiling for Windows */
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)

/* C++ header files */
#include <cstdlib>
#include <stdexcept>
#include <cerrno>

/* OS header files */
#include <windows.h>
#include <ntsecapi.h>
#include <dpapi.h>
#include <Wincrypt.h>
#include <ntstatus.h>

/* project header files */
#include "Encryptor.h"

/**
 * Windows encryption implementation for SecureString
 *
 * This implementation mimics the implementation in the .NET SecureString
 * (https://referencesource.microsoft.com/#mscorlib/system/security/securestring.cs)
 *
 * The implementation uses SystemFunction040() to encrypt and
 * SystemFunction041() to decrypt buffers
 */
class WinEncryptor : public Encryptor {
public:

	/**
	 * constructor - default implementation
	 */
	WinEncryptor()  = default;

	/**
	 * copy constructor - default implementation
	 */
	WinEncryptor(WinEncryptor&)  = default;

	/**
	 * move constructor - default implementation
	 */
	WinEncryptor(WinEncryptor&&)  = default;

	/**
	 * destructor - default implementation
	 */
	virtual ~WinEncryptor() = default;

	/**
	 * copy assignment - default implementation
	 */
	virtual WinEncryptor& operator=(WinEncryptor&)  = default;

	/**
	 * move assignment - default implementation
	 */
	virtual WinEncryptor& operator=(WinEncryptor&&)  = default;

	/**
	 * verification that encryption is supported on specific device
	 *
	 * testing is performed by attempting to encrypt a buffer.
	 *
	 * @return		true if supported, false if not supported
	 */
	virtual bool encryption_supported() const noexcept
	{
		void *ptr = malloc(block_size());
		if (!ptr)
			return false;

		bool ret = true;
		try {
			NTSTATUS sts = SystemFunction040(ptr,
								static_cast<ULONG>(block_size()),
								static_cast<ULONG>(CRYPTPROTECTMEMORY_SAME_PROCESS));
			ret = (sts == STATUS_SUCCESS);
		} catch (...) {
			ret = false;
		}
		free(ptr);
		return ret;
	}


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
						const encryption_flags flags) noexcept
	{
		if (num_bytes % block_size() != 0)
			return EMSGSIZE;

		if (SystemFunction040(buffer, num_bytes, static_cast<ULONG>(flags)) != STATUS_SUCCESS)
			return EOPNOTSUPP;

		return 0;
	}

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
						const encryption_flags flags) noexcept
	{
		if (num_bytes % block_size() != 0)
			return EMSGSIZE;

		if (SystemFunction041(buffer, num_bytes, static_cast<ULONG>(flags)) != STATUS_SUCCESS)
			return EOPNOTSUPP;

		return 0;
	}

	/**
	 * encryption block size [bytes] used by encryptor. all encryption and
	 * decryption buffers MUST be aligned to this size
	 *
	 * @return			block size
	 */
	virtual size_t block_size() const noexcept
	{
		return RTL_ENCRYPT_MEMORY_SIZE;
	}

};


#endif /* defined(_WIN32) || defined(__WIN32__) || defined(WIN32) */
#endif /* WINENCRYPTOR_H_ */
