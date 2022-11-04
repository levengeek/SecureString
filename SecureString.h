/*
 * SecureString is a C++ implementation for the .NET SecureString
 * (https://referencesource.microsoft.com/#mscorlib/system/security/securestring.cs)
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

#ifndef SECURESTRING_H_
#define SECURESTRING_H_

/* C++ header files */
#include <string>
#include <atomic>
#include <mutex>
#include <cstring>
#include <type_traits>
#include <memory>
#include <cstdint>
#include <functional>
#include <cwchar>

/* project header files */
#include "Encryptor.h"
#include "SafeStringBuffer.h"
#include "SecureStringExceptions.h"

/**
 * SecureString is a C++ implementation for the .NET SecureString
 * (https://referencesource.microsoft.com/#mscorlib/system/security/securestring.cs)
 *
 * the implementation is thread-safe and protects against data-races via a lock
 *
 * this template essentially only allows instantiating wrappers for
 * std::string and std::wstring
 *
 * @param[in]	Char				the type of character (char, wchar_t) that
 * 									is used in the SecureString
 * @param[in]	ThrowsExceptions	true  - the SecureString throws exceptions
 * 									false - the SecureString returns error codes
 *
 * @notice		the class makes a distinction between "characters" and bytes -
 * 				the former being the number of Char elements in the SecureString
 *
 * @warning		the ThrowsExceptions parameter does not effect the behavior of
 * 				error handling in the constructors - those will ALWAYS throw
 * 				exceptions to indicate failure
 */
template <typename Char,
		  bool ThrowsExceptions = false,
		  typename std::enable_if<std::is_same<Char, char   >::value ||
		  	  	  	  	  	  	  std::is_same<Char, wchar_t>::value
											>::type* = nullptr
		 >
class SecureString final {
public:

	/**
	 * constructor
	 *
	 * @param[in]	encryptor	object deriving from the Encryptor class that
	 * 							will be used for the duration of the string for
	 * 							encryption and decryption
	 *
	 * @throw		SecureStringEncryptorException
	 *
	 */
	SecureString(Encryptor &encryptor) :
		m_num_Char(0), m_num_Char_allocated(0), m_data(nullptr),
		m_ro(false), m_encrypted(false),
		m_encryptor(encryptor)
	{
		static_assert(std::is_same<Char, char>::value ||
					 std::is_same<Char, wchar_t>::value);
		if (!m_encryptor.get().encryption_supported())
			throw SecureStringEncryptorException();
	}

	/**
	 * constructor
	 *
	 * @param[in]	encryptor	object deriving from the Encryptor class that
	 * 							will be used for the duration of the string for
	 * 							encryption and decryption
	 * @param[in]	str			NULL terminated C-style string to use for
	 * 							initializing the SecureString
	 *
	 * @throw		SecureStringEncryptorException
	 * @throw		SecureStringInitializationException
	 * @throw		SecureStringCapacityException
	 * @throw		SecureStringEncryptionException
	 */
	SecureString(Encryptor &encryptor, const Char *str) :
		SecureString(encryptor)
	{
		if (!str)
			throw SecureStringInitializationException();

		if constexpr (std::is_same<Char, char>::value)
			m_num_Char = strlen(str)/* + 1*/;
		else
			m_num_Char = wcslen(str)/* + 1*/;

		int err;
		err = ensure_capacity(m_num_Char);
		if (err)
			throw SecureStringCapacityException(m_num_Char);
		std::copy(str, str+m_num_Char, m_data);
		err = protect_memory();
		if (err)
			throw SecureStringEncryptionException(err);
	}

	/**
	 * constructor
	 *
	 * @param[in]	encryptor	object deriving from the Encryptor class that
	 * 							will be used for the duration of the string for
	 * 							encryption and decryption
	 * @param[in]	str			C++ std::string or stt::wstring to use for
	 * 							initializing the SecureString
	 *
	 * @throw		SecureStringEncryptorException
	 * @throw		SecureStringInitializationException
	 * @throw		SecureStringCapacityException
	 * @throw		SecureStringEncryptionException
	 */
	SecureString(Encryptor &encryptor, const std::basic_string<Char> &str) :
		SecureString(encryptor, str.c_str())
	{

	}

	/**
	 * copy constructor
	 *
	 * @throw		SecureStringCapacityException
	 */
	SecureString(SecureString &other) :
		m_data(nullptr), m_encryptor(other.m_encryptor)
	{
		std::lock_guard<std::mutex> guard(other.m_lock);
		m_num_Char = other.m_num_Char;
		m_num_Char_allocated = other.m_num_Char_allocated;
		m_ro = other.m_ro;
		m_encrypted = other.m_encrypted;

		m_data = new Char[m_num_Char_allocated];
		if (!m_data)
			throw SecureStringCapacityException(m_num_Char);
		std::copy(other.m_data, other.m_data+m_num_Char_allocated, m_data);
	}

	/**
	 * destructor
	 */
	~SecureString()
	{
		std::lock_guard<std::mutex> guard(m_lock);
		m_ro = false; // enables clear() to run
		protected_clear();
	}

	/* TODO: implement these */
	SecureString(SecureString &&other);
	SecureString& operator=(const SecureString &other);
	SecureString& operator=(SecureString &&other);

	/**
	 * @return		number of (wide) characters in SecureString
	 */
	inline size_t length() const noexcept
	{
		return m_num_Char;
	}

	/**
	 * @return		number of bytes in SecureString
	 */
	inline size_t size() const noexcept
	{
		return Char_to_bytes(m_num_Char);
	}

	/**
	 * make SecureString read only
	 *
	 * after calling this method, any modification to the SecureString is
	 * prohibited (other that destrying it)
	 */
	void make_ro() noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);
		m_ro = false;
	}

	/**
	 * check is SecureString is read only
	 *
	 * @return		true - SecureString is read only,
	 * 				false - SecureString is modifiable
	 */
	inline bool is_ro() const noexcept
	{
		return m_ro;
	}

	/**
	 * append a character the end end of the SecureString
	 *
	 * @param[in]	ch	charachter to append
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int append(const Char& ch)
	{
		std::lock_guard<std::mutex> guard(m_lock);
		int err;

		if (m_ro)
			return EPERM;

		err = unprotect_memory();
		if (err)
			return err;

		err = ensure_capacity(m_num_Char + 1);
		if (err)
			return err;

		m_data[m_num_Char++] = ch;
		return protect_memory();
	}

	/**
	 * insert a character at a specific location in SecureString
	 *
	 * this method results in a SecureString that is one character larger
	 *
	 * @param[in]	offset		offset into SecureString - may not be larger
	 * 							than the length of the SecureString
	 * @param[in]	ch			character to insert
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int insert_at(const size_t offset, const Char ch) noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);

		if (m_ro)
			return EPERM;

		if (offset >= m_num_Char)
			return E2BIG;

		int err = unprotect_memory();
		if (err)
			return err;

		ensure_capacity(m_num_Char + 1);
		for (size_t i = m_num_Char ; i >= offset + 1 ; --i)
			m_data[i] = m_data[i - 1];
		m_data[offset] = ch;
		return protect_memory();
	}

	/**
	 * overwrite a character at a specific location in SecureString
	 *
	 * this method doesn't change the length of the SecureString
	 *
	 * @param[in]	offset		offset into SecureString - may not be larger
	 * 							than the length of the SecureString
	 * @param[in]	ch			character to use for overwrite
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int set_at(const size_t offset, const Char ch) noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);

		if (m_ro)
			return EPERM;

		if (offset >= m_num_Char)
			return E2BIG;

		int err = unprotect_memory();
		if (err)
			return err;

		m_data[offset] = ch;
		return protect_memory();
	}

	/**
	 * remove a character from a specific location in SecureString
	 *
	 * this method results in a SecureString that is one character shorter
	 *
	 * @param[in]	offset		offset into SecureString - may not be larger
	 * 							than the length of the SecureString
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int remove_at(const size_t offset) noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);

		if (m_ro)
			return EPERM;

		if (offset >= m_num_Char)
			return E2BIG;

		int err = unprotect_memory();
		if (err)
			return err;

		for (size_t i = offset + 1 ; i < m_num_Char ; ++i)
			m_data[i - 1] = m_data[i];

		m_data[--m_num_Char] = static_cast<Char>('\0');
		return protect_memory();
	}

	/**
	 * clear SecureString contents
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int clear() noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);

		return protected_clear();
	}

	/**
	 * retrieve clear-text version of the SecureString
	 *
	 * @return		clear-text std::basic_string<>
	 *
	 * @warning		caller should check if the return value is empty. this may
	 * 				be an indication of an error
	 * @warning		caller should protect returned string from leaking unwanted
	 * 				clear-text information into the system
	 */
	std::basic_string<Char> to_string() noexcept
	{
		std::lock_guard<std::mutex> guard(m_lock);

		int err = unprotect_memory();
		if (err)
			return std::basic_string<Char>();

		Char *chr = new Char[m_num_Char + sizeof('\0')];
		if (!chr) {
			protect_memory();
			return std::basic_string<Char>();
		}

		std::copy(m_data, m_data+m_num_Char, chr);
		protect_memory();
		chr[m_num_Char] = static_cast<Char>('\0');
		std::basic_string<Char> ret(chr);
		std::fill(chr, chr+m_num_Char+1, static_cast<Char>('\0'));
		delete[]chr;
		return ret;
	}


	/**
	 * retrieve clear-text version of the SecureString
	 *
	 * @return		unique pointer to a SafeStringBuffer containing the
	 * 				clear-text std::basic_string<>
	 *
	 * @warning		caller should check if the return value is empty. this may
	 * 				be an indication of an error
	 */
	std::unique_ptr<SafeStringBuffer<Char>> to_safe_string() noexcept
	{
		// no need to guard this method, since all access to the object
		// will be done in tos_string()
		// std::lock_guard<std::mutex> guard(m_lock);

		return std::make_unique<SafeStringBuffer<Char>>(std::move(to_string()));
	}


private:

	/**
	 * use the Encryptor to encrypt the underlying array of characters
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int protect_memory()
	{
		if (m_encrypted || !m_data)
			return 0;

		int ret = m_encryptor.get().encrypt(static_cast<void *>(m_data), Char_to_bytes(m_num_Char_allocated), Encryptor::ACCESSIBLE_SAME_PROCESS);
		if (ret == 0)
			m_encrypted = true;
		return ret;
	}

	/**
	 * use the Encryptor to decrypt the underlying array of characters
	 *
	 * @return			0 if successful, otherwise error from <cerrno>
	 */
	int unprotect_memory()
	{
		if (!m_encrypted || !m_data)
			return 0;

		int ret = m_encryptor.get().decrypt(static_cast<void *>(m_data), Char_to_bytes(m_num_Char_allocated), Encryptor::ACCESSIBLE_SAME_PROCESS);
		if (ret == 0)
			m_encrypted = false;
		return ret;
	}

	/**
	 * translate the number of characters in the SecureString to the
	 * corresponding number of bytes to encrypt per the Encryptor's implementation
	 *
	 * @param[in]	num_Char	number of characters
	 *
	 * @return		number of required bytes per the Encryptor's implementation
	 */
	size_t encryptor_required_bytes(const size_t num_Char)
	{
		const size_t required = m_encryptor.get().block_size();
		if (num_Char == 0)
			return required;

		return ((Char_to_bytes(num_Char) + required - 1) / required) * required;
	}

	/**
	 * guarantee that the underlying array of characters is large enough to store
	 * the characters
	 *
	 * @param[in]	num_Char	number of characters
	 *
	 * @return		0 if successful, otherwise error from <cerrno>
	 */
	int ensure_capacity(const size_t num_Char)
	{
		const size_t required = encryptor_required_bytes(num_Char);
		const size_t exists = Char_to_bytes(m_num_Char_allocated);
		if (required <= exists)
			return 0;

		Char *data = new Char[bytes_to_Chars(required)];
		if (!data)
			return ENOMEM;
		if (m_data)
			std::copy(m_data, m_data+m_num_Char, data);

		discard_data();
		m_data = data;
		m_num_Char_allocated = bytes_to_Chars(required);
		return 0;
	}

	/**
	 * translate characters to bytes
	 *
	 * @param[in]	num_Chars	number of characters
	 *
	 * @return		number of bytes
	 */
	static inline size_t Char_to_bytes(const size_t &num_Chars)
	{
		return num_Chars * sizeof(Char);
	}

	/**
	 * translate bytes to characters
	 *
	 * @param[in]	num_bytes	number of bytes
	 *
	 * @return		number of characters
	 */
	static inline size_t bytes_to_Chars(const size_t &num_bytes)
	{
		return num_bytes / sizeof(Char);
	}

	/**
	 * clear all data from SecureString
	 *
	 * @warning		should only be called after the SecureString's lock
	 * 				is acquired
	 */
	int protected_clear() noexcept
	{
		if (m_ro)
			return EPERM;

		discard_data();
		m_num_Char = 0;
		m_num_Char_allocated = 0;
		m_encrypted = false;

		return 0;
	}

	/**
	 * safely release the underlying array of characters
	 *
	 * @warning		should only be called after the SecureString's lock
	 * 				is acquired
	 */
	void discard_data() noexcept
	{
		if (m_data) {
			std::fill(m_data, m_data+m_num_Char, static_cast<Char>('\0'));
			delete [] m_data;
			m_data = nullptr;
			m_num_Char_allocated = 0;
		}
	}

	/** lock protecting SecureString from data races */
	std::mutex	 m_lock;
	/** number of characters in SecureString */
	size_t		 m_num_Char;
	/** number of characters allocated in m_data */
	size_t		 m_num_Char_allocated;
	/** array of characters */
	Char 		*m_data;
	/** is SecureString read only */
	std::atomic<bool> m_ro;
	/** is m_data encrypted or clear-text */
	bool		 m_encrypted;
	/** reference to Encryptor */
	std::reference_wrapper<Encryptor>	m_encryptor;
};

#ifdef SECURESTRING_EXPLICIT_INSTATIATION_CHAR
extern template class SecureString<char>;
#endif

#ifdef SECURESTRING_EXPLICIT_INSTATIATION_WCHAR_T
extern template class SecureString<wchar_t>;
#endif

#endif /* SECURESTRING_H_ */
