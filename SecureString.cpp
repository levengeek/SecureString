/*
 * SecureString full explicit instantiation
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

#include "SecureString.h"


#ifdef SECURESTRING_EXPLICIT_INSTATIATION_CHAR
template class SecureString<char>;
#endif

#ifdef SECURESTRING_EXPLICIT_INSTATIATION_WCHAR_T
template class SecureString<wchar_t>;
#endif
