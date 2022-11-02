/*
* SecureString.cpp
*
*  Created on: Oct 25, 2022
*      Author: dovle
*/

#include "SecureString.h"


#ifdef SECURESTRING_EXPLICIT_INSTATIATION_CHAR
template class SecureString<char>;
#endif

#ifdef SECURESTRING_EXPLICIT_INSTATIATION_WCHAR_T
template class SecureString<wchar_t>;
#endif
