# SecureString
C++ implementation of the .NET SecureString
See https://learn.microsoft.com/en-us/dotnet/api/system.security.securestring

# Example

#include "SecureString.h"
#include "WinEncryptor.h"

int main(int argc, char *argv[])
{
	WinEncryptor enc;
	std::string str("hello world");
	SecureString<char> *ssc = new SecureString<char>(enc, str);
	ssc->append('!');

	std::cout << "the copy contains " << ssc->to_string() << std::endl;
	delete ssc;
	return 0;
}
