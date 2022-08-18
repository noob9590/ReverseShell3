#include "Additionals.h"


bool WinOpenFile(HANDLE& hFile, std::string& filename, bool createFile)
{
	hFile = ::CreateFileA(
		filename.c_str(),
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL, // default
		createFile ? CREATE_ALWAYS : OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		int error = GetLastError();
		std::cerr << "Error at CreateFile." << std::endl;
		return false;
	}
	
	return true;
}
