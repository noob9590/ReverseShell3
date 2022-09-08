#pragma once
#include <Windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <optional>
#include "base64.h"


#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


class Crypter
{
	
	Crypter();
	~Crypter();

	static bool Hash(BCRYPT_ALG_HANDLE hAlg, PBYTE bytes, DWORD dwSize, std::vector<BYTE>& pbHashOut);
	static std::optional<std::string> Hash(BCRYPT_ALG_HANDLE hAlg, PBYTE bytes, DWORD dwSize);
	
};

