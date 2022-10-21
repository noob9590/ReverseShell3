#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>
#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <format>
#include <memory>
#include "base64.h"
#pragma comment( lib, "bcrypt.lib" )

#include <iostream>

namespace EasyBCrypt
{

	inline void PrintBytes(
		IN BYTE* pbPrintData,
		IN DWORD    cbDataLen)
	{
		DWORD dwCount = 0;

		for (dwCount = 0; dwCount < cbDataLen; dwCount++)
		{
			printf("0x%02x, ", pbPrintData[dwCount]);

			if (dwCount + 1 % 32 == 0)
				std::cout << std::endl;
		}
		std::cout << std::endl;

	}

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

	
	typedef std::shared_ptr<std::string> STATUS;

	enum ChaningMode : UINT8
	{
		CBC,
		CFB,
		GCM,
		CCM,
		ECB,
		NA
	};

	inline void ReportError(_In_ DWORD dwErrCode)
	{
		if (not NT_SUCCESS(dwErrCode))
			wprintf(L"Error: 0x%08x (%d)\n", dwErrCode, dwErrCode);
	}

	// prime number
	static
		const
		BYTE OakleyGroup1P[] =
	{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f,
		0xda, 0xa2, 0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b,
		0x80, 0xdc, 0x1c, 0xd1, 0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67,
		0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6, 0x3b, 0x13, 0x9b, 0x22,
		0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd, 0xef, 0x95,
		0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
		0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51,
		0xc2, 0x45, 0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6,
		0xf4, 0x4c, 0x42, 0xe9, 0xa6, 0x3a, 0x36, 0x20, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	// generator
	static
		const
		BYTE OakleyGroup1G[] =
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02
	};

	std::optional<std::vector<BYTE>> Hash(PBYTE bytes, DWORD dwSize);
	std::optional<std::vector<BYTE>> Hash(const std::string& str);

	std::variant<STATUS, std::vector<BYTE>>GenerateRandomBytes(size_t sz);

	std::variant<STATUS, std::vector<BYTE>> KeyFromDerivation(BCRYPT_ALG_HANDLE KdfAlgHandle, const std::vector<BYTE>& key, PBCryptBufferDesc kdfParameters = nullptr, WORD rounds = 128);
	std::variant<STATUS, std::vector<BYTE>> CreateSymmetricKeyBlob(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& key, ChaningMode mode);
	std::variant<STATUS, std::vector<BYTE>> CreateAESKeyBlob(BCRYPT_ALG_HANDLE& hAlg, const std::vector<BYTE>& key, ChaningMode mode, const std::wstring& kdfAlgorithm = L"", PBCryptBufferDesc kdfParameters = nullptr, WORD rounds = 128);

	std::variant<STATUS, std::vector<BYTE>> Encrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, std::vector<BYTE>* authTag = nullptr);
	std::variant<STATUS, std::string> Decrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::vector<BYTE>& ciphertext, std::vector<BYTE>* authTag = nullptr);

	std::variant<STATUS, std::string> Encrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, std::vector<BYTE>* authTag = nullptr);
	std::variant<STATUS, std::string> Decrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& ciphertext, std::vector<BYTE>* authTag = nullptr);

	std::shared_ptr<BYTE[]> CreateDHParamBlob(DWORD keyLength = 768, const std::vector<BYTE>& dhPrime = {}, const std::vector<BYTE>& dhGenerator = {});
	std::variant<STATUS, std::vector<BYTE>> GenerateDHKeyPair(std::shared_ptr<BYTE[]> dhParams, BCRYPT_ALG_HANDLE& exchAlgHandle, BCRYPT_KEY_HANDLE& dhKeyHandle);
	std::variant<STATUS, std::vector<BYTE>> GenerateDHSecret(BCRYPT_ALG_HANDLE exchAlgHandle, BCRYPT_KEY_HANDLE dhKeyHandle, std::vector<BYTE>& alicePubBlob, const std::wstring& pwszKDF = BCRYPT_KDF_RAW_SECRET, PBCryptBufferDesc kdfParameters = nullptr);

}