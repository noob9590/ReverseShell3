#include "Crypter.h"

bool Crypter::Hash(BCRYPT_ALG_HANDLE hAlg, PBYTE bytes, DWORD dwSize, std::vector<BYTE>& pbHashOut)
{

	//BCRYPT_ALG_HANDLE       hAlg = NULL;
	BCRYPT_HASH_HANDLE      hHash = NULL;
	NTSTATUS                status = STATUS_UNSUCCESSFUL;
	DWORD                   cbData = 0,
							cbHash = 0,
							cbHashObject = 0;
	PBYTE                   pbHashObject = NULL;

	////open an algorithm handle
	//if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
	//	&hAlg,
	//	BCRYPT_SHA256_ALGORITHM,
	//	NULL,
	//	0)))
	//{
	//	wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
	//	goto Cleanup;
	//}

	//calculate the size of the buffer to hold the hash object
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	//allocate the hash object on the heap
	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (NULL == pbHashObject)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
		goto Cleanup;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
		goto Cleanup;
	}


	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)bytes,
		dwSize,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
		goto Cleanup;
	}

	// resize the vector to the hash size
	pbHashOut.resize(cbHash);

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHashOut.data(),
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		goto Cleanup;
	}

	

Cleanup:

	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}


	return NT_SUCCESS(status);

}

std::optional<std::string> Crypter::Hash(BCRYPT_ALG_HANDLE hAlg, PBYTE bytes, DWORD dwSize)
{
	std::vector<BYTE> hash;

	if (not Hash(hAlg, bytes, dwSize, hash))
		return std::nullopt;

	return std::string(base64_encode(hash.data(), hash.size()));
}
