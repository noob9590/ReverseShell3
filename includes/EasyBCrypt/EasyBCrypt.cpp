#include "EasyBCrypt.h"

namespace EasyBCrypt
{
	std::optional<std::vector<BYTE>> EasyBCrypt::Hash(PBYTE bytes, DWORD dwSize)
	{
		;
		BCRYPT_ALG_HANDLE hAlgHash;
		BCRYPT_HASH_HANDLE hHash = NULL;
		NTSTATUS status = STATUS_UNSUCCESSFUL;
		DWORD cbData = 0, cbHash = 0, cbHashObject = 0;
		std::unique_ptr<BYTE[]> pbHashObject = NULL;
		std::vector<BYTE> pbHashOut;

		// Open an algorithm handle.
		if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(
			&hAlgHash,
			BCRYPT_SHA256_ALGORITHM,
			NULL,
			0)))
		{
			wprintf(L"**** Error returned by BCryptOpenAlgorithmProvider\n");
			ExitProcess(1);
		}

		//calculate the size of the buffer to hold the hash object
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlgHash,
			BCRYPT_OBJECT_LENGTH,
			reinterpret_cast<PBYTE>(&cbHashObject),
			sizeof(DWORD),
			&cbData,
			0)))
		{
			wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
			goto Cleanup;
		}

		//allocate the hash object on the heap
		pbHashObject = std::make_unique<BYTE[]>(cbHashObject);

		//calculate the length of the hash
		if (!NT_SUCCESS(status = BCryptGetProperty(
			hAlgHash,
			BCRYPT_HASH_LENGTH,
			reinterpret_cast<PBYTE>(&cbHash),
			sizeof(DWORD),
			&cbData,
			0)))
		{
			wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
			goto Cleanup;
		}

		//create a hash
		if (!NT_SUCCESS(status = BCryptCreateHash(
			hAlgHash,
			&hHash,
			pbHashObject.get(),
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
			reinterpret_cast<PBYTE>(bytes),
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

		if (hAlgHash)
		{
			BCryptCloseAlgorithmProvider(hAlgHash, 0);
		}

		if (hHash)
		{
			BCryptDestroyHash(hHash);
		}

		if (not NT_SUCCESS(status)) return std::nullopt;

		return pbHashOut;

	}

	std::optional<std::vector<BYTE>> EasyBCrypt::Hash(const std::string& str)
	{
		auto optHash = Hash(reinterpret_cast<PBYTE>(const_cast<char*>(str.data())), static_cast<DWORD>(str.size()));
		if (not optHash) return std::nullopt;

		return optHash.value();
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::GenerateRandomBytes(size_t sz)
	{
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		std::vector<BYTE> rndBytes(sz);

		nt_status = BCryptGenRandom(
			NULL,                                  // Alg Handle pointer; If NULL, the default provider is chosen
			reinterpret_cast<PBYTE>(&rndBytes[0]), // Address of the buffer that receives the random number(s)
			sz,                                    // Size of the buffer in bytes
			BCRYPT_USE_SYSTEM_PREFERRED_RNG);      // Flags 

		if (not NT_SUCCESS(nt_status))
			return std::make_shared<std::string>(std::format("GenerateRandomBytes: error returned from BCryptGenRandom. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status)));

		return rndBytes;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::KeyFromDerivation(BCRYPT_ALG_HANDLE KdfAlgHandle, const std::vector<BYTE>& key, PBCryptBufferDesc kdfParameters, WORD rounds /*= 128*/)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		BCRYPT_KEY_HANDLE hKey = NULL;
		ULONG ResultLength = 0;
		std::vector<BYTE> dKey;

		nt_status = BCryptGenerateSymmetricKey(
			KdfAlgHandle,                                                 // Algorithm Handle 
			&hKey,                                                        // A pointer to a key handle
			NULL,                                                         // Buffer that recieves the key object;NULL implies memory is allocated and freed by the function
			0,                                                            // Size of the buffer in bytes
			reinterpret_cast<PBYTE>(const_cast<unsigned char*>(&key[0])), // Buffer that contains the key material
			static_cast<ULONG>(key.size()),                               // Size of the buffer in bytes
			0);                                                           // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("KeyFromDerivation: error returned from BCryptGenerateSymmetricKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}
			

		//
		// Derive AES key from the password
		//

		dKey.resize(rounds / 8);

		nt_status = BCryptKeyDerivation(
			hKey,                                 // Handle to the password key
			kdfParameters,                        // Parameters to the KDF algorithm
			reinterpret_cast<PBYTE>(dKey.data()), // Address of the buffer which receives the derived bytes
			static_cast<ULONG>(dKey.size()),      // Size of the buffer in bytes
			&ResultLength,                        // Variable that receives number of bytes copied to above buffer  
			0);                                   // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("KeyFromDerivation: error returned from BCryptKeyDerivation. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
		}

	cleanup:
		// cleanup

		if (KdfAlgHandle)
			BCryptCloseAlgorithmProvider(KdfAlgHandle, 0);

		if (hKey)
			BCryptDestroyKey(hKey);

		if (not NT_SUCCESS(nt_status))
			return err;

		return dKey;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::CreateSymmetricKeyBlob(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& key, ChaningMode mode)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		BCRYPT_KEY_HANDLE hKey = NULL;
		DWORD			  cbBlob = 0;
		std::vector<BYTE> pbBlob;
		std::wstring chainingMode;

		// key alias
		PBYTE _key = const_cast<PBYTE>(&key[0]);
		DWORD _keySIze = static_cast<DWORD>(key.size());

		if (mode == ChaningMode::CBC)
			chainingMode = BCRYPT_CHAIN_MODE_CBC;
		else if (mode == ChaningMode::CFB)
			chainingMode = BCRYPT_CHAIN_MODE_CFB;
		else if (mode == ChaningMode::GCM)
			chainingMode = BCRYPT_CHAIN_MODE_GCM;
		else if (mode == ChaningMode::CCM)
			chainingMode = BCRYPT_CHAIN_MODE_CCM;
		else if (mode == ChaningMode::ECB)
			chainingMode = BCRYPT_CHAIN_MODE_ECB;
		else
			chainingMode = BCRYPT_CHAIN_MODE_NA;

		nt_status = BCryptSetProperty(
			hAlg,                                                               // Handle to a CNG object          
			BCRYPT_CHAINING_MODE,                                               // Property name(null terminated unicode string)
			reinterpret_cast<PBYTE>(const_cast<wchar_t*>(chainingMode.data())), // Address of the buffer that contains the new property value 
			static_cast<DWORD>((chainingMode.size() + 1) * sizeof(wchar_t)),    // Size of the buffer in bytes
			0);                                                                 // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("CreateSymmetricKeyBlob: error returned from BCryptSetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}
			

		nt_status = BCryptGenerateSymmetricKey(
			hAlg,      // Algorithm provider handle
			&hKey,     // A pointer to key handle
			NULL,      // A pointer to the buffer that recieves the key object;NULL implies memory is allocated and freed by the function
			0,         // Size of the buffer in bytes
			_key,      // A pointer to a buffer that contains the key material
			_keySIze,  // Size of the buffer in bytes
			0);        // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("CreateSymmetricKeyBlob: error returned from BCryptGenerateSymmetricKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			NULL,
			0,
			&cbBlob,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("CreateSymmetricKeyBlob: error returned from BCryptExportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}


		pbBlob.resize(cbBlob);

		nt_status = BCryptExportKey(
			hKey,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			&pbBlob[0],
			cbBlob,
			&cbBlob,
			0);
		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("CreateSymmetricKeyBlob: error returned from BCryptExportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
		}

	cleanup:

		if (hKey)
			BCryptDestroyKey(hKey);

		if (not NT_SUCCESS(nt_status))
			return err;

		return pbBlob;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::CreateAESKeyBlob(BCRYPT_ALG_HANDLE& hAlg, const std::vector<BYTE>& key, ChaningMode mode, const std::wstring& kdfAlgorithm, PBCryptBufferDesc kdfParameters /*= nullptr*/, WORD rounds /*= 128*/)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
		BCRYPT_ALG_HANDLE hKdf = NULL;
		std::vector<BYTE> _key = key;

		nt_status = BCryptOpenAlgorithmProvider(
			&hAlg,
			BCRYPT_AES_ALGORITHM,
			NULL,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("CreateAESKeyBlob: error returned from BCryptOpenAlgorithmProvider. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			return err;
		}

		if (kdfAlgorithm.size() > 0 and kdfParameters != nullptr)
		{
			nt_status = BCryptOpenAlgorithmProvider(
				&hKdf,
				kdfAlgorithm.data(),
				NULL,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("CreateAESKeyBlob: error returned from BCryptOpenAlgorithmProvider. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				return err;
			}

			auto optDerivedKey = KeyFromDerivation(hKdf, key, kdfParameters, rounds);

			if (auto out = std::get_if<STATUS>(&optDerivedKey))
				return optDerivedKey;

			_key = (std::get<std::vector<BYTE>>(std::move(optDerivedKey)));
		}

		auto optKeyBlob = CreateSymmetricKeyBlob(hAlg, _key, mode);

		return optKeyBlob;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::Encrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, std::vector<BYTE>* authTag)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		BCRYPT_KEY_HANDLE hKey = NULL;
		ULONG ciphertextLen = 0;
		ULONG res = 0;
		std::vector<BYTE> encryptedData;

		// chaining mode buffer
		WCHAR chainingMode[32] = { 0 };

		// pblob alias
		PBYTE _pbBlob = const_cast<PBYTE>(&pbBlob[0]);
		DWORD _cbBlob = static_cast<DWORD>(pbBlob.size());

		// plaintext alias
		PBYTE _pbPlaintext = reinterpret_cast<PBYTE>(const_cast<char*>(&plaintext[0]));
		DWORD _cbPlaintext = static_cast<DWORD>(plaintext.size());

		// IV alias
		PBYTE _pbIV = const_cast<PBYTE>(&IV[0]);
		DWORD _cbIV = static_cast<DWORD>(IV.size());

		nt_status = BCryptImportKey(
			hAlg,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			&hKey,
			NULL,
			0,
			_pbBlob,
			_cbBlob,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Encrypt: error returned from BCryptImportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		// calculate the size of aes mode string length
		nt_status = BCryptGetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			NULL,
			0,
			&res,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Encrypt: error returned from BCryptGetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		// get the chaining mode string
		nt_status = BCryptGetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			reinterpret_cast<PBYTE>(&chainingMode[0]),
			res,
			&res,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Encrypt: error returned from BCryptGetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		if (wcsncmp(BCRYPT_CHAIN_MODE_GCM, chainingMode, res) == 0 or \
			wcsncmp(BCRYPT_CHAIN_MODE_CCM, chainingMode, res) == 0)
		{
			// when the chain mode is gcm or ccm the user must provide an authTag vector
			if (not authTag)
			{
				nt_status = STATUS_UNSUCCESSFUL;
				*err = std::format("Encrypt: With GCM/CCM mode you must provide authTag vector. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			BCRYPT_AUTH_TAG_LENGTHS_STRUCT authTagLengths;
			nt_status = BCryptGetProperty(hAlg,
				BCRYPT_AUTH_TAG_LENGTH,
				(PBYTE)&authTagLengths,
				sizeof(authTagLengths),
				&res,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptGetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
			BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

			authInfo.pbNonce = _pbIV; // pointer to the nonce
			authInfo.cbNonce = _cbIV; // the size of the nonce

			std::vector<BYTE>& _authTag = *authTag;
			_authTag.clear();
			_authTag.resize(authTagLengths.dwMinLength);

			authInfo.pbTag = &_authTag[0]; // receive the auth tag when encrypting data
			authInfo.cbTag = _authTag.size(); // the size of the buffer


			nt_status = BCryptEncrypt(hKey,
				_pbPlaintext,
				_cbPlaintext,
				&authInfo,
				NULL,
				0,
				NULL,
				0,
				&ciphertextLen,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			encryptedData.resize(ciphertextLen);

			nt_status = BCryptEncrypt(hKey,
				_pbPlaintext,
				_cbPlaintext,
				&authInfo,
				NULL,
				0,
				reinterpret_cast<PBYTE>(&encryptedData[0]),
				ciphertextLen,
				&res,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

		}

		else if (wcsncmp(BCRYPT_CHAIN_MODE_CFB, chainingMode, res) == 0 or \
				 wcsncmp(BCRYPT_CHAIN_MODE_CBC, chainingMode, res) == 0 )
		{
			std::unique_ptr<BYTE[]> copyIV = std::make_unique<BYTE[]>(IV.size());
			PBYTE					pbCopyIV = copyIV.get();

			memcpy(pbCopyIV, _pbIV, _cbIV);

			nt_status = BCryptEncrypt(
				hKey,                 // Handle to a key which is used to encrypt 
				_pbPlaintext,         // Address of the buffer that contains the plaintext
				_cbPlaintext,         // Size of the buffer in bytes
				NULL,                 // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
				pbCopyIV,             // Address of the buffer that contains the IV. 
				_cbIV,                // Size of the IV buffer in bytes
				NULL,                 // Address of the buffer the receives the ciphertext
				0,                    // Size of the buffer in bytes
				&ciphertextLen,       // Variable that receives number of bytes copied to ciphertext buffer 
				BCRYPT_BLOCK_PADDING);// Flags; Block padding allows to pad data to the next block size

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			encryptedData.resize(ciphertextLen);

			nt_status = BCryptEncrypt(
				hKey,                                       // Handle to a key which is used to encrypt 
				_pbPlaintext,                               // Address of the buffer that contains the plaintext
				_cbPlaintext,                               // Size of the buffer in bytes
				NULL,                                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
				pbCopyIV,                                   // Address of the buffer that contains the IV. 
				_cbIV,                                      // Size of the IV buffer in bytes
				reinterpret_cast<PBYTE>(&encryptedData[0]), // Address of the buffer the receives the ciphertext
				ciphertextLen,                              // Size of the buffer in bytes
				&res,                                       // Variable that receives number of bytes copied to ciphertext buffer 
				BCRYPT_BLOCK_PADDING);                      // Flags; Block padding allows to pad data to the next block size

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}
		}

		else
		{
			nt_status = BCryptEncrypt(
				hKey,                   // Handle to a key which is used to encrypt 
				_pbPlaintext,           // Address of the buffer that contains the plaintext
				_cbPlaintext,           // Size of the buffer in bytes
				NULL,                   // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
				NULL,                   // Address of the buffer that contains the IV. 
				0,                      // Size of the IV buffer in bytes
				NULL,                   // Address of the buffer the receives the ciphertext
				0,                      // Size of the buffer in bytes
				&ciphertextLen,         // Variable that receives number of bytes copied to ciphertext buffer 
				BCRYPT_BLOCK_PADDING);  // Flags; Block padding allows to pad data to the next block size

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			encryptedData.resize(ciphertextLen);

			nt_status = BCryptEncrypt(hKey,
				_pbPlaintext,
				_cbPlaintext,
				NULL,
				NULL,
				0,
				reinterpret_cast<PBYTE>(&encryptedData[0]),
				ciphertextLen,
				&res,
				BCRYPT_BLOCK_PADDING);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Encrypt: error returned from BCryptEncrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}
		}


	cleanup:
		// cleanup
		if (hKey)
			BCryptDestroyKey(hKey);

		if (not NT_SUCCESS(nt_status))
			return err;

		return encryptedData;
	}

	std::variant<STATUS, std::string> EasyBCrypt::Decrypt(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::vector<BYTE>& ciphertext, std::vector<BYTE>* authTag)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		BCRYPT_KEY_HANDLE hKey = NULL;
		ULONG plaintextLength = 0;
		ULONG res = 0;
		std::string	decryptedData;

		// chaining mode buffer
		WCHAR chainingMode[32] = { 0 };

		// pblob alias
		PBYTE _pbBlob = const_cast<PBYTE>(&pbBlob[0]);
		DWORD _cbBlob = static_cast<DWORD>(pbBlob.size());

		// ciphertext alias
		PBYTE _pbCiphertext = reinterpret_cast<PBYTE>(const_cast<PBYTE>(&ciphertext[0]));
		DWORD _cbCiphertext = static_cast<DWORD>(ciphertext.size());

		// IV alias
		PBYTE _pbIV = const_cast<PBYTE>(&IV[0]);
		DWORD _cbIV = static_cast<DWORD>(IV.size());

		nt_status = BCryptImportKey(
			hAlg,
			NULL,
			BCRYPT_OPAQUE_KEY_BLOB,
			&hKey,
			NULL,
			0,
			_pbBlob,
			_cbBlob,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Decrypt: error returned from BCryptImportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		// calculate the size of aes mode string length
		nt_status = BCryptGetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			NULL,
			0,
			&res,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Decrypt: error returned from BCryptGetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		// get the chaining mode string
		nt_status = BCryptGetProperty(
			hAlg,
			BCRYPT_CHAINING_MODE,
			reinterpret_cast<PBYTE>(&chainingMode[0]),
			res,
			&res,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("Decrypt: error returned from BCryptGetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		if (wcsncmp(BCRYPT_CHAIN_MODE_GCM, chainingMode, res) == 0 or \
			wcsncmp(BCRYPT_CHAIN_MODE_CCM, chainingMode, res) == 0)
		{
			// when the chain mode is gcm or ccm the user must provide an authTag vector
			if (not authTag)
			{
				nt_status = STATUS_UNSUCCESSFUL;
				*err = std::format("Decrypt: With GCM/CCM mode you must provide authTag vector. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
			BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

			authInfo.pbNonce = _pbIV; // pointer to the nonce
			authInfo.cbNonce = _cbIV; // the size of the nonce

			std::vector<BYTE>& _authTag = *authTag;

			authInfo.pbTag = &_authTag[0]; // receive the auth tag when encrypting data
			authInfo.cbTag = _authTag.size(); // the size of the buffer

			nt_status = BCryptDecrypt(
				hKey,
				_pbCiphertext,
				_cbCiphertext,
				&authInfo,
				NULL,
				0,
				NULL,
				0,
				&plaintextLength,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			decryptedData.resize(plaintextLength);

			nt_status = BCryptDecrypt(
				hKey,
				_pbCiphertext,
				_cbCiphertext,
				&authInfo,
				NULL,
				0,
				reinterpret_cast<PBYTE>(&decryptedData[0]),
				plaintextLength,
				&res,
				0);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}
		}

		else if (wcsncmp(BCRYPT_CHAIN_MODE_CFB, chainingMode, res) == 0 or \
				 wcsncmp(BCRYPT_CHAIN_MODE_CBC, chainingMode, res) == 0)
		{
			std::unique_ptr<BYTE[]> copyIV = std::make_unique<BYTE[]>(IV.size());
			PBYTE					pbCopyIV = copyIV.get();

			memcpy(pbCopyIV, _pbIV, _cbIV);

			nt_status = BCryptDecrypt(
				hKey,                  // Handle to a key which is used to encrypt 
				_pbCiphertext,         // Address of the buffer that contains the ciphertext
				_cbCiphertext,         // Size of the buffer in bytes
				NULL,                  // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
				pbCopyIV,              // Address of the buffer that contains the IV. 
				_cbIV,                 // Size of the IV buffer in bytes
				NULL,                  // Address of the buffer the recieves the plaintext
				0,                     // Size of the buffer in bytes
				&plaintextLength,      // Variable that recieves number of bytes copied to plaintext buffer 
				BCRYPT_BLOCK_PADDING);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			decryptedData.resize(plaintextLength);

			nt_status = BCryptDecrypt(
				hKey,                                       // Handle to a key which is used to encrypt 
				_pbCiphertext,                              // Address of the buffer that contains the ciphertext
				_cbCiphertext,                              // Size of the buffer in bytes
				NULL,                                       // A pointer to padding info, used with asymmetric and authenticated encryption; else set to NULL
				pbCopyIV,                                   // Address of the buffer that contains the IV. 
				_cbIV,                                      // Size of the IV buffer in bytes
				reinterpret_cast<PBYTE>(&decryptedData[0]), // Address of the buffer the receives the plaintext
				plaintextLength,                            // Size of the buffer in bytes
				&res,                                       // Variable that receives number of bytes copied to plaintext buffer 
				BCRYPT_BLOCK_PADDING);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));

				if (nt_status == 0xC000003E)
					*err = std::format("Decrypt: An error occurred in reading or writing data. Probably due to an incorrect IV or key. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));

				goto cleanup;
			}
		}

		else
		{
			nt_status = BCryptDecrypt(
				hKey,
				_pbCiphertext,
				_cbCiphertext,
				NULL,
				NULL,
				0,
				NULL,
				0,
				&plaintextLength,
				BCRYPT_BLOCK_PADDING);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}

			decryptedData.resize(plaintextLength);

			nt_status = BCryptDecrypt(
				hKey,
				_pbCiphertext,
				_cbCiphertext,
				NULL,
				NULL,
				0,
				reinterpret_cast<PBYTE>(&decryptedData[0]),
				plaintextLength,
				&res,
				BCRYPT_BLOCK_PADDING);

			if (not NT_SUCCESS(nt_status))
			{
				*err = std::format("Decrypt: error returned from BCryptDecrypt. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
				goto cleanup;
			}
		}
		
	cleanup:
		// cleanup
		if (hKey)
			BCryptDestroyKey(hKey);

		if (not NT_SUCCESS(nt_status))
			return err;

		decryptedData.resize(res);
		decryptedData.shrink_to_fit();

		return decryptedData;
	}

	std::variant<STATUS, std::string> EasyBCrypt::Encrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& plaintext, std::vector<BYTE>* authTag)
	{
		auto optEncryption = Encrypt(hAlg, pbBlob, IV, plaintext, authTag);
		if (auto out = std::get_if<STATUS>(&optEncryption))
		{
			return *out;
		}

		std::vector<BYTE> out = std::get<std::vector<BYTE>>(std::move(optEncryption));
		return base64_encode(out.data(), out.size(), false);
	}

	std::variant<STATUS, std::string> EasyBCrypt::Decrypt64(BCRYPT_ALG_HANDLE hAlg, const std::vector<BYTE>& pbBlob, const std::vector<BYTE>& IV, const std::string& ciphertext, std::vector<BYTE>* authTag)
	{

		std::string ciphertext64 = base64_decode(ciphertext, false);
		auto optDecryption = Decrypt(hAlg, pbBlob, IV, std::vector<BYTE>(ciphertext64.begin(), ciphertext64.end()), authTag);
		return optDecryption;
	}

	std::shared_ptr<BYTE[]> EasyBCrypt::CreateDHParamBlob(DWORD keyLength, const std::vector<BYTE>& dhPrime, const std::vector<BYTE>& dhGenerator)
	{
		PBYTE m_dhPrime;
		PBYTE m_dhGenerator;
		DWORD m_dhPrimeSize;
		DWORD m_dhGeneratorSize;

		DWORD dhParamBlobLen;
		std::shared_ptr<BYTE[]> dhBlob;
		BCRYPT_DH_PARAMETER_HEADER* DhParamHdrPointer;

		// use the default prime and generator if no prime and generator are passed.
		// there is no problem of reusing them since anyway everybody can see them.
		if (dhPrime.size() == 0 or dhGenerator.size() == 0)
		{
			m_dhPrime = const_cast<BYTE*>(OakleyGroup1P);
			m_dhGenerator = const_cast<BYTE*>(OakleyGroup1G);
			m_dhPrimeSize = sizeof(OakleyGroup1P);
			m_dhGeneratorSize = sizeof(OakleyGroup1G);
		}
		else
		{
			m_dhPrime = const_cast<PBYTE>(dhPrime.data());
			m_dhGenerator = const_cast<PBYTE>(dhGenerator.data());
			m_dhPrimeSize = static_cast<DWORD>(dhPrime.size());
			m_dhGeneratorSize = static_cast<DWORD>(dhGenerator.size());
		}

		dhParamBlobLen = sizeof(BCRYPT_DH_PARAMETER_HEADER) + m_dhPrimeSize + m_dhGeneratorSize;
		dhBlob = std::make_shared<BYTE[]>(dhParamBlobLen);

		DhParamHdrPointer = reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER*>(dhBlob.get());
		DhParamHdrPointer->cbLength = dhParamBlobLen;
		DhParamHdrPointer->cbKeyLength = keyLength / 8;
		DhParamHdrPointer->dwMagic = BCRYPT_DH_PARAMETERS_MAGIC;

		memcpy(dhBlob.get() + sizeof(BCRYPT_DH_PARAMETER_HEADER), m_dhPrime, m_dhPrimeSize);
		memcpy(dhBlob.get() + sizeof(BCRYPT_DH_PARAMETER_HEADER) + m_dhPrimeSize, m_dhGenerator, m_dhGeneratorSize);

		return dhBlob;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::GenerateDHKeyPair(std::shared_ptr<BYTE[]> dhParams, BCRYPT_ALG_HANDLE& exchAlgHandle, BCRYPT_KEY_HANDLE& dhKeyHandle)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		DWORD keyLength  = reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER*>(dhParams.get())->cbKeyLength * 8;
		DWORD pubBlobLen = 0;
		std::vector<BYTE> pubBlob;

		nt_status = BCryptOpenAlgorithmProvider(
			&exchAlgHandle,
			BCRYPT_DH_ALGORITHM,
			NULL,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptOpenAlgorithmProvider. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptGenerateKeyPair(
			exchAlgHandle,              // Algorithm handle
			&dhKeyHandle,               // Key handle - will be created
			keyLength,                  // Length of the key - in bits
			0);                         // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptGenerateKeyPair. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptSetProperty(
			dhKeyHandle,
			BCRYPT_DH_PARAMETERS,
			dhParams.get(),
			reinterpret_cast<BCRYPT_DH_PARAMETER_HEADER*>(dhParams.get())->cbLength,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptSetProperty. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptFinalizeKeyPair(
			dhKeyHandle,                 // Key handle
			0);                          // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptFinalizeKeyPair. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptExportKey(
			dhKeyHandle,               // Handle of the key to export
			NULL,                      // Handle of the key used to wrap the exported key
			BCRYPT_DH_PUBLIC_BLOB,     // Blob type (null terminated unicode string)
			NULL,                      // Buffer that receives the key blob
			0,                         // Buffer length (in bytes)
			&pubBlobLen,               // Number of bytes copied to the buffer
			0);                        // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptExportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		pubBlob.resize(pubBlobLen);

		nt_status = BCryptExportKey(
			dhKeyHandle,               // Handle of the key to export
			NULL,                      // Handle of the key used to wrap the exported key
			BCRYPT_DH_PUBLIC_BLOB,     // Blob type (null terminated unicode string)
			&pubBlob[0],               // Buffer that receives the key blob
			pubBlobLen,                // Buffer length (in bytes)
			&pubBlobLen,               // Number of bytes copied to the buffer
			0);                        // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHKeyPair: error returned from BCryptExportKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
		}


	cleanup:
		// cleanup if one of the functions is failed.
		if (not NT_SUCCESS(nt_status))
		{
			if (exchAlgHandle)
				BCryptCloseAlgorithmProvider(exchAlgHandle, 0);

			if (dhKeyHandle)
				BCryptDestroyKey(dhKeyHandle);

			return err;
		}

		return pubBlob;
	}

	std::variant<STATUS, std::vector<BYTE>> EasyBCrypt::GenerateDHSecret(BCRYPT_ALG_HANDLE exchAlgHandle, BCRYPT_KEY_HANDLE dhKeyHandle, std::vector<BYTE>& alicePubBlob, const std::wstring& pwszKDF, PBCryptBufferDesc kdfParameters /*= nullptr*/)
	{
		STATUS err = std::make_shared<std::string>();
		NTSTATUS nt_status = STATUS_UNSUCCESSFUL;

		BCRYPT_KEY_HANDLE PubKeyHandleA = NULL;
		BCRYPT_SECRET_HANDLE secretAgreement = NULL;
		std::vector<BYTE> secret;
		DWORD secrentLength = 0;

		nt_status = BCryptImportKeyPair(
			exchAlgHandle,               // Alg handle
			NULL,                        // Parameter not used
			BCRYPT_DH_PUBLIC_BLOB,       // Blob type (Null terminated unicode string)
			&PubKeyHandleA,              // Key handle that will be recieved
			&alicePubBlob[0],            // Buffer than points to the key blob
			static_cast<ULONG>(alicePubBlob.size()), // Buffer length in bytes
			0);                          // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHSecret: error returned from BCryptImportKeyPair. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptCloseAlgorithmProvider(
			exchAlgHandle,
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHSecret: error returned from BCryptCloseAlgorithmProvider. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptSecretAgreement(
			dhKeyHandle,          // Private key handle
			PubKeyHandleA,        // Public key handle
			&secretAgreement,     // Handle that represents the secret agreement value
			0);

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHSecret: error returned from BCryptSecretAgreement. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}

		nt_status = BCryptDeriveKey(
			secretAgreement,       // Secret agreement handle
			&pwszKDF[0],           // Key derivation function (null terminated unicode string)
			kdfParameters,         // KDF parameters
			NULL,                  // Buffer that recieves the derived key 
			0,                     // Length of the buffer
			&secrentLength,        // Number of bytes copied to the buffer
			0);                    // Flags

		if (not NT_SUCCESS(nt_status))
		{
			*err = std::format("GenerateDHSecret: error returned from BCryptDeriveKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
			goto cleanup;
		}


		secret.resize(secrentLength);

		nt_status = BCryptDeriveKey(
			secretAgreement,      // Secret agreement handle
			&pwszKDF[0],          // Key derivation function (null terminated unicode string)
			kdfParameters,        // KDF parameters
			&secret[0],           // Buffer that receives the derived key 
			secrentLength,        // Length of the buffer
			&secrentLength,       // Number of bytes copied to the buffer
			0);

		{
			*err = std::format("GenerateDHSecret: error returned from BCryptDeriveKey. NTSATUS code: {:#x}", static_cast<unsigned long>(nt_status));
		}

	cleanup:

		// cleanup
		if (PubKeyHandleA)
			BCryptDestroyKey(PubKeyHandleA);

		if (dhKeyHandle)
			BCryptDestroyKey(dhKeyHandle);

		if (secretAgreement)
			BCryptDestroySecret(secretAgreement);

		if (not NT_SUCCESS(nt_status))
			err;

		return secret;
	}

}
