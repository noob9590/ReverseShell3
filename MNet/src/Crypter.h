#pragma once
#include <type_traits>
#include <cassert>
#include "Packet.h"
#include "..\..\includes\EasyBCrypt\EasyBCrypt.h"
#include "CrypterException.h"

namespace MNet 
{
	class Crypter
	{
	private:
		BCRYPT_ALG_HANDLE hAlg = NULL;
		std::vector<BYTE> keyBlob;
		

	public:
		Crypter() = default;
		Crypter(const std::vector<BYTE>& key);
		void Terminate();
		std::vector<BYTE> GenerateNonce();

		void EncryptPacket(Packet& packet);
		void DecryptPacket(Packet& packet);
	};

	//template<typename T>
	//inline void Crypter::EncryptPacket(Packet& packet, const T& plaintext)
	//{
	//	static_assert(std::is_same<T, std::string>::value || std::is_same<T, std::vector<BYTE>>::value,
	//		"The plaintext can only be passed via a std::vector<BYTE> or a std::string");

	//	// generate nonce for the packet
	//	std::vector<BYTE> nonce = GenerateNonce();
	//	std::vector<BYTE> authTag;

	//	// we encrypt as string even if a vector is passed
	//	std::string plaintextIn;
	//	std::string ciphertext;


	//	// check if we get vector.
	//	if (std::is_same<T, std::vector<BYTE>>::value)
	//		plaintextIn.assign(plaintext.begin(), plaintext.end());

	//	else
	//		plaintextIn = plaintext;
	//	
	//	
	//	auto optEncryption64 = EasyBCrypt::Encrypt64(this->hAlg, this->keyBlob, nonce, plaintextIn, &authTag);
	//	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optEncryption64))
	//	{
	//		std::string err = *(*out);
	//		throw std::runtime_error(err);
	//	}

	//	ciphertext = std::get<std::string>(optEncryption64);
	//	packet << ciphertext << nonce << authTag;
	//}
	//template<typename T>
	//inline void Crypter::DecryptPacket(Packet& packet, T& plaintext)
	//{
	//	static_assert(std::is_same<T, std::string>::value || std::is_same<T, std::vector<BYTE>>::value,
	//		"Decrypt64 can only return a std::string or a std::vector<BYTE>");

	//	std::vector<BYTE> nonce;
	//	std::vector<BYTE> authTag;
	//	std::string ciphertext;
	//	packet >> ciphertext >> nonce >> authTag;

	//	auto optDecryption64 = EasyBCrypt::Decrypt64(this->hAlg, this->keyBlob, nonce, ciphertext, &authTag);
	//	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optDecryption64))
	//	{
	//		std::string err = *(*out);
	//		throw std::runtime_error(err);
	//	}

	//	std::string& plaintextOut = std::get<std::string>(optDecryption64);

	//	if (std::is_same<T, std::string>::value)
	//		plaintext = std::move(plaintextOut);

	//	else
	//		T.assign(plaintextOut.begin(), plaintextOut.end());
	//}

}


