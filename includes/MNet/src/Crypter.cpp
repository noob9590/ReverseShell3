#include "Crypter.h"

MNet::Crypter::Crypter(const std::vector<BYTE>& key)
{
	int rounds = key.size() * 8;
	auto optAESKeyBlob = EasyBCrypt::CreateAESKeyBlob(this->hAlg, key, EasyBCrypt::GCM, L"", nullptr, rounds);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optAESKeyBlob))
	{
		std::string err = *(*out);
		throw CrypterException("[Crypter::Crypter(const std::vector<BYTE>& key)] - " + err);
	}

	keyBlob = std::get<std::vector<BYTE>>(optAESKeyBlob);
}

void MNet::Crypter::Terminate()
{
	if (hAlg != NULL)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
		hAlg = NULL;
	}

	this->keyBlob.clear();
}

std::vector<BYTE> MNet::Crypter::GenerateNonce()
{

	auto optNonce = EasyBCrypt::GenerateRandomBytes(12);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optNonce))
	{
		std::string err = *(*out);
		throw CrypterException("[Crypter::GenerateRandomBytes()] - " + err);
	}

	return std::get<std::vector<BYTE>>(optNonce);
}

void MNet::Crypter::EncryptPacket(Packet& packet)
{
	std::vector<BYTE> authTag;
	std::vector<BYTE> nonce = GenerateNonce();
	std::string packetContent(packet.buffer.begin(), packet.buffer.end());

	auto optEncryption64 = EasyBCrypt::Encrypt64(this->hAlg, this->keyBlob, nonce, packetContent, &authTag);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optEncryption64))
	{
		std::string err = *(*out);
		throw CrypterException("[Crypter::EncryptPacket(Packet& packet)] - " + err);
	}

	packetContent = std::get<std::string>(optEncryption64);

	// create packet that contains encrypted packet, nonce and authentication tag
	packet.Clear();
	packet << packetContent << nonce << authTag;
}

void MNet::Crypter::DecryptPacket(Packet& packet)
{
	std::vector<BYTE> nonce;
	std::vector<BYTE> authTag;
	std::string packetContent;

	packet >> packetContent >> nonce >> authTag;
	packet.Clear(packet.GetPacketType());

	auto optDecryption64 = EasyBCrypt::Decrypt64(this->hAlg, this->keyBlob, nonce, packetContent, &authTag);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optDecryption64))
	{
		std::string err = *(*out);
		throw CrypterException("[Crypter::DecryptPacket(Packet& packet)] - " + err);
	}

	// extract the decrypted packet and re-assign the pakcet buffer 
	packetContent = std::get<std::string>(optDecryption64);
	packet.buffer.assign(packetContent.begin(), packetContent.end());
}
