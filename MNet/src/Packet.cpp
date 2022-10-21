#include "Packet.h"

namespace MNet
{
	Packet::Packet(PacketType packetType)
	{
		Clear(packetType);
	}

	void Packet::Clear(PacketType packetType)
	{
		buffer.clear();
		buffer.resize(sizeof(PacketType));
		SetPacketType(packetType);
		packetOffset = sizeof(PacketType);
	}

	void Packet::Append(const void* data, uint32_t size)
	{
		buffer.insert(buffer.end(), (BYTE*)data, (BYTE*)data + size);
	}

	size_t Packet::PacketSize() const
	{
		return buffer.size();
	}

	uint32_t Packet::GetPacketOffset() const
	{
		return packetOffset;
	}

	const PacketType Packet::GetPacketType()
	{
		PacketType* PTRpacketType = reinterpret_cast<PacketType*>(&buffer[0]);
		return static_cast<PacketType>(ntohs(*PTRpacketType));
	}

	void Packet::SetPacketType(PacketType packetType)
	{
		PacketType* PTRpacketType = reinterpret_cast<PacketType*>(&buffer[0]);
		*PTRpacketType = static_cast<PacketType>(htons(packetType));
	}

	void Packet::InsertInt(uint32_t data)
	{
		data = htonl(data);
		Append(&data, sizeof(uint32_t));
	}

	int Packet::ExtractInt()
	{
		if (sizeof(uint32_t) + packetOffset > buffer.size())
			throw PacketException("[Packet::ExtractInt()] - exceeded the buffer size.");

		uint32_t data = *reinterpret_cast<uint32_t*>(buffer.data() + packetOffset);
		data = ntohl(data);
		packetOffset += sizeof(uint32_t);
		return data;
	}

	void Packet::InsertString(const std::string& str)
	{
		InsertInt((uint32_t)str.size());
		Append(str.data(), str.size());
	}

	std::string Packet::ExtractString()
	{
		uint32_t strSize = ExtractInt();

		if (strSize + packetOffset > buffer.size())
			throw PacketException("[Packet::ExtractString()] - exceeded the buffer size.");

		std::string str;
		str.resize(strSize);
		str.assign((char*)buffer.data() + packetOffset, strSize);
		packetOffset += strSize;
		return str;
	}

	void Packet::InsertBytes(std::vector<BYTE> bytes)
	{
		InsertInt((uint32_t)bytes.size());
		Append(bytes.data(), bytes.size());
	}

	std::vector<BYTE> Packet::ExtractBytes()
	{
		std::vector<BYTE> bytes;
		uint32_t bytesBufferSize = ExtractInt();

		if (bytesBufferSize + packetOffset > buffer.size())
			throw PacketException("[Packet::ExtractBytes()] - exceeded the buffer size.");

		bytes.reserve(bytesBufferSize);
		bytes.insert(bytes.begin(), &buffer[0] + packetOffset, &buffer[0] + packetOffset + bytesBufferSize);
		packetOffset += bytesBufferSize;
		return bytes;
	}
	
	Packet& Packet::operator << (uint32_t data)
	{
		InsertInt(data);
		return *this;
	}

	Packet& Packet::operator >> (uint32_t& data)
	{
		data = ExtractInt();
		return *this;
	}

	Packet& Packet::operator << (const std::string& str)
	{
		InsertString(str);
		return *this;
	}

	Packet& Packet::operator >> (std::string& str)
	{
		str = ExtractString();
		return *this;
	}

	Packet& Packet::operator << (const std::vector<BYTE>& bytes)
	{
		InsertBytes(bytes);
		return *this;
	}

	Packet& Packet::operator >> (std::vector<BYTE>& bytes)
	{
		bytes = ExtractBytes();
		return *this;
	}
}