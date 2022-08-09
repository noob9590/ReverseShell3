#include "Packet.h"

void Packet::Clear()
{
	buffer.clear();
	packetOffset = 0;
}

void Packet::Append(const void* data, uint32_t size)
{
	buffer.insert(buffer.end(), (char*)data, (char*)data + size);
}

size_t Packet::PacketSize() const
{
	return buffer.size();
}

uint32_t Packet::GetPacketOffset() const
{
	return packetOffset;
}

void Packet::InsertInt(uint32_t data)
{
	data = htonl(data);
	Append(&data, sizeof(uint32_t));
}

int Packet::ExtractInt()
{
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
	std::string str;
	str.resize(strSize);
	str.assign(buffer.data() + packetOffset, strSize);
	packetOffset += strSize;
	return str;
}
