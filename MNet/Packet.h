#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>

class Packet
{
private:

	uint32_t packetOffset = 0;

public:
	
	std::vector<char> buffer;

	void Clear();
	void Append(const void* data, uint32_t size);
	size_t PacketSize() const;
	uint32_t GetPacketOffset() const;

	void InsertInt(uint32_t data);
	int ExtractInt();

	void InsertString(const std::string& str);
	std::string ExtractString();
};

