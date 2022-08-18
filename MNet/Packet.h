#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <vector>
#include <string>
#include "PacketType.h"

namespace MNet
{
	class Packet
	{
	private:
		uint32_t packetOffset = 0;

	public:
		std::vector<BYTE> buffer;

		Packet(PacketType packetType = PacketType::Invalid);

		void Clear(PacketType packetType = PacketType::Invalid);
		void Append(const void* data, uint32_t size);

		size_t PacketSize() const;
		uint32_t GetPacketOffset() const;

		const PacketType GetPacketType();
		void SetPacketType(PacketType packetType);

		void InsertInt(uint32_t data);
		int ExtractInt();

		void InsertString(const std::string& str);
		std::string ExtractString();

		void InsertBytes(std::vector<BYTE> bytes);
		std::vector<BYTE> ExtractBytes();

	};
}
