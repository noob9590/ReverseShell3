#pragma once
// windows api
#include <windows.h> // the vector will be changed to char them this include will be removed

// std
#include <string>
#include <vector>

// custom
#include "PacketException.h"

namespace MNet
{
	enum PacketType : uint16_t
	{
		Invalid,
		request,
		response
	};

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

		Packet& operator << (uint32_t data);
		Packet& operator >> (uint32_t& data);

		Packet& operator << (const std::string& str);
		Packet& operator >> (std::string& str);

		Packet& operator << (const std::vector<BYTE>& bytes);
		Packet& operator >> (std::vector<BYTE>& bytes);

	};
}
