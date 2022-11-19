#pragma once

// win api
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")

// std
#include <string>
#include <iostream>
#include <filesystem>
#include <fstream>

// custom
#include "Packet.h"
#include "Crypter.h"
#include "MResult.h"

#define BUFSIZE 8192

namespace MNet
{
	class Connection
	{
	private:

		SOCKET connSocket = INVALID_SOCKET;
		std::string ip;
		std::string port;

	public:

		Crypter Crypt;
		Connection() = default;
		Connection(SOCKET connSocket, std::string ip, std::string port);
		SOCKET GetClientSocket() const;
		const std::string& GetIp() const;
		const std::string& GetPort() const;

		M_Result Send(const void* data, int size, int& bytesSent);
		M_Result SendAll(void* data, int dataSize);
		M_Result Recv(void* buff, int buffSize, int& bytesReceived);
		M_Result RecvAll(void* data, int dataSize);
		M_Result SendPacket(Packet packet);
		M_Result RecvPacket(Packet& packet);
		
		M_Result SendFile(const std::string& path, uintmax_t filesize);
		M_Result RecvFile(const std::string& path, uintmax_t bytesToRead);
		void Close();
		
	};
}


