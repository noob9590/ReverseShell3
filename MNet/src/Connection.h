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

		bool Send(const void* data, int size, int& bytesSent);
		bool SendAll(void* data, int dataSize);
		bool Recv(void* buff, int buffSize, int& bytesReceived);
		bool RecvAll(void* data, int dataSize);
		bool SendPacket(Packet packet);
		bool RecvPacket(Packet& packet);
		
		bool SendFile(const std::string& path, uintmax_t filesize);
		bool RecvFile(const std::string& path, uintmax_t bytesToRead);
		bool Close();
		
	};
}


