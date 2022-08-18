#pragma once

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <iostream>
#include <cassert>
#include <filesystem>
#include "Packet.h"
#include "Additionals.h"

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

		Connection() {};
		Connection(SOCKET connSocket, std::string ip, std::string port);
		SOCKET GetClientSocket() const;
		const std::string& GetIp() const;
		const std::string& GetPort() const;

		bool Send(const void* data, int size, int& bytesSent);
		bool SendAll(void* data, int dataSize);
		bool Recv(void* buff, int buffSize, int& bytesReceived);
		bool RecvAll(void* data, int dataSize);
		bool Send(Packet packet);
		bool Recv(Packet& packet);
		
		bool SendFile(std::string& filename);
		bool RecvFile(std::string& filename, uint32_t filesize);
		bool Close();
		
	};
}


