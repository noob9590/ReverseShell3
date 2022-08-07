#pragma once

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <iostream>


namespace MNet
{
	class Connection
	{
	private:

		SOCKET connSocket;
		std::string ip;
		std::string port;

	public:

		//ClientInfo(const char* ip, const char* port);

		Connection() {};
		Connection(SOCKET connSocket, std::string ip, std::string port);
		SOCKET GetClientSocket() const;
		const std::string& GetIp() const;
		const std::string& GetPort() const;

		bool Send(const void* data, int size, int& bytesSent);
		bool SendAll(void* data, int dataSize);
		bool Recv(void* buff, int buffSize, int& bytesReceived);
		bool RecvAll(void* data, int dataSize);
		bool Close();
		
	};
}


