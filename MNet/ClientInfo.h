#pragma once

#define WIN32_LEAN_AND_MEAN
#include <ws2tcpip.h>
#include <windows.h>
#include <string>
#include <iostream>


namespace MNet
{
	class ClientInfo
	{
	private:

		SOCKET cliSocket = INVALID_SOCKET;
		std::string ip;
		std::string port;

	public:

		//ClientInfo(const char* ip, const char* port);

		ClientInfo() {};
		ClientInfo(SOCKET acceptedCliSocket, sockaddr_in strcCliInfo);
		SOCKET GetClientSocket() const;
		const std::string& GetIp() const;
		const std::string& GetPort() const;
		
	};
}


