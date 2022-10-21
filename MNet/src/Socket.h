#pragma once
// windows api
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment (lib, "Ws2_32.lib")

// std
#include <string>
#include <optional>
#include <iostream>

// custom
#include "Connection.h"


namespace MNet
{
	enum SocketOption
	{
		TCP_NoDelay //TRUE = disable nagle's algorithm
	};

	class Socket
	{
	private:
		SOCKET connSocket = INVALID_SOCKET;
		addrinfo connType { };
		bool SetSocketOptions(SocketOption option, BOOL value);

	public:

		Socket() = default;
		Socket(int addressFamily, int sockType, int sockProto);

		bool Create(bool setBlocking = true);
		bool Close();
		bool Bind(PCSTR port, PCSTR ip = NULL);
		bool SetBlocking(bool isBlocking);

		std::optional<std::tuple<SOCKET, std::string, std::string>> Accept();
		bool Connect(PCSTR ip, PCSTR port);

		SOCKET GetSocketHandle() const;
	};
}


