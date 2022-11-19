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
#include "MResult.h"


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
		M_Result SetSocketOptions(SocketOption option, BOOL value);

	public:

		Socket() = default;
		Socket(int addressFamily, int sockType, int sockProto);

		M_Result Create(bool setBlocking = true);
		void Close();
		M_Result Bind(PCSTR port, PCSTR ip = NULL);
		M_Result SetBlocking(bool isBlocking);

		std::optional<std::tuple<SOCKET, std::string, std::string>> Accept();
		M_Result Connect(PCSTR ip, PCSTR port);

		SOCKET GetSocketHandle() const;
	};
}


