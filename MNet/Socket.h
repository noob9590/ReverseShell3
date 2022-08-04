#pragma once
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iostream>
#include <optional>
#include "SocketOption.h"
#include "ClientInfo.h"
#pragma comment (lib, "Ws2_32.lib")

namespace MNet
{
	class Socket
	{
	private:
		SOCKET connSocket = INVALID_SOCKET;
		addrinfo connType;

		bool InitGetAddrInfo(PCSTR ip, PCSTR port, addrinfo*& StrcConnect);
		bool SetSocketOptions(SocketOption option, BOOL value);

	public:

		Socket(int addressFamily, int sockType, int sockProto);
		~Socket();

		bool Create();
		bool Close();
		bool Connect(PCSTR ip, PCSTR port);
		bool Bind(PCSTR port, PCSTR ip = NULL);
		bool Accept(ClientInfo& acceptedClient);

		SOCKET GetSocketHandle() const;
	};
}


