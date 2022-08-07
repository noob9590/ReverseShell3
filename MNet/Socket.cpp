#include "Socket.h"

namespace MNet
{
	bool Socket::InitGetAddrInfo(PCSTR ip, const PCSTR port, struct addrinfo*& StrcConnect)
	{
		int status;
		status = getaddrinfo(ip, port, &connType, &StrcConnect);
		if (status != 0)
		{
			std::cerr << "InitGetAddrInfo Error." << std::endl;
			return false;
		}
		return true;
	}

	Socket::Socket(int addressFamily, int sockType, int sockProto)
	{
		ZeroMemory(&connType, sizeof(connType));
		connType.ai_family = addressFamily;
		connType.ai_socktype = sockType;
		connType.ai_protocol = sockProto;
		connType.ai_flags = AI_PASSIVE;
	}

	Socket::~Socket()
	{
		Close();
	}

	SOCKET Socket::GetSocketHandle() const
	{
		return connSocket;
	}

	bool Socket::Create(bool setBlocking)
	{
		connSocket = WSASocket(connType.ai_family, connType.ai_socktype, connType.ai_protocol, NULL, 0, 0);
		if (connSocket == INVALID_SOCKET)
		{
			return false;
		}

		if (not SetBlocking(setBlocking))
		{
			std::cerr << "SetBlocking Error." << std::endl;
			return false;
		}

		if (not SetSocketOptions(SocketOption::TCP_NoDelay, TRUE))
		{
			std::cerr << "SetSocketOptions Error." << std::endl;
			return false;
		}

		return true;
	}

	bool Socket::Close()
	{
		if (connSocket == INVALID_SOCKET)
		{
			throw std::runtime_error("Try to close INVALID_SOCKET");
			return false;
		}
		if (closesocket(connSocket) != 0)
		{
			std::cerr << "Close Error: %d" << WSAGetLastError() << std::endl;
			return false;
		}

		connSocket = INVALID_SOCKET;
		return true;
	}

	bool Socket::Connect(PCSTR ip, PCSTR port)
	{
		int status;
		addrinfo* connect;

		if (not InitGetAddrInfo(ip, port, connect))
		{
			return false;
		}

		status = WSAConnect(connSocket, connect->ai_addr, (int)connect->ai_addrlen, 0, 0, 0, 0);

		freeaddrinfo(connect);

		if (status == SOCKET_ERROR)
		{
			return false;
		}
		return true;
	}

	bool Socket::SetSocketOptions(SocketOption option, BOOL value)
	{
		int status = 0;
		switch (option)
		{
		case SocketOption::TCP_NoDelay:
			status = setsockopt(connSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&value, sizeof(value));
			break;

		default:
			return false;
		}

		if (status != 0)
		{
			return false;
		}
		return true;
	}

	bool Socket::Bind(PCSTR port, PCSTR ip)
	{
		int status;
		addrinfo* connect;

		if (not InitGetAddrInfo(ip, port, connect))
		{
			return false;
		}

		status = bind(connSocket, connect->ai_addr, (int)connect->ai_addrlen);

		freeaddrinfo(connect);

		if (status == SOCKET_ERROR)
		{
			return false;
		}

		status = listen(connSocket, SOMAXCONN);
		if (status == INVALID_SOCKET)
		{
			return false;
		}

		return true;
	}

	std::optional<std::tuple<SOCKET, std::string, std::string>> Socket::Accept()
	{
		char ip[INET_ADDRSTRLEN];
		sockaddr_in strcCliInfo;
		int strcCliInfoLen = sizeof(strcCliInfo);

		SOCKET cliSocket = WSAAccept(connSocket, (SOCKADDR*)&strcCliInfo, &strcCliInfoLen, 0, 0);

		int port = ntohs(strcCliInfo.sin_port);
		inet_ntop(AF_INET, &strcCliInfo.sin_addr, ip, INET_ADDRSTRLEN);

		if (cliSocket == INVALID_SOCKET)
		{
			return { };
		}

		return { {cliSocket, std::string(ip), std::to_string(port) } };
	}

	bool Socket::SetBlocking(bool isBlocking)
	{
		unsigned long blocking = 0;
		unsigned long nonBlocking = 1;
		int status = ioctlsocket(connSocket, FIONBIO, isBlocking ? &blocking : &nonBlocking);
		if (status == SOCKET_ERROR)
		{
			return false;
		}
		return true;

	}

}

