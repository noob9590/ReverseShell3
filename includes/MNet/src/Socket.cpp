#include "Socket.h"

namespace MNet
{

	Socket::Socket(int addressFamily, int sockType, int sockProto)
	{
		ZeroMemory(&connType, sizeof(connType));
		connType.ai_family = addressFamily;
		connType.ai_socktype = sockType;
		connType.ai_protocol = sockProto;
		connType.ai_flags = AI_PASSIVE;
	}

	SOCKET Socket::GetSocketHandle() const
	{
		return connSocket;
	}

	M_Result Socket::Create(bool setBlocking)
	{
		connSocket = WSASocket(connType.ai_family, connType.ai_socktype, connType.ai_protocol, NULL, 0, 0);
		if (connSocket == INVALID_SOCKET)
		{
			std::cerr << "Error at WSASocket." << std::endl;
			return M_GenericError;
		}

		if (SetBlocking(setBlocking) != M_Success)
		{
			std::cerr << "Error at SetBlocking." << std::endl;
			Close(); // Close the socket here since we are not closing the socket when this method fails
			return M_GenericError;
		}

		if (SetSocketOptions(SocketOption::TCP_NoDelay, TRUE) != M_Success)
		{
			std::cerr << "Error at SetSocketOptions." << std::endl;
			Close(); // Close the socket here since we are not closing the socket when this method fails
			return M_GenericError;
		}

		return M_Success;
	}

	void Socket::Close()
	{
		if (connSocket != INVALID_SOCKET)
		{
			closesocket(connSocket);
			connSocket = INVALID_SOCKET;
		}		
	}

	M_Result Socket::Connect(PCSTR ip, PCSTR port)
	{
		int status;
		addrinfo* connect;

		status = getaddrinfo(ip, port, &connType, &connect);
		if (status != 0)
		{
			std::cerr << "Error at getaddrinfo." << std::endl;
			return M_GenericError;
		}

		status = WSAConnect(connSocket, connect->ai_addr, (int)connect->ai_addrlen, 0, 0, 0, 0);

		freeaddrinfo(connect);

		if (status == SOCKET_ERROR)
		{
			std::cerr << "Error at WSAConnect." << std::endl;
			return M_GenericError;
		}
		return M_Success;
	}

	M_Result Socket::SetSocketOptions(SocketOption option, BOOL value)
	{
		int status = 0;
		switch (option)
		{
		case SocketOption::TCP_NoDelay:
			status = setsockopt(connSocket, IPPROTO_TCP, TCP_NODELAY, (const char*)&value, sizeof(value));
			break;

		default:
			return M_GenericError;
		}

		if (status != 0)
		{
			std::cerr << "Error at setsockopt." << std::endl;
			return M_GenericError;
		}
		return M_Success;
	}

	M_Result Socket::Bind(PCSTR port, PCSTR ip)
	{
		int status;
		addrinfo* connect;

		status = getaddrinfo(ip, port, &connType, &connect);
		if (status != 0)
		{
			std::cerr << "Error at getaddrinfo." << std::endl;
			return M_GenericError;
		}

		status = bind(connSocket, connect->ai_addr, (int)connect->ai_addrlen);

		freeaddrinfo(connect);

		if (status == SOCKET_ERROR)
		{
			std::cerr << "Error at bind." << std::endl;
			return M_GenericError;
		}

		status = listen(connSocket, SOMAXCONN);
		if (status == INVALID_SOCKET)
		{
			std::cerr << "Error at listen." << std::endl;
			return M_GenericError;
		}

		return M_Success;
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
			std::cerr << "Error at WSAAccept." << std::endl;
			return { };
		}

		return { {cliSocket, std::string(ip), std::to_string(port) } };
	}

	M_Result Socket::SetBlocking(bool isBlocking)
	{
		unsigned long blocking = 0;
		unsigned long nonBlocking = 1;
		int status = ioctlsocket(connSocket, FIONBIO, isBlocking ? &blocking : &nonBlocking);
		if (status == SOCKET_ERROR)
		{
			std::cerr << "Error at ioctlsocket." << std::endl;
			return M_GenericError;
		}
		return M_Success;

	}

}

