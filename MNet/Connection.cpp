#include "Connection.h"

//MNet::ClientInfo::ClientInfo(const char* ip, const char* port) :
//	ip(ip), port(port)
//{
//}

namespace MNet
{

	Connection::Connection(SOCKET connSocket, std::string ip, std::string port)
		: connSocket(connSocket), ip(ip), port(port)
	{
		if (connSocket == INVALID_SOCKET)
			throw std::runtime_error("Trying to initialize connection with INVALID_SOCKET");
	}

	SOCKET Connection::GetClientSocket() const
	{
		return connSocket;
	}

	const std::string& Connection::GetIp() const
	{
		return ip;
	}

	const std::string& Connection::GetPort() const
	{
		return port;
	}

	bool Connection::Close()
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

	bool Connection::Send(const void* buff, int buffSize, int& bytesSent)
	{
		bytesSent = send(connSocket, (const char*)buff, buffSize, 0);
		if (bytesSent == SOCKET_ERROR)
		{
			return false;
		}
		return true;
	}

	bool Connection::SendAll(void* data, int dataSize)
	{
		int totalBytesSent = 0;
		while (totalBytesSent < dataSize)
		{
			int bytesSent = 0;
			int bytesRemaining = dataSize - totalBytesSent;
			char* bufferOffset = (char*)data + totalBytesSent;

			if (not Send(bufferOffset, bytesRemaining, bytesSent))
			{
				std::cerr << "Send Error: %d" << WSAGetLastError() << std::endl;
				return false;
			}

			totalBytesSent += bytesSent;
		}

		return true;
	}

	bool Connection::Recv(void* buff, int buffSize, int& bytesReceived)
	{
		bytesReceived = recv(connSocket, (char*)buff, buffSize, 0);
		if (bytesReceived <= 0)
		{
			if (bytesReceived == 0)
				std::cerr << "Connection Lost." << std::endl;

			return false;
		}

		return true;
	}

	bool Connection::RecvAll(void* data, int dataSize)
	{
		int totalBytesReceived = 0;
		while (totalBytesReceived < dataSize)
		{
			int bytesReceived = 0;
			int bytesRemaining = dataSize - totalBytesReceived;
			char* bufferOffset = (char*)data + totalBytesReceived;

			if (not Recv(bufferOffset, bytesRemaining, bytesReceived))
			{
				std::cerr << "Recv Error: %d" << WSAGetLastError() << std::endl;
				return false;
			}

			totalBytesReceived += bytesReceived;
		}

		return true;
	}

}

