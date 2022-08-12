#include "Connection.h"

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
			std::cerr << "Error at closesocket." << std::endl;
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
			std::cerr << "Error at send." << std::endl;
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
				std::cerr << "Error at Send." << std::endl;
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
				std::cerr << "Error at recv." << std::endl;

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
				std::cerr << "Error at Recv" << std::endl;
				return false;
			}

			totalBytesReceived += bytesReceived;
		}

		return true;
	}

	bool Connection::Send(Packet packet)
	{
		uint32_t encodedPacketSize = htonl(packet.PacketSize());
		if (not SendAll(&encodedPacketSize, sizeof(uint32_t)))
		{
			int error = WSAGetLastError();
			std::cerr << "Error at SendAll (packet size)" << std::endl;
			return false;
		}

		if (not SendAll(packet.buffer.data(), packet.PacketSize()))
		{
			int error = WSAGetLastError();
			std::cerr << "Error at SendAll (packet content)" << std::endl;
			return false;
		}

		return true;
	}

	bool Connection::Recv(Packet& packet)
	{
		packet.Clear();

		uint32_t encodedPacketSize = 0;
		if (not RecvAll(&encodedPacketSize, sizeof(uint32_t)))
		{
			int error = WSAGetLastError();
			std::cerr << "Error at RecvAll (packet size)" << std::endl;
			return false;
		}
		
		uint32_t bufferSize = ntohl(encodedPacketSize);
		packet.buffer.resize(bufferSize);

		if (not RecvAll(packet.buffer.data(), bufferSize))
		{
			int error = WSAGetLastError();
			std::cerr << "Error at RecvAll (packet content)" << std::endl;
			return false;
		}

		return true;
	}

}

