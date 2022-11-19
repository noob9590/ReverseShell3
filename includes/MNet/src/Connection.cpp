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

	void Connection::Close()
	{
		if (connSocket != INVALID_SOCKET)
		{
			closesocket(connSocket);
			connSocket = INVALID_SOCKET;
			Crypt.Terminate();
		}
	}

	M_Result Connection::Send(const void* buff, int buffSize, int& bytesSent)
	{
		bytesSent = send(connSocket, (const char*)buff, buffSize, 0);
		if (bytesSent == SOCKET_ERROR)
		{
			return M_GenericWarning;
		}
		return M_Success;
	}

	M_Result Connection::SendAll(void* data, int dataSize)
	{
		int totalBytesSent = 0;
		while (totalBytesSent < dataSize)
		{
			int bytesSent = 0;
			int bytesRemaining = dataSize - totalBytesSent;
			char* bufferOffset = (char*)data + totalBytesSent;

			if (Send(bufferOffset, bytesRemaining, bytesSent) == M_GenericWarning)
			{
				return M_GenericWarning;
			}

			totalBytesSent += bytesSent;
		}

		return M_Success;
	}

	M_Result Connection::Recv(void* buff, int buffSize, int& bytesReceived)
	{
		bytesReceived = recv(connSocket, (char*)buff, buffSize, 0);
		if (bytesReceived <= 0)
		{
			return M_GenericWarning;
		}

		return M_Success;
	}

	M_Result Connection::RecvAll(void* data, int dataSize)
	{
		int totalBytesReceived = 0;
		while (totalBytesReceived < dataSize)
		{
			int bytesReceived = 0;
			int bytesRemaining = dataSize - totalBytesReceived;
			char* bufferOffset = (char*)data + totalBytesReceived;

			if (Recv(bufferOffset, bytesRemaining, bytesReceived) == M_GenericWarning)
			{
				if (bytesReceived == 0)
					return M_GenericWarning;

				int err = GetLastError();

				if (err == WSAEWOULDBLOCK)
					continue;

				else
					return M_GenericWarning;
			}

			totalBytesReceived += bytesReceived;
		}

		return M_Success;
	}

	M_Result Connection::SendPacket(Packet packet)
	{
		uint32_t encodedPacketSize = htonl(packet.PacketSize());
		if (SendAll(&encodedPacketSize, sizeof(uint32_t)) == M_GenericWarning)
		{
			return M_GenericWarning;
		}

		if (SendAll(packet.buffer.data(), packet.PacketSize()) == M_GenericWarning)
		{
			return M_GenericWarning;
		}

		return M_Success;
	}

	M_Result Connection::RecvPacket(Packet& packet)
	{
		packet.Clear(packet.GetPacketType());

		uint32_t encodedPacketSize = 0;
		if (RecvAll(&encodedPacketSize, sizeof(uint32_t)) == M_GenericWarning)
		{
			return M_GenericWarning;
		}

		uint32_t bufferSize = ntohl(encodedPacketSize);
		packet.buffer.resize(bufferSize);

		if (RecvAll(packet.buffer.data(), bufferSize) == M_GenericWarning)
		{
			return M_GenericWarning;
		}

		return M_Success;
	}

	// might break this function into several
	M_Result Connection::SendFile(const std::string& path, uintmax_t filesize)
	{
		Packet packet(PacketType::request);
		std::fstream file;
		file.open(path, std::ios::in | std::ios::binary);
		if (not file.is_open())
		{
			std::cerr << "Error while trying to open the file." << std::endl;
			return M_GenericError;
		}

		do
		{
			uint32_t bytesToRead = min(BUFSIZE, filesize);
			std::string fileBuffer;
			fileBuffer.resize(bytesToRead);

			file.read(&fileBuffer[0], bytesToRead);

			packet.Clear(packet.GetPacketType());
			packet << fileBuffer;
			Crypt.EncryptPacket(packet);

			M_Result res = SendPacket(packet);
			if (res != M_Success)
			{
				file.close();
				return res;
			}

			filesize -= bytesToRead;

		} while (filesize);

		file.close();

		return M_Success;
	}

	M_Result Connection::RecvFile(const std::string& path, uintmax_t bytesToRead)
	{
		Packet packet(PacketType::request);
		std::fstream file;
		file.open(path, std::ios::out | std::ios::binary);

		if (not file.is_open())
		{
			std::cerr << "Error while trying to open the file." << std::endl;
			return M_GenericError;
		}

		do
		{
			M_Result res = RecvPacket(packet);
			if (res != M_Success)
			{
				file.close();
				return res;
			}
			Crypt.DecryptPacket(packet);

			std::string fileBuffer;
			packet >> fileBuffer;

			file.write(&fileBuffer[0], fileBuffer.size());
			bytesToRead -= fileBuffer.size();

		} while (bytesToRead);

		file.close();
		return M_Success;
	}

}

