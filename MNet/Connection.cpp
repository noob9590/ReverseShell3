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


	bool Connection::SendFile(std::string path)
	{
		Packet packet;
		HANDLE hFile;
		DWORD dwBytesRead = 0;
		DWORD bytesRemaining = 0;
		OVERLAPPED ol = { 0 };
		LARGE_INTEGER lpFileSize;
		std::vector<BYTE> fileBuffer;

		hFile = ::CreateFileA(
			path.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL, // default
			OPEN_EXISTING | CREATE_NEW,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			NULL
		);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			std::cerr << "Error at CreateFile." << std::endl;
			return false;
		}

		BOOL bSuccess = GetFileSizeEx(hFile, &lpFileSize);
		if (not bSuccess)
		{
			std::cerr << "Error at GetFileSizeEx." << std::endl;
			return false;
		}

		bytesRemaining = (DWORD)lpFileSize.LowPart;
		std::string fname = std::filesystem::path(path).filename().string();

		packet.InsertInt(bytesRemaining);
		packet.InsertString(fname);

		if (not Send(packet))
		{
			std::cerr << "Error at Send." << std::endl;
			return false;
		}

		do
		{
			uint32_t buffSize = min(8192, bytesRemaining);
			fileBuffer.clear();
			fileBuffer.resize(buffSize);

			if (not ReadFileEx(hFile, fileBuffer.data(), buffSize, &ol, 0))
			{
				std::cerr << "Error at ReadFileEx." << std::endl;
				return false;
			}

			GetOverlappedResult(hFile, &ol, &dwBytesRead, TRUE);
			ol.Offset += dwBytesRead;
			bytesRemaining -= dwBytesRead;

			packet.Clear();
			packet.InsertBytes(fileBuffer);
			if (not Send(packet))
			{
				std::cerr << "Error at Send (file content)" << std::endl;
				return false;
			}

		} while (bytesRemaining);

		CloseHandle(hFile);

		return true;
	}

	bool Connection::RecvFile()
	{
		Packet packet;
		HANDLE hFile;
		DWORD dwBytesRead = 0;
		OVERLAPPED ol = { 0 };
		LARGE_INTEGER lpFileSize;

		if (not Recv(packet))
		{
			std::cout << "Error at Recv (file information)" << std::endl;
			return false;
		}

		uint32_t    filesize = packet.ExtractInt();
		std::string filename = packet.ExtractString();

		hFile = ::CreateFileA(
			filename.c_str(),
			GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL, // default
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
			NULL
		);

		if (hFile == INVALID_HANDLE_VALUE)
		{
			std::cerr << "Error at CreateFile." << std::endl;
			return false;
		}

		do
		{

			packet.Clear();
			if (not Recv(packet))
			{
				std::cout << "Error at Recv (file content)" << std::endl;
				return false;
			}

			std::vector<BYTE> fileBuffer = packet.ExtractBytes();

			if (not WriteFileEx(hFile, fileBuffer.data(), fileBuffer.size(), &ol, NULL))
			{
				std::cerr << "Error at WriteFileEx." << std::endl;
				return false;
			}

			GetOverlappedResult(hFile, &ol, &dwBytesRead, TRUE);
			ol.Offset += dwBytesRead;
			filesize  -= dwBytesRead;

			// Temp assert for making sure we write all the bytes.
			// This needs to be replaced with a while loop.
			//assert(dwBytesRead == fileBuffer.size());

		} while (filesize);

		CloseHandle(hFile);

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

