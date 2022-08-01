#include "Server.h"

Server::Server(PCSTR port)
	: port(port)
{
	Server::CreateSocket();
	Server::Bind();
}

void Server::CreateSocket()
{
	this->status = WSAStartup(MAKEWORD(2, 2), &(this->data));
	if (this->status != 0)
	{
		fprintf(stderr, "WSAStartup error: %d\n", this->status);
		exit(1);
	}

	ZeroMemory(&(this->StrcServer), sizeof(this->StrcServer));
	this->StrcServer.ai_family = AF_INET;
	this->StrcServer.ai_socktype = SOCK_STREAM;
	this->StrcServer.ai_protocol = IPPROTO_TCP;
	this->StrcServer.ai_flags = AI_PASSIVE;

	this->status = getaddrinfo(NULL, this->port, &(this->StrcServer), &(this->StrcServerOut));
	if (this->status != 0)
	{
		fprintf(stderr, "getaddrinfo error: %d\n", this->status);
		Server::~Server();
		exit(1);
	}

	this->sockServer = WSASocket(this->StrcServerOut->ai_family, this->StrcServerOut->ai_socktype, this->StrcServerOut->ai_protocol, NULL, 0, 0);
	if (this->sockServer == INVALID_SOCKET)
	{
		fprintf(stderr, "Socket error: %ld\n", WSAGetLastError());
		Server::~Server();
		exit(1);
	}
}

void Server::Bind()
{
	this->status = bind(this->sockServer, this->StrcServerOut->ai_addr, (int)(this->StrcServerOut->ai_addrlen));
	if (this->status == SOCKET_ERROR)
	{
		fprintf(stderr, "Bind error: %d\n", WSAGetLastError());
		Server::~Server();
		exit(1);
	}

	this->status = listen(this->sockServer, SOMAXCONN);
	if (this->status == INVALID_SOCKET)
	{
		fprintf(stderr, "Listen error: %d\n", WSAGetLastError());
		Server::~Server();
		exit(1);
	}
}

void Server::Accept()
{

	this->LenclientInfo = sizeof(this->sockClientInfo);
	this->sockClient = WSAAccept(this->sockServer, (SOCKADDR*) &sockClientInfo, &(this->LenclientInfo), NULL, NULL);
	
	if (this->sockClient == INVALID_SOCKET)
	{
		fprintf(stderr, "WSAAccept error: %d\n", WSAGetLastError());
		Server::~Server();
		exit(1);
	}
}

std::tuple<std::string, int> Server::GetConnectionInfo()
{
	char IPStr[INET_ADDRSTRLEN];
	int port = ntohs(this->sockClientInfo.sin_port);
	inet_ntop(AF_INET, &(this->sockClientInfo.sin_addr), IPStr, INET_ADDRSTRLEN);
	return {IPStr, port};
}

//bool Server::SendAll(SOCKET sock, const void* data, size_t data_size)
//{
//	//const unsigned char* data_ptr = static_cast<const unsigned char*>(data);
//
//	const char* data_ptr = static_cast<const char*>(data);
//	char dbuf[BUF_SIZE];
//	int b_sent;
//
//	while (data_size > 0)
//	{
//		ZeroMemory(dbuf, BUF_SIZE);
//		memcpy(dbuf, data_ptr, data_size);
//
//		b_sent = send(sock, dbuf, data_size, 0);
//		if (b_sent == SOCKET_ERROR)
//		{
//			fprintf(stderr, "SendAll error: %d\n", WSAGetLastError());
//			return false;
//		}
//
//		data_ptr += b_sent;
//		data_size -= b_sent;
//	}
//	return true;
//}

int Server::Send(SOCKET sock, const void* data, size_t data_size)
{
	int sent;
	int total_sent = 0;
	const char* dbuf = static_cast<const char*>(data);
	do
	{
		sent = send(sock, dbuf, data_size, 0);
		if (sent == SOCKET_ERROR)
			return -1;

		dbuf += sent;
		data_size -= sent;
		total_sent += sent;

	} while (data_size > 0);
	return total_sent;
}

bool Server::SendMsg(SOCKET sock, std::string msg, size_t size)
{
	size_t total_sent = 0;
	const char* msg_ptr = msg.c_str();
	char dbuf[BUF_SIZE];
	do
	{
		int to_send = min(size - total_sent, BUF_SIZE);
		ZeroMemory(dbuf, BUF_SIZE);
		memcpy(dbuf, msg_ptr, to_send);
		int sent = Send(sock, static_cast<const void*>(dbuf), to_send);
		if (sent == -1)
		{
			fprintf(stderr, "Send error: %d\n", WSAGetLastError());
			return false;
		}
		total_sent += sent;
		msg_ptr += sent;
		
	} while (size > total_sent);
	return true;
}

int Server::Recv(SOCKET sock, void* data, int data_size)
{
	int recved;
	int total_recved = 0;
	char* dbuf = static_cast<char*>(data);
	do
	{
		recved = recv(sock, dbuf, data_size, 0);
		if (recved <= 0)
		{
			// recved == 0 --> connection closed
			// recved == -1 --> SOCKET_ERROR
			return 0;
		}
		total_recved += recved;
		dbuf += recved;

	} while (data_size > total_recved);
	std::cout << total_recved << std::endl;
	return total_recved;
}

bool Server::ReadSize(SOCKET sock, unsigned long* size)
{
	if (!Server::Recv(sock, static_cast<void*>(size), sizeof(size)))
		return false;
	*size = ntohl(*size);
	return true;
}

bool Server::RecvAll(SOCKET sock)
{
	unsigned long size;
	if (!Server::ReadSize(sock, &size))
	{
		//handle the error
		return false;
	}
	
	size_t total_recv = 0;
	do
	{
		int sz_to_read = min(512, size); // might change the size
		std::vector<char> dbuf(sz_to_read + 1, 0); // might change the size

		int recved = Server::Recv(sock, static_cast<void*>(dbuf.data()), sz_to_read);
		if (!recved)
		{
			//handle the error
			return false;
		}
		size -= recved;
		std::cout << dbuf.data();
	} while (size > 0);

	std::cout << std::endl;
	return true;
}

bool Server::RecvMsg(SOCKET sock)
{
	unsigned long size;
	if (!Server::ReadSize(sock, &size))
	{
		//handle the error
		return false;
	}
	int num = 0;
	char dbuf[BUF_SIZE + 1];
	do
	{
		int sz_to_read = min(512, size);
		ZeroMemory(dbuf, BUF_SIZE + 1);
		num = Server::Recv(sock, static_cast<void*>(dbuf), sz_to_read);
		if (!num)
		{
			fprintf(stderr, "Recv error: %d\n", WSAGetLastError());
			return false;
		}
		size -= num;
		std::cout << dbuf;

	} while (size > 0);

	std::cout << std::endl;
	return true;
}

void Server::CommandAndControl(std::string& cmd, size_t size)
{
	if (cmd.rfind("GETF", 0) == 0)
	{

	}
	else if (cmd.rfind("PUTF", 0) == 0)
	{

	}
	else
	{
		if (!Server::SendMsg(this->sockClient, cmd, size))
		{
			Server::~Server();
			exit(1);
		}
		if (!Server::RecvMsg(this->sockClient))
		{
			Server::~Server();
			exit(1);
		}
	}
}

Server::~Server()
{
	if (this->sockServer != INVALID_SOCKET)
		closesocket(this->sockServer);

	if (this->sockClient != INVALID_SOCKET)
		closesocket(this->sockClient);

	if (this->StrcServerOut)
		freeaddrinfo(this->StrcServerOut);

	WSACleanup();
}
