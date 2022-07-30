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

bool Server::SendAll(SOCKET sock, const void* data, size_t data_size)
{
	//const unsigned char* data_ptr = static_cast<const unsigned char*>(data);

	const char* data_ptr = static_cast<const char*>(data);
	char dbuf[BUF_SIZE];
	int b_sent;

	while (data_size > 0)
	{
		ZeroMemory(dbuf, BUF_SIZE);
		memcpy(dbuf, data_ptr, data_size);

		b_sent = send(sock, dbuf, data_size, 0);
		if (b_sent == SOCKET_ERROR)
		{
			fprintf(stderr, "SendAll error: %d\n", WSAGetLastError());
			return false;
		}

		data_ptr += b_sent;
		data_size -= b_sent;
	}
	return true;
}

bool Server::ReceiveAll(SOCKET sock, void* data, size_t data_size)
{
	int b_received;
	char* dbuf = static_cast<char*>(data);
	ZeroMemory(dbuf, BUF_SIZE);

	do
	{
		b_received = recv(sock, dbuf, BUF_SIZE, 0);
		if (b_received < 0)
		{

		}
		data_size += b_received;
		dbuf += b_received;

	} while (b_received > 0);

	return true;
}

void Server::CommandAndControl(std::string& cmd, size_t size)
{
	const char* m_Cmd = cmd.c_str();

	if (cmd.rfind("GETF", 0) == 0)
	{

	}
	else if (cmd.rfind("PUTF", 0) == 0)
	{

	}
	else
	{
		if (!Server::SendAll(this->sockClient, static_cast<const void*>(m_Cmd), size))
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
