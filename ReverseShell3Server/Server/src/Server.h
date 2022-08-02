#pragma once
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <iostream>
#include <optional>
#include <vector>
#pragma comment (lib, "Ws2_32.lib")

#define BUF_SIZE 512

class Server
{
private:
	int status = -1;

	struct sockaddr_in sockClientInfo;
	int LenclientInfo;

	struct addrinfo StrcServer;
	struct addrinfo* StrcServerOut = 0;

	SOCKET sockServer = INVALID_SOCKET;
	SOCKET sockClient = INVALID_SOCKET;
	WSADATA data;

	PCSTR port;

	void CreateSocket();
	void Bind();

	int Send(SOCKET, const void*, int);
	bool SendSize(SOCKET, unsigned long);
	bool SendMsg(SOCKET, std::string, int);
	int Recv(SOCKET, void*, int);
	bool ReadSize(SOCKET, unsigned long*);
	bool RecvMsg(SOCKET sock);

public:
	Server(PCSTR port);
	void Accept();
	std::tuple<std::string, int> GetConnectionInfo();
	void CommandAndControl(std::string&, size_t);
	~Server();
};
