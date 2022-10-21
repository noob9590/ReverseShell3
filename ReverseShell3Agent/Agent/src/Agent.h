#pragma once
// custom
#include <Networking.h>
#include "Command.h"

// win api
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// std
#include <exception>




using namespace MNet;

class Agent
{
private:
	Socket connSocket;
	Connection serverConn;
	Command command;
	bool OnConnect(Connection connection);

public:
	Agent() = default;

	bool Connect(PCSTR ip, PCSTR port);
	bool ShutDown();
	bool Logic();
};

