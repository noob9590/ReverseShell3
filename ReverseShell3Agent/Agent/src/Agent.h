#pragma once
// custom
#include "src\Networking.h"
#include "Command.h"

// win api
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// std
#include <exception>
#include <iomanip>




using namespace MNet;

class Agent
{
private:
	Socket connSocket;
	Connection serverConn;
	Command command;
	M_Result OnConnect(Connection& connection);

public:
	Agent() = default;

	M_Result Connect(PCSTR ip, PCSTR port);
	void ShutDown();
	M_Result Logic();
};

