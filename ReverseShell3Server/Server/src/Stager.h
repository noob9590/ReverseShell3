#pragma once
#include <io.h>
#include "src\Networking.h"
#include <exception>
#include <unordered_map>
#include <thread>


using namespace MNet;

class Stager
{
private:
	Socket connSocket;
	std::unordered_map<std::string, Connection> connections;
	std::vector<WSAPOLLFD> connectionsEvents;
	std::thread connectionsThread;
	Connection* currentConn = nullptr;
	CommandStructure InputParser(const std::string& input);
	M_Result OnConnect(Connection& newConnection);
	void ConnectionsManager();
	void CloseConnection(SOCKET disconnectedSocket, const std::string& reason);
	
public:
	M_Result Listen(PCSTR port, PCSTR ip = nullptr);
	M_Result Logic(const std::string& command);
	void ShutDown();
	void Run();
	void PrintHelp();
	void PrintAgents();
	void SetCurrentAgent(const std::string& input);
	Connection* const GetCurrentAgent() const;
};

