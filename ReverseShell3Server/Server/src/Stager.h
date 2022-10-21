#pragma once
#include <io.h>
#include <Networking.h>
#include <exception>


using namespace MNet;

class Stager
{
private:
	Socket connSocket;
	Connection clientConn;
	CommandStructure CommandParser(const std::string& input);
	bool OnConnect(Connection newConnection);
	
public:
	bool Listen(PCSTR port, PCSTR ip = nullptr);
	bool ShutDown();
	bool Logic(const std::string& command);
	void PrintHelp();

	
	
};

