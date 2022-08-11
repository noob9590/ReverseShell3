#include <MNet\Networking.h>
#include "Agent.h"


using namespace MNet;

int main()
{
	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
		exit(1);
	}

	std::cout << "[+] Winsock successfuly initialized." << std::endl;

	Agent agent;
	agent.Connect("127.0.0.1", "4000");
	
	while (agent.Logic(""))
		Sleep(50);

	if (not agent.serverConn.Close())
	{
		std::cerr << "Main::Agent::serverConn::Close Error." << std::endl;
		exit(1);
	}
	if (not agent.console.Close())
	{
		std::cerr << "Main::Agent::console::Close Error." << std::endl;
		exit(1);
	}
	
	WSA::ShutDown();
}