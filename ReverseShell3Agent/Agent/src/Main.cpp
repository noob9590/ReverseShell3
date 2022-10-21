#include "Agent.h"

using namespace MNet;

int main()
{
	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
		ExitProcess(1);
	}

	std::cout << "[+] Winsock successfully initialized." << std::endl;

	Agent agent;
	if (not agent.Connect("127.0.0.1", "4000"))
	{
		std::cerr << "Failed to establish connection." << std::endl;
		ExitProcess(1);
	}

	while (agent.Logic());

	if (not agent.ShutDown())
	{
		std::cerr << "Error at ShutDown" << std::endl;
		ExitProcess(1);
	}

	// cleanup
	WSA::ShutDown();
}
