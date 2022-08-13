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
	//if (not agent.Initialize())
	//{
	//	std::cerr << "Failed to initialize agent." << std::endl;
	//	ExitProcess(1);
	//}

	if (not agent.Connect("127.0.0.1", "4000"))
	{
		std::cerr << "Failed to establish connection." << std::endl;
		ExitProcess(1);
	}
	
	while (agent.Logic())
		Sleep(50);

	if (not agent.ShutDown())
	{
		std::cerr << "Error at ShutDown" << std::endl;
		ExitProcess(1);
	}
	
	WSA::ShutDown();
}