#include "Agent.h"

using namespace MNet;

int main()
{

	if (not WSA::StartUp())
	{
		ExitProcess(EXIT_FAILURE);
	}

	Agent agent;
	M_Result res{};
	bool isConnected = false;

	while (not isConnected)
	{
		res = agent.Connect("", "");

		if (res == M_Success)
			isConnected = true;

		else if (res == M_GenericError)
			break;

		else
			Sleep(10000);
	}

	while (isConnected)
	{
		res = agent.Logic();
		
		if (res != M_Success)
			break;
	}

	// cleanup
	agent.ShutDown();
	WSA::ShutDown();
}
