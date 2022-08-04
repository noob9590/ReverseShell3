#include <MNet\Networking.h>
#include <iostream>

using namespace MNet;

int main()
{
	if (WSA::StartUp())
	{
		std::cout << "Winsock successfuly initialized." << std::endl;
		
		Socket serverSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (serverSock.Create())
		{
			std::cout << "Server socket successfuly created." << std::endl;

			if (serverSock.Bind("4000"))
			{
				std::cout << "Server successfuly bind." << std::endl;

				ClientInfo client;
				if (serverSock.Accept(client))
				{

				}
				else
				{
					// handle the error when accept failed.
				}

			}
			else
			{
				// handle the error when socket bind failed.
			}
		}
		else
		{
			// handle the error when socket creation failed.
		}
	}
	else
	{
		// handle the error when StartUp failed.
	}
	
	WSA::ShutDown();
}

