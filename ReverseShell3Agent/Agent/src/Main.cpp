#include <MNet\Networking.h>

using namespace MNet;
int main()
{
	if (WSA::StartUp())
	{
		std::cout << "Winsock successfuly initialized." << std::endl;
		
		Socket clientSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (clientSock.Create())
		{
			std::cout << "Client socket successfuly created." << std::endl;

			if (clientSock.Connect("127.0.0.1", "4000"))
			{
				std::cout << "Client successfuly connected." << std::endl;
			}
			else
			{
				// handle the error when connect failed.
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