#include <MNet\Networking.h>
#include <cstdint>

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

				Connection toServer(clientSock.GetSocketHandle(), "127.0.0.1", "4000");
				std::string clientMessage = "Hello from client.";
				uint16_t clientMessageSize = htons(clientMessage.size());

				if (toServer.SendAll(&clientMessageSize, sizeof(uint16_t)))
				{
					if (not toServer.SendAll(clientMessage.data(), clientMessage.size()))
					{
						std::cerr << "SendAll (message) Error: " << WSAGetLastError() << std::endl;
					}
				}
				else
				{
					std::cerr << "SendAll (size) Error: " << WSAGetLastError() << std::endl;
				}
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