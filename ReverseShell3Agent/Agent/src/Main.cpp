#include <MNet\Networking.h>
#include <cstdint>

using namespace MNet;

int main()
{
	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
	}

	std::cout << "[+] Winsock successfuly initialized." << std::endl;
	
	Client client;
	client.Initialize("127.0.0.1", "4000");
	
	while (true)
		client.Logic(std::string("test"));

	WSA::ShutDown();
}