#include "Client.h"

namespace MNet
{
    bool Client::Initialize(PCSTR ip, PCSTR port)
    {
        Socket connSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (not connSocket.Create())
        {
            std::cerr << "[-] Failed to create the socket." << std::endl;
            return false;
        }

        std::cout << "[+] Client socket successfuly created." << std::endl;

        if (not connSocket.Connect(ip, port))
        {
            std::cerr << "[-] Failed to connect to the server." << std::endl;
            connSocket.Close();
            return false;
        }

        std::cout << "[+] Client successfuly connected." << std::endl;

        serverConn = Connection(connSocket.GetSocketHandle(), ip, port);
        OnConnect(serverConn);

        return true;
    }

    bool Client::Logic(std::string command)
    {
        Packet packet;

        if (command == "Upload")
        {
            std::cout << "Not Implemented Yet." << std::endl;
        }
        else if (command == "Download")
        {
            std::cout << "Not Implemented Yet." << std::endl;
        }
        else
        {
            if (not serverConn.Recv(packet))
            {
                connSocket.Close();
                return false;
            }

            uint32_t packetSize = packet.PacketSize();

            while (packet.GetPacketOffset() < packetSize)
                std::cout << "[!] Message from server: " << packet.ExtractString() << std::endl;

            packet.Clear();
            packet.InsertString(std::string("Message from client."));
            packet.InsertString(std::string("Second message from client."));

            if (not serverConn.Send(packet))
            {
                serverConn.Close();
                return false;
            }
        }

        return true;
    }

    void Client::OnConnect(Connection connection)
    {
        std::cout << "[+] Established new connection to server: [ ip: " << connection.GetIp() << ", port: " << connection.GetPort() << "]" << std::endl;
    }
}

