#include "Server.h"

namespace MNet
{
    bool Server::Initialize(PCSTR port, PCSTR ip)
    {
        Socket serverSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (not serverSocket.Create())
        {
            std::cout << "[-] Failed to create the socket." << std::endl;
            return false;
        }

        std::cout << "[+] Server socket successfuly created." << std::endl;

        if (not serverSocket.Bind(port, ip))
        {
            std::cout << "[-] Failed to bind the socket." << std::endl;
            serverSocket.Close();
            return false;
        }

        std::cout << "[+] Server binded successfuly" << std::endl;

        auto connAttempt = serverSocket.Accept();

        if (not connAttempt.has_value())
        {
            std::cout << "[-] Failed to accept new connection." << std::endl;
            serverSocket.Close();
            return false;
        }

        auto [acceptedSocket, connIp, connPort] = connAttempt.value();

        clientConn = Connection(acceptedSocket, connIp, connPort);
        OnConnect(clientConn);

        return true;

    }

    bool Server::Logic(const std::string& command)
    {
        Packet packet;

        if (command == "Quit")
        {
            return false;
            connSocket.Close();
            clientConn.Close();
        }
        else if (command == "Upload")
        {
            std::cout << "Not Implemented Yet." << std::endl;
            connSocket.Close();
            clientConn.Close();
            return false;
        }
        else if (command == "Download")
        {
            std::cout << "Not Implemented Yet." << std::endl;
            connSocket.Close();
            clientConn.Close();
            return false;
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

            while (packet.GetPacketOffset() < packetSize)
                std::cout << "[!] Message from client: " << packet.ExtractString() << std::endl;
        }

        return true;
    }

    void Server::OnConnect(Connection connection)
    {
        std::cout << "[+] Accepted new connection: [ ip: " << connection.GetIp() << ", port: " << connection.GetPort() << "]" << std::endl;
    }

}
