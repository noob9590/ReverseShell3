#include "Client.h"

namespace MNet
{
    bool Client::Connect(PCSTR ip, PCSTR port)
    {
        connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (not connSocket.Create())
        {
            std::cerr << "Error at Create." << std::endl;
            return false;
        }

        std::cout << "[+] Client socket successfuly created." << std::endl;

        if (not connSocket.Connect(ip, port))
        {
            std::cerr << "Error at Connect" << std::endl;
            connSocket.Close();
            return false;
        }

        std::cout << "[+] Client successfuly connected." << std::endl;

        serverConn = Connection(connSocket.GetSocketHandle(), ip, port);
        OnConnect(serverConn);

        return true;
    }

    bool Client::Logic()
    {
        Packet packet;
        std::string msg = "Hello from client!";

        packet.InsertString(msg);

        if (not serverConn.Send(packet))
        {
            std::cerr << "Error at Send" << std::endl;
            return false;
        }

        if (not serverConn.Recv(packet))
        {
            std::cerr << "Error at Recv." << std::endl;
            return false;
        }

        std::cout << "Message from server: " << packet.ExtractString() << std::endl;
        

        return true;
    }

    bool Client::ShutDown()
    {
        if (not connSocket.Close())
        {
            std::cerr << "Error at Close." << std::endl;
            return false;
        }

        return true;
    }

    void Client::OnConnect(Connection connection)
    {
        std::cout << "[+] Established new connection to server: [ ip: " << connection.GetIp() << ", port: " << connection.GetPort() << "]" << std::endl;
    }
}

