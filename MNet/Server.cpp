#include "Server.h"

namespace MNet
{
    bool Server::Initialize(PCSTR port, PCSTR ip)
    {
        connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        if (not connSocket.Create())
        {
            std::cerr << "Error at Create" << std::endl;
            return false;
        }

        std::cout << "[+] Server socket successfuly created." << std::endl;

        if (not connSocket.Bind(port, ip))
        {
            std::cout << "Error at Bind" << std::endl;
            connSocket.Close();
            return false;
        }

        std::cout << "[+] Server binded successfuly" << std::endl;

        auto connAttempt = connSocket.Accept();

        if (not connAttempt.has_value())
        {
            std::cout << "Error at Accept" << std::endl;
            connSocket.Close();
            return false;
        }

        auto [acceptedSocket, connIp, connPort] = connAttempt.value();

        clientConn = Connection(acceptedSocket, connIp, connPort);
        OnConnect(clientConn);


        return true;

    }

    bool Server::ShutDown()
    {

        if (not connSocket.Close())
        {
            std::cerr << "Error at ShutDown" << std::endl;
            return false;
        }

#pragma region temporary
        if (not (clientConn.GetClientSocket() == INVALID_SOCKET))
            if (not clientConn.Close())
            {
                std::cerr << "Error at ShutDown" << std::endl;
                return false;
            }
#pragma endregion Code specific to close a single connected client

        return true;
    }

    bool Server::Logic(const std::string& command)
    {
        Packet packet;
        
        if (not clientConn.Recv(packet))
        {
            std::cerr << "Error at Recv" << std::endl;
            clientConn.Close();
            return false;
        }

        std::cout << "Message from client: " << packet.ExtractString() << std::endl;

        std::string msg = "Hello from server!";

        packet.Clear();
        packet.InsertString(msg);

        if (not clientConn.Send(packet))
        {
            std::cerr << "Error at Send" << std::endl;
            clientConn.Close();
            return false;
        }

        return true;
    }


    void Server::OnConnect(Connection connection)
    {
        std::cout << "[+] Accepted new connection: [ ip: " << connection.GetIp() << ", port: " << connection.GetPort() << "]" << std::endl;
    }

}
