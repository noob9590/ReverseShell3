#include "WSA.h"

bool MNet::WSA::StartUp()
{
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0)
    {
        std::cerr << "WSAStartup failed." << std::endl;
        return false;
    }
    return true;
}

void MNet::WSA::ShutDown()
{
    WSACleanup();
}
