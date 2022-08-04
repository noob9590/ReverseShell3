#include "ClientInfo.h"

//MNet::ClientInfo::ClientInfo(const char* ip, const char* port) :
//	ip(ip), port(port)
//{
//}

namespace MNet
{
	ClientInfo::ClientInfo(SOCKET acceptedCliSocket, sockaddr_in strcCliInfo)
		: cliSocket(acceptedCliSocket)
	{
		char ip[INET_ADDRSTRLEN];
		int port = ntohs(strcCliInfo.sin_port);
		inet_ntop(AF_INET, &strcCliInfo.sin_addr, ip, INET_ADDRSTRLEN);
		this->ip = ip;
		this->port = std::to_string(port);
	}

	SOCKET ClientInfo::GetClientSocket() const
	{
		return cliSocket;
	}

	const std::string& ClientInfo::GetIp() const
	{
		return ip;
	}

	const std::string& ClientInfo::GetPort() const
	{
		return port;
	}
}

