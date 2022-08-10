#pragma once
#include "Socket.h"
#include "Connection.h"
namespace MNet
{
	class Client
	{
	public:
		Connection serverConn;

		Client() {};
		virtual bool Connect(PCSTR ip, PCSTR port);
		virtual bool Logic(std::string command);


	protected:
		Socket connSocket;
		//Connection serverConn;

		virtual void OnConnect(Connection connection);
	};
}


