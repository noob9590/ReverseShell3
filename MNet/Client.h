#pragma once
#include "Socket.h"
#include "Connection.h"
namespace MNet
{
	class Client
	{
	public:

		Client() {};
		virtual bool Connect(PCSTR ip, PCSTR port);
		virtual bool Logic();
		virtual bool ShutDown();

	protected:
		Socket connSocket;
		Connection serverConn;

		virtual void OnConnect(Connection connection);
	};
}


