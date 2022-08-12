#pragma once
#include <any>
#include "Socket.h"
#include "Connection.h"

namespace MNet
{
	class Server
	{
	public:
		Server() { };
		virtual bool Initialize(PCSTR port, PCSTR ip = nullptr);
		virtual bool ShutDown();
		virtual bool Logic(const std::string& command);

	protected:
		Socket connSocket;
		Connection clientConn;

		virtual void OnConnect(Connection connection);
	};
}


