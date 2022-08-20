#pragma once
#include <MNet\networking.h>
#include <io.h>

using namespace MNet;

class Stager : public Server
{
private:
	void OnConnect(Connection newConnection) override;
	PacketType MapPacketType(const std::string& cmd);

public:
	bool Logic(const std::string& command) override;
	
};

