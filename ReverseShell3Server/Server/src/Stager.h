#pragma once
#include <MNet\networking.h>

using namespace MNet;

class Stager : public Server
{
private:
	void OnConnect(Connection newConnection) override;

public:
	bool Logic(const std::string& command) override;
};

