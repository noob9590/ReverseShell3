#pragma once
#include <MNet\Networking.h>
#include <filesystem>
#include <sstream>
#include "Command.h"

using namespace MNet;

class Agent : public Client
{
private:

	Command command;

	void OnConnect(Connection connection) override;

public:

	bool ShutDown() override;
	bool Logic() override;
};

