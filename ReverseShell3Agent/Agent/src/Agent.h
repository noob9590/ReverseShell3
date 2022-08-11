#pragma once
#include <MNet\Networking.h>
#include "CommandPrompt.h"

using namespace MNet;

class Agent : public Client
{
private:
	void OnConnect(Connection connection) override;

public:
	CommandPrompt console;

	Agent();
	bool Logic(std::string command) override;
};

