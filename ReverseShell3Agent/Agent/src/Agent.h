#pragma once
#include <MNet\Networking.h>
#include "CommandPrompt.h"

using namespace MNet;

class Agent : public Client
{
private:

	CommandPrompt console;

	void OnConnect(Connection connection) override;

public:

	bool Initialize();
	bool ShutDown() override;
	bool Logic() override;
};

