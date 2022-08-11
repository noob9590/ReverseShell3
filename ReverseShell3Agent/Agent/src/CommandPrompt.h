#pragma once
#include <windows.h>
#include <synchapi.h>
#include <iostream>
#include <vector>
#include <assert.h>

class CommandPrompt
{
private:
	std::vector<char> output;
	HANDLE h_IN_RD = nullptr;
	HANDLE h_IN_WR = nullptr;
	HANDLE h_OUT_RD = nullptr;
	HANDLE h_OUT_WR = nullptr;

public:
	CommandPrompt() { };
	bool InitializeCmdPipe();
	bool Launch(bool isPipeInitialized = true);
	bool Close();
	bool Cmd2Buffer();
	bool Buffer2Cmd(std::string& buffer);
	const std::string GetCmdOutput() const;

};

