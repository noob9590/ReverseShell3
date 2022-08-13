#pragma once
#include <windows.h>
#include <synchapi.h>
#include <iostream>
#include <vector>
#include <assert.h>
#include <tchar.h>
#include <cassert>

class CommandPrompt
{
	// TODO: refactor this class
	//       create method to return current path
private:
	std::vector<char> output;
	HANDLE h_OUT_RD = INVALID_HANDLE_VALUE;
	HANDLE h_OUT_WR = INVALID_HANDLE_VALUE;
	bool CmdOutput2Buffer();

public:
	CommandPrompt() { };
	bool InitializePromptPipe();
	bool ExecCommand(std::string cmd);
	const std::string GetCmdOutput() const;




};

