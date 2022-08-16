#pragma once
#include <windows.h>
#include <synchapi.h>
#include <iostream>
#include <vector>
#include <tchar.h>
#include <filesystem>
#include <exception>

class Command
{
	// TODO: refactor this class
	//       create method to return current path
private:
	std::vector<char> output;
	bool CmdOutput2Buffer(HANDLE& h_OUT_RD);
	bool InitializePromptPipe(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR);

public:
	Command() { };
	bool Execute(std::string cmd);
	const std::string GetCmdOutput() const;
	const std::string GetCurrentPath() const;
	const bool SetCurrentPath(std::string& path) const;

};

