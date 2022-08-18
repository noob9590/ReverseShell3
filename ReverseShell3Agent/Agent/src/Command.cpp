#include "Command.h"


bool Command::PipeInit(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR)
{
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (not CreatePipe(&h_OUT_RD, &h_OUT_WR, &saAttr, 0))
	{
		std::cerr << "Error at CreatePipe" << std::endl;
		return false;
	}

	if (not SetHandleInformation(h_OUT_RD, HANDLE_FLAG_INHERIT, 0))
	{
		std::cerr << "Error at SetHandleInformation" << std::endl;
		CloseHandle(h_OUT_RD);
		CloseHandle(h_OUT_WR);

		return false;
	}

	return true;
}

bool Command::Pipe2Buffer(HANDLE& h_OUT_RD)
{
	DWORD dwRead;
	DWORD dwAvailBytes = 0;
	DWORD dwReadTotal = 0;
	BOOL bSuccess;

	output.clear();

	for (;;)
	{
		bSuccess = ReadFile(h_OUT_RD, output.data() + dwReadTotal, dwAvailBytes, &dwRead, NULL);
		dwReadTotal += dwRead;

		if (not bSuccess)
			break;

		bSuccess = PeekNamedPipe(h_OUT_RD, NULL, 0, NULL, &dwAvailBytes, NULL);

		if (not bSuccess)
			break;

		int bufferSize = static_cast<int>(dwReadTotal) + static_cast<int>(dwAvailBytes);
		output.resize(bufferSize);
	}

	return true;
}

bool Command::Execute(std::string cmd)
{
	HANDLE h_OUT_RD;
	HANDLE h_OUT_WR;

	if (not PipeInit(h_OUT_RD, h_OUT_WR))
	{
		std::cerr << "Error at InitializePromptPipe." << std::endl;
		return false;
	}

	BOOL bSuccess;
	STARTUPINFOA si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);

	si.hStdError = h_OUT_WR;
	si.hStdOutput = h_OUT_WR;
	si.dwFlags |= STARTF_USESTDHANDLES;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));
	
	cmd = "/c " + cmd;

	bSuccess = CreateProcessA(
		"C:\\Windows\\System32\\cmd.exe",
		(LPSTR)cmd.c_str(),
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi);

	if (not bSuccess)
	{
		std::cerr << "Error at CreateProcessA." << std::endl;
		return false;
	}

	// first close the handle to notify ReadFile.
	CloseHandle(h_OUT_WR);

	if (not Pipe2Buffer(h_OUT_RD))
	{
		std::cerr << "Error at CmdOutput2Buffer." << std::endl;
		return false;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(h_OUT_RD);

	return true;
}

const std::string Command::GetCurrentDir() const
{
	return std::filesystem::current_path().string();
}

const bool Command::SetCurrentDir(std::string& path) const
{
	try
	{
		auto dst = std::filesystem::path(path);
		std::filesystem::current_path(dst);
	}

	catch (std::filesystem::filesystem_error e)
	{
		return false;
	}

	return true;
		
}

const std::string Command::GetOutput() const
{
	return std::string(output.data(), output.size());
}
