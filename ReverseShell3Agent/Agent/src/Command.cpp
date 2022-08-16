#include "Command.h"


bool Command::InitializePromptPipe(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR)
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
		h_OUT_RD = INVALID_HANDLE_VALUE;
		h_OUT_WR = INVALID_HANDLE_VALUE;

		return false;
	}

	return true;
}

bool Command::CmdOutput2Buffer(HANDLE& h_OUT_RD)
{
	DWORD dwRead;
	DWORD dwAvailBytes = 0;
	DWORD dwReadTotal = 0;
	BOOL bSuccess = FALSE;

	bSuccess = PeekNamedPipe(h_OUT_RD, NULL, 0, NULL, &dwAvailBytes, NULL);
	if (not bSuccess)
	{
		int error = GetLastError();
		std::cerr << "Error at PeekNamedPipe." << std::endl;
		return false;
	}

	output.clear();
	output.resize(dwAvailBytes);


	for (;;)
	{

		bSuccess = ReadFile(h_OUT_RD, output.data() + dwReadTotal, dwAvailBytes, &dwRead, NULL);
		dwReadTotal += dwRead;
		if (not bSuccess)
		{
			int error = GetLastError();
			if (error == ERROR_BROKEN_PIPE)
				break;

			std::cerr << "Error at ReadFile." << std::endl;
			return false;
		}

		bSuccess = PeekNamedPipe(h_OUT_RD, NULL, 0, NULL, &dwAvailBytes, NULL);
		if (not bSuccess)
		{
			int error = GetLastError();
			std::cerr << "Error at PeekNamedPipe." << std::endl;
			return false;
		}
		
		int bufferSize = static_cast<int>(dwReadTotal) + static_cast<int>(dwAvailBytes);
		output.resize(bufferSize);
	}

	return true;
}

bool Command::Execute(std::string cmd)
{
	HANDLE h_OUT_RD;
	HANDLE h_OUT_WR;

	if (not InitializePromptPipe(h_OUT_RD, h_OUT_WR))
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

	CloseHandle(h_OUT_WR);

	if (not CmdOutput2Buffer(h_OUT_RD))
	{
		std::cerr << "Error at CmdOutput2Buffer." << std::endl;
		return false;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(h_OUT_RD);

	h_OUT_WR = INVALID_HANDLE_VALUE;
	h_OUT_RD = INVALID_HANDLE_VALUE;

	return true;
}

const std::string Command::GetCurrentPath() const
{
	return std::filesystem::current_path().string();
}

const bool Command::SetCurrentPath(std::string& path) const
{
	try
	{
		int whiteSpace = path.find(' ');
		std::string pathstring = path.substr(++whiteSpace);
		auto dst = std::filesystem::path(pathstring);
		std::filesystem::current_path(dst);
	}

	catch (std::filesystem::filesystem_error e)
	{
		return false;
	}

	return true;
		
}

const std::string Command::GetCmdOutput() const
{
	return std::string(output.data(), output.size());
}
