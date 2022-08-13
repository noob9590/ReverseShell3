#include "CommandPrompt.h"


bool CommandPrompt::InitializePromptPipe()
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

bool CommandPrompt::ExecCommand(std::string cmd)
{
	BOOL bSuccess;
	STARTUPINFOA si;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);

	assert(h_OUT_WR != INVALID_HANDLE_VALUE);
	assert(h_OUT_RD != INVALID_HANDLE_VALUE);

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

	CloseHandle(h_OUT_RD);

	if (not CmdOutput2Buffer())
	{
		std::cerr << "Error at CmdOutput2Buffer." << std::endl;
		return false;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(h_OUT_WR);

	h_OUT_WR = INVALID_HANDLE_VALUE;
	h_OUT_RD = INVALID_HANDLE_VALUE;

	return true;
}

bool CommandPrompt::CmdOutput2Buffer()
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

		output.resize(dwReadTotal + dwAvailBytes);
	}
	
	return true;
}


const std::string CommandPrompt::GetCmdOutput() const
{
	return std::string(output.data(), output.size());
}
