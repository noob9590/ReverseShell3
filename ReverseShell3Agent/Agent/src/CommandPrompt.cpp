#include "CommandPrompt.h"


bool CommandPrompt::InitializeCmdPipe()
{
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&h_IN_RD, &h_IN_WR, &saAttr, 0))
	{
		std::cerr << "Error at CreatePipe" << std::endl;
		return false;
	}
		

	if (!CreatePipe(&h_OUT_RD, &h_OUT_WR, &saAttr, 0))
	{
		std::cerr << "Error at CreatePipe" << std::endl;
		CloseHandle(h_IN_RD);
		CloseHandle(h_IN_WR);

		h_IN_RD = nullptr;
		h_IN_WR = nullptr;

		return false;
	}
		
	return true;
}


bool CommandPrompt::Launch(bool isPipeInitialized)
{
	BOOL bSuccess = FALSE;
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(STARTUPINFOA);

	if (isPipeInitialized)
	{
		si.hStdError = h_OUT_WR;
		si.hStdOutput = h_OUT_WR;
		si.hStdInput = h_IN_RD;
		si.dwFlags |= STARTF_USESTDHANDLES;
	}

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	bSuccess = CreateProcessA(
		NULL,
		(LPSTR)"cmd.exe",
		NULL,
		NULL,
		TRUE,
		CREATE_NO_WINDOW,
		NULL,
		NULL,
		&si,
		&pi);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(h_OUT_WR);
	CloseHandle(h_IN_RD);

	if (not bSuccess)
	{
		std::cerr << "Error at CreateProcessA." << std::endl;
		return false;
	}

	return true;
}

bool CommandPrompt::Buffer2Cmd(std::string& buffer)
{
	DWORD dwWritten, dwWrittenTotal = 0;
	DWORD dwBufferSize = (DWORD)buffer.size();
	BOOL bSuccess = FALSE;

	// # TODO: check the behavior of dwWritten/dwWrittenTotal
	// #       maybe the are the same
	for (;;)
	{
		bSuccess = WriteFile(h_IN_WR, buffer.data() + dwWrittenTotal, dwBufferSize, &dwWritten, NULL);
		dwWrittenTotal += dwWritten;
		if (not bSuccess)
		{
			std::cerr << "Error at WriteFile." << std::endl;
			return false;
		}
		if (dwWrittenTotal == dwBufferSize)
			break;
	}

	return true;
}

bool CommandPrompt::Cmd2Buffer()
{
	DWORD dwRead;
	DWORD dwAvailBytes = 0;
	DWORD dwAvailBytesPrev = 1;
	DWORD dwReadTotal = 0;
	BOOL bSuccess = FALSE;

	output.clear();
	output.resize(1);

	bSuccess = ReadFile(h_OUT_RD, output.data() + dwReadTotal, 1, &dwRead, NULL);
	dwReadTotal += dwRead;
	if (not bSuccess)
	{
		std::cerr << "Error at ReadFile." << std::endl;
		return false;
	}

	for (;;)
	{
		bSuccess = PeekNamedPipe(h_OUT_RD, NULL, 0, NULL, &dwAvailBytes, NULL);
		if (not bSuccess)
		{
			std::cerr << "Error at PeekNamedPipe." << std::endl;
			return false;
		}

		if (dwAvailBytes == dwAvailBytesPrev)
			break;

		dwAvailBytesPrev = dwAvailBytes;

		Sleep(100);
	}

	
	output.resize(++dwAvailBytes);

	for (;;)
	{
		bSuccess = ReadFile(h_OUT_RD, output.data() + dwReadTotal, dwAvailBytes - dwReadTotal, &dwRead, NULL);
		dwReadTotal += dwRead;
		if (not bSuccess)
		{
			std::cerr << "Error at ReadFile." << std::endl;
			return false;
		}
		if (dwAvailBytes == dwReadTotal)
			break;
	}

	return true;
}



bool CommandPrompt::Close()
{
	BOOL isClosed;

	if (not h_IN_WR or not h_OUT_RD)
	{
		throw std::runtime_error("Try to close nullptr HANDLE");
		return false;
	}
		
	isClosed = CloseHandle(h_IN_WR);
	if (not isClosed)
	{
		std::cerr << "CommandPrompt::Close::CloseHandle Error." << GetLastError() << std::endl;
		return false;
	}

	isClosed = CloseHandle(h_OUT_RD);
	if (not isClosed)
	{
		std::cerr << "CommandPrompt::Close::CloseHandle Error." << GetLastError() << std::endl;
		return false;
	}

	h_IN_WR = nullptr;
	h_OUT_RD = nullptr;

	return true;
}


const std::string CommandPrompt::GetCmdOutput() const
{
	return std::string(output.data(), output.size());
}
