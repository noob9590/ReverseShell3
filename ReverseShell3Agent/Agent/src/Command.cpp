#include "Command.h"


bool Command::InitPipe(HANDLE& h_OUT_RD, HANDLE& h_OUT_WR)
{
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (not ::CreatePipe(&h_OUT_RD, &h_OUT_WR, &saAttr, 0))
	{
		std::cerr << "Error at CreatePipe" << std::endl;
		return false;
	}

	if (not ::SetHandleInformation(h_OUT_RD, HANDLE_FLAG_INHERIT, 0))
	{
		std::cerr << "Error at SetHandleInformation" << std::endl;
		::CloseHandle(h_OUT_RD);
		::CloseHandle(h_OUT_WR);

		return false;
	}

	return true;
}

bool Command::FromPipeToBuffer(HANDLE& h_OUT_RD)
{
	DWORD dwRead;
	DWORD dwAvailBytes = 0;
	DWORD dwReadTotal = 0;
	BOOL bSuccess;

	output.clear();

	for (;;)
	{
		bSuccess = ::ReadFile(h_OUT_RD, output.data() + dwReadTotal, dwAvailBytes, &dwRead, NULL);
		dwReadTotal += dwRead;

		if (not bSuccess)
			break;

		bSuccess = ::PeekNamedPipe(h_OUT_RD, NULL, 0, NULL, &dwAvailBytes, NULL);

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

	if (not InitPipe(h_OUT_RD, h_OUT_WR))
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

	bSuccess = ::CreateProcessA(
		(LPCSTR)"C:\\Windows\\System32\\cmd.exe",
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
	::CloseHandle(h_OUT_WR);

	if (not FromPipeToBuffer(h_OUT_RD))
	{
		std::cerr << "Error at CmdOutput2Buffer." << std::endl;
		return false;
	}

	// cleanup
	::WaitForSingleObject(pi.hProcess, INFINITE);
	::CloseHandle(pi.hProcess);
	::CloseHandle(pi.hThread);
	::CloseHandle(h_OUT_RD);

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

void Command::TakeScreenshot(std::vector<BYTE>& imageBytes)
{
	using namespace Gdiplus;

	IStream* stream = NULL;
	// create stream object
	HRESULT hr = ::CreateStreamOnHGlobal(0, TRUE, &stream);
	CImage image;
	ULARGE_INTEGER liSize;

	// create a screen and a memory device context
	HDC hDCScreen = ::CreateDC(_T("DISPLAY"), NULL, NULL, NULL);
	// create a compatible bitmap and select it in the memory DC
	HDC hDCMem = ::CreateCompatibleDC(hDCScreen);
	int width = ::GetDeviceCaps(hDCScreen, HORZRES); // get screen width
	int height = ::GetDeviceCaps(hDCScreen, VERTRES); // get screen height
	// bit-blit from screen to memory device context
	HBITMAP hBitmap = ::CreateCompatibleBitmap(hDCScreen, width, height);
	HBITMAP hBmpOld = (HBITMAP)::SelectObject(hDCMem, hBitmap);
	// note: CAPTUREBLT flag is required to capture layered windows
	DWORD dwRop = SRCCOPY | CAPTUREBLT;
	BOOL bRet = ::BitBlt(hDCMem, 0, 0, width, height, hDCScreen, 0, 0, dwRop);
	// attach bitmap handle to CImage
	image.Attach(hBitmap);
	// screenshot to jpg and save to stream
	image.Save(stream, Gdiplus::ImageFormatJPEG);
	::IStream_Size(stream, &liSize);
	DWORD len = liSize.LowPart;
	::IStream_Reset(stream);
	imageBytes.resize(len);
	::IStream_Read(stream, &imageBytes[0], len);
	stream->Release();

	// restore the memory DC and perform cleanup
	::SelectObject(hDCMem, hBmpOld);
	::DeleteDC(hDCMem);
	::DeleteDC(hDCScreen);
}