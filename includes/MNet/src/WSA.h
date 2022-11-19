#pragma once

// windows api
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment (lib, "Ws2_32.lib")

// std
#include <iostream>

namespace MNet
{
	class WSA
	{
	public:
		static bool StartUp();
		static void ShutDown();
	};
}