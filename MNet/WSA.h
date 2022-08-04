#pragma once
#define WIN32_LEAN_AND_MEAN

#include <iostream>
#include <windows.h>
#include <winsock2.h>

namespace MNet
{
	class WSA
	{
	public:
		static bool StartUp();
		static void ShutDown();
	};
}