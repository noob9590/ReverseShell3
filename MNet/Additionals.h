#pragma once
#include <windows.h>
#include <iostream>
#include <optional>

bool WinOpenFile(HANDLE& hFIle, std::string& filename, bool createNewFile);

