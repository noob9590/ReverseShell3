#include <mnet\networking.h>
#include <iostream>
#include <string>
#include <cstdint>

using namespace MNet;

int main()
{
	if (WSA::StartUp())
	{
		std::cout << "Winsock successfuly initialized." << std::endl;
		
		Socket serverSock(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (serverSock.Create(true))
		{
			std::cout << "server socket successfuly created." << std::endl;

			if (serverSock.Bind("4000"))
			{
				std::cout << "server bind successfuly" << std::endl;
				while (true)
				{
					auto attempt = serverSock.Accept();
						if (attempt.has_value())
						{
							auto [acceptedSocket, ip, port] = attempt.value();
							Connection toClient(acceptedSocket, ip, port);
							std::string serverBuffer = "";

							uint16_t bufferSize = 0;

							if (toClient.RecvAll(&bufferSize, sizeof(uint16_t)))
							{
								bufferSize = ntohs(bufferSize);
								serverBuffer.resize(bufferSize);
				
								if (toClient.RecvAll(serverBuffer.data(), bufferSize))
								{
									std::cout << serverBuffer << std::endl;
								}
								else
								{
									std::cerr << "RecvAll (message) Error: " << WSAGetLastError() << std::endl;
								}
							}

							else
							{
								std::cerr << "RecvAll (size) Error: " << WSAGetLastError() << std::endl;
							}
						}

				}
			}
			else
			{
				std::cout << "Failed to bind/listen to connection." << std::endl;
				// handle the error when socket bind failed.
			}
		}
		else
		{
			std::cout << "Failed to create the socket." << std::endl;
			// handle the error when socket creation failed.
		}
	}
	else
	{
		std::cout << "Failed to start up Winsock." << std::endl;
		// handle the error when startup failed.
	}
	
	WSA::ShutDown();
}


//#include <atomic>
//#include <thread>
//#include <iostream>
//#include <chrono>
//
//void ReadCin(std::atomic<bool>& run)
//{
//    std::string buffer;
//
//    while (run.load())
//    {
//        std::cin >> buffer;
//        if (buffer == "Quit")
//        {
//            run.store(false);
//        }
//    }
//}
//
//int main()
//{
//    std::atomic<bool> run(true);
//    std::thread cinThread(ReadCin, std::ref(run));
//
//    while (run.load())
//    {
//        std::cout << "IN LOOP" << std::endl;
//        std::this_thread::sleep_for(std::chrono::seconds(3));
//        // main loop
//    }
//
//    run.store(false);
//    cinThread.join();
//
//    return 0;
//}
