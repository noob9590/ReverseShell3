#include <mnet\networking.h>
#include <iostream>
#include <string>
#include <cstdint>

using namespace MNet;

int main()
{
	if (not WSA::StartUp())
	{
		std::cout << "Failed to start up Winsock." << std::endl;
	}
		
	std::string command;
	Server TCPServer;
	TCPServer.Initialize("4000");

	do
	{
		command.clear();

		std::getline(std::cin, command);

	} while (TCPServer.Logic(command));
	
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
