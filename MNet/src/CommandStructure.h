#pragma once
#include <string>
#include <inttypes.h>

namespace MNet
{
	enum CommandType : uint16_t
	{
		invalid,
		commandline,
		changedir,
		upload,
		download,
		screenshot,
		agentdown
	};

	struct CommandStructure
	{
		CommandType type = CommandType::invalid;
		std::string cmd;
		std::string remote_path;
		std::string local_path;
		std::string err;
	};
}

