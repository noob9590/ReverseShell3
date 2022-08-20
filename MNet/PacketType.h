#pragma once
#include <stdint.h>

namespace MNet
{

	enum PacketType : uint16_t
	{
		Invalid,
		Integers,
		Characters,
		Bytes,
		ConnectionClose,
		FileRequest,
		FileTransmit,
		Screenshot,
		Pwd
	};

}