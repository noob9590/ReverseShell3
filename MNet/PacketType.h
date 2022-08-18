#pragma once
#include <stdint.h>

namespace MNet
{

	enum PacketType : uint16_t
	{
		Invalid,
		ConnectionClose,
		Integers,
		Text,
		Bytes,
		Pwd
	};

}