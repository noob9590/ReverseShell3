#pragma once
#include <stdexcept>
#include <string>

namespace MNet
{
	class PacketException : public std::exception
	{
	private:
		std::string exception;

	public:
		explicit PacketException(std::string exception) :
			exception(exception)
		{};

		virtual const char* what() const throw()
		{
			return exception.c_str();
		}
	};
}


