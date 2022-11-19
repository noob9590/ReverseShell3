#pragma once
#include <stdexcept>

namespace MNet
{
	class CrypterException : public std::exception
	{
	private:
		std::string exception;

	public:
		CrypterException(std::string exception) :
			exception(exception)
		{};

		virtual const char* what() const throw()
		{
			return exception.c_str();
		}

	};
}
