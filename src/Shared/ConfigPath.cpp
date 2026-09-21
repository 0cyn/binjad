#include "binjad/Config.hpp"

#include "binjad/platform/Paths.hpp"

#include <exception>
#include <string>
#include <string_view>

namespace binjad {
	ConfigPathSelection SelectConfigPath(int argc, char* const argv[])
	{
		ConfigPathSelection result;
		try
		{
			result.path = platform::DefaultConfigPath();
		}
		catch (const std::exception& exception)
		{
			result.error = "cannot determine configuration path: " + std::string(exception.what());
			return result;
		}

		for (int index = 1; index < argc; ++index)
		{
			const std::string_view argument(argv[index]);
			if (argument == "--config")
			{
				if (++index >= argc)
				{
					result.path.reset();
					result.error = "--config requires a path";
					return result;
				}
				result.path = argv[index];
				continue;
			}
			constexpr std::string_view prefix = "--config=";
			if (argument.starts_with(prefix) && argument.size() > prefix.size())
			{
				result.path = argument.substr(prefix.size());
				continue;
			}
			result.path.reset();
			result.error = "unknown argument: " + std::string(argument);
			return result;
		}
		return result;
	}
}  // namespace binjad
