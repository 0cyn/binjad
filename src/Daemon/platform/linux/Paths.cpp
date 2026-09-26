#include "binjad/platform/Paths.hpp"

#include <cstdlib>
#include <stdexcept>

namespace binjad::platform {
	std::filesystem::path UserDataDirectory()
	{
		if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
			return std::filesystem::path(xdg) / "binjad";
		const char* home = std::getenv("HOME");
		if (!home || !*home)
			throw std::runtime_error("neither XDG_DATA_HOME nor HOME is set");
		return std::filesystem::path(home) / ".local" / "share" / "binjad";
	}

	std::filesystem::path DefaultConfigPath()
	{
		return UserDataDirectory() / "config.json";
	}
}  // namespace binjad::platform
