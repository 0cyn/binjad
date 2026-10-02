#include "binjad/platform/Paths.hpp"

#include <cstdlib>
#include <stdexcept>

namespace binjad::platform {
	std::filesystem::path HomeDirectory()
	{
		const char* home = std::getenv("HOME");
		if (!home || !*home)
			throw std::runtime_error("HOME is not set");
		return home;
	}

	std::filesystem::path UserDataDirectory()
	{
		if (const char* xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
			return std::filesystem::path(xdg) / "binjad";
		return HomeDirectory() / ".local" / "share" / "binjad";
	}

	std::filesystem::path DefaultConfigPath()
	{
		return UserDataDirectory() / "config.json";
	}

	std::filesystem::path DefaultBinaryNinjaInstallationDirectory()
	{
		return HomeDirectory() / "binaryninja";
	}
}  // namespace binjad::platform
