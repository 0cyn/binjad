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
		return HomeDirectory() / "Library" / "Application Support" / "binjad";
	}

	std::filesystem::path DefaultConfigPath()
	{
		return UserDataDirectory() / "config.json";
	}

	std::filesystem::path DefaultBinaryNinjaInstallationDirectory()
	{
		return "/Applications/Binary Ninja.app";
	}
}  // namespace binjad::platform
