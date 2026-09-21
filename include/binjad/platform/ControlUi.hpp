#pragma once

#include "binjad/Config.hpp"

#include <filesystem>
#include <string>

namespace binjad::platform {
	std::string LaunchControlUi(const std::filesystem::path& executable, const std::filesystem::path& configPath,
		const Config& config);
}  // namespace binjad::platform
