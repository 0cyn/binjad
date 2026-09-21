#pragma once

#include <filesystem>
#include <memory>
#include <string>

namespace binjad::portal {
	class Api;
}

namespace binjad::platform {
	inline constexpr const char* kToolControlSocketName = "menubar-control.sock";

	class ToolControlServer
	{
	public:
		virtual ~ToolControlServer() = default;
	};

	struct ToolControlServerStart
	{
		std::unique_ptr<ToolControlServer> server;
		std::string error;
	};

	std::filesystem::path ToolControlSocketPath(const std::filesystem::path& configPath);
	ToolControlServerStart StartToolControlServer(
		const std::filesystem::path& path, std::shared_ptr<portal::Api> api);
}  // namespace binjad::platform
