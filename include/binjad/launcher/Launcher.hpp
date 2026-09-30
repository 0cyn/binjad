#pragma once

#include "binjad/Config.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::launcher {
	inline constexpr std::string_view kInstallationEnvironment = "BINJAD_INTERNAL_BINARY_NINJA_INSTALLATION_DIR";

	struct BinaryNinjaLayout
	{
		std::filesystem::path installationDirectory;
		std::filesystem::path coreDirectory;
		std::filesystem::path pluginDirectory;
		std::filesystem::path lldbLibraryDirectory;
		std::filesystem::path apiRevisionFile;
	};

	struct LaunchPlan
	{
		std::filesystem::path configurationPath;
		std::filesystem::path runtimeExecutable;
		BinaryNinjaLayout binaryNinja;
	};

	struct LaunchPlanResult
	{
		std::optional<LaunchPlan> plan;
		std::vector<ConfigError> configurationErrors;
		std::string error;
	};

	struct LauncherConfigurationResult
	{
		std::optional<BinaryNinjaConfig> config;
		std::vector<ConfigError> errors;
	};

	class Launcher
	{
	public:
		explicit Launcher(std::filesystem::path executablePath);

		static std::filesystem::path CurrentExecutablePath();
		LaunchPlanResult Prepare(int argc, char* const argv[]) const;
		int Run(int argc, char* const argv[]) const;

	private:
		static LauncherConfigurationResult LoadConfiguration(const std::filesystem::path& configurationPath);
		std::filesystem::path ResolveRuntimeExecutable() const;
		static std::optional<BinaryNinjaLayout> ValidateInstallation(
			const std::filesystem::path& installationDirectory, std::string& error);
		[[noreturn]] static void Execute(const LaunchPlan& plan, int argc, char* const argv[]);

		std::filesystem::path executablePath_;
	};
}  // namespace binjad::launcher
