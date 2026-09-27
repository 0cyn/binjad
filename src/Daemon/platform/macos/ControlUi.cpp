#include "binjad/platform/ControlUi.hpp"

#include "binjad/platform/Paths.hpp"
#include "binjad/platform/macos/MachBootstrap.hpp"

#include <spawn.h>
#include <sys/wait.h>

#include <cerrno>
#include <cstring>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

extern char** environ;

#ifndef BINJAD_SERVICE_EXECUTABLE
	#define BINJAD_SERVICE_EXECUTABLE ""
#endif

namespace binjad::platform {
	namespace {
		constexpr std::string_view kBundleName = "binjad-menubar.app";

		std::filesystem::path CanonicalPath(const std::filesystem::path& path)
		{
			std::error_code error;
			auto canonical = std::filesystem::weakly_canonical(path, error);
			return error ? std::filesystem::path {} : canonical;
		}

		std::string LaunchControlUiImpl(const std::filesystem::path& executable,
			const std::filesystem::path& configPath, const Config& config)
		{
			const std::filesystem::path serviceExecutable(BINJAD_SERVICE_EXECUTABLE);
			if (serviceExecutable.empty())
				return {};

			// Development and integration-test daemons must not retarget the one installed status item.
			const auto runningExecutable = CanonicalPath(executable);
			const auto installedExecutable = CanonicalPath(serviceExecutable);
			if (runningExecutable.empty() || installedExecutable.empty() || runningExecutable != installedExecutable)
				return {};
			const auto runningConfig = CanonicalPath(configPath);
			const auto installedConfig = CanonicalPath(DefaultConfigPath());
			if (runningConfig.empty() || installedConfig.empty() || runningConfig != installedConfig)
				return {};

			const auto formulaPrefix = serviceExecutable.parent_path().parent_path();
			if (formulaPrefix.empty() || formulaPrefix.parent_path().filename() != "opt")
				return "installed service executable is not beneath a Homebrew opt prefix";
			const auto formula = formulaPrefix.filename().string();
			const auto brew = formulaPrefix.parent_path().parent_path() / "bin" / "brew";
			const auto bundle = formulaPrefix / "libexec" / kBundleName;
			if (!std::filesystem::is_regular_file(brew))
				return "Homebrew executable is unavailable at " + brew.string();
			if (!std::filesystem::is_directory(bundle))
				return "menu bar application is unavailable at " + bundle.string();

			const auto portalUrl = config.http.publicBaseUrl + config.http.portalPath;
			std::vector<std::string> argumentStorage {
				"open",
				"-g",
				bundle.string(),
				"--args",
				"--brew-path",
				brew.string(),
				"--formula",
				formula,
				"--service-label",
				std::string(macos::kMachServiceName),
				"--config-path",
				installedConfig.string(),
				"--portal-url",
				portalUrl,
			};
			std::vector<char*> arguments;
			arguments.reserve(argumentStorage.size() + 1);
			for (auto& argument : argumentStorage)
				arguments.push_back(argument.data());
			arguments.push_back(nullptr);

			pid_t process = 0;
			const int spawnResult = posix_spawn(&process, "/usr/bin/open", nullptr, nullptr, arguments.data(), environ);
			if (spawnResult != 0)
				return "cannot launch menu bar application: " + std::string(std::strerror(spawnResult));

			int status = 0;
			while (waitpid(process, &status, 0) < 0)
			{
				if (errno == EINTR)
					continue;
				return "cannot wait for menu bar application launcher: " + std::string(std::strerror(errno));
			}
			if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
				return "macOS could not open the menu bar application";
			return {};
		}
	}  // namespace

	std::string LaunchControlUi(const std::filesystem::path& executable, const std::filesystem::path& configPath,
		const Config& config)
	{
		try
		{
			return LaunchControlUiImpl(executable, configPath, config);
		}
		catch (const std::exception& exception)
		{
			return "cannot launch menu bar application: " + std::string(exception.what());
		}
	}
}  // namespace binjad::platform
