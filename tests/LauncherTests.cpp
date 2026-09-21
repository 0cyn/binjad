#include "binjad/launcher/Launcher.hpp"
#include "binjad/platform/Paths.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
	#include <sys/wait.h>
	#include <unistd.h>
#endif

namespace {
	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}

	void WriteFile(const std::filesystem::path& path, std::string_view contents = {})
	{
		std::ofstream stream(path, std::ios::binary | std::ios::trunc);
		if (!stream || !(stream << contents))
			throw std::runtime_error("cannot create launcher fixture: " + path.string());
	}

	struct TemporaryDirectory
	{
		std::filesystem::path path;

		~TemporaryDirectory()
		{
			std::error_code error;
			std::filesystem::remove_all(path, error);
		}
	};
}  // namespace

int main(int argc, char** argv)
{
	try
	{
		Require(argc > 0, "launcher test executable path is unavailable");
		if (const char* launched = std::getenv(binjad::launcher::kInstallationEnvironment.data());
			launched && *launched)
		{
			std::cout << "installation=" << launched << '\n';
			const char* search = nullptr;
#if defined(__APPLE__)
			search = std::getenv("DYLD_LIBRARY_PATH");
#elif defined(__linux__)
			search = std::getenv("LD_LIBRARY_PATH");
#elif defined(_WIN32)
			search = std::getenv("PATH");
#endif
			std::cout << "search=" << (search ? search : "") << '\n';
			std::cout << "bn_install_dir=" << (std::getenv("BN_INSTALL_DIR") ? "set" : "unset") << '\n';
			return 0;
		}

		const auto unique = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
		TemporaryDirectory temporary {std::filesystem::weakly_canonical(std::filesystem::temp_directory_path())
			/ ("binjad-launcher-tests-" + unique)};
		const auto privateError = binjad::platform::CreatePrivateDirectory(temporary.path);
		Require(privateError.empty(), privateError);

#if defined(_WIN32)
		const auto launcherPath = temporary.path / "binjad.exe";
		const auto runtimePath = temporary.path / "binjad-runtime.exe";
#else
		const auto launcherPath = temporary.path / "binjad";
		const auto runtimePath = temporary.path / "binjad-runtime";
#endif
		WriteFile(launcherPath, "launcher");
		std::filesystem::copy_file(std::filesystem::canonical(argv[0]), runtimePath);
		std::filesystem::permissions(
			runtimePath, std::filesystem::perms::owner_exec, std::filesystem::perm_options::add);

		const auto installation = temporary.path / "Binary Ninja";
#if defined(__APPLE__)
		const auto coreDirectory = installation / "Contents" / "MacOS";
		const auto revisionDirectory = installation / "Contents" / "Resources";
		const auto coreName = "libbinaryninjacore.1.dylib";
		const auto kernelCacheName = "libkernelcache.dylib";
		const auto sharedCacheName = "libsharedcache.dylib";
		const auto debuggerName = "libdebuggercore.dylib";
#elif defined(__linux__)
		const auto coreDirectory = installation;
		const auto revisionDirectory = installation;
		const auto coreName = "libbinaryninjacore.so.1";
		const auto kernelCacheName = "libkernelcache.so";
		const auto sharedCacheName = "libsharedcache.so";
		const auto debuggerName = "libdebuggercore.so";
#elif defined(_WIN32)
		const auto coreDirectory = installation;
		const auto revisionDirectory = installation;
		const auto coreName = "binaryninjacore.dll";
		const auto kernelCacheName = "kernelcache.dll";
		const auto sharedCacheName = "sharedcache.dll";
		const auto debuggerName = "debuggercore.dll";
#endif
		const auto pluginDirectory = coreDirectory / "plugins";
		std::filesystem::create_directories(pluginDirectory / "lldb" / "lib");
		std::filesystem::create_directories(revisionDirectory);
		WriteFile(coreDirectory / coreName);
		WriteFile(pluginDirectory / kernelCacheName);
		WriteFile(pluginDirectory / sharedCacheName);
		WriteFile(pluginDirectory / debuggerName);
		WriteFile(revisionDirectory / "api_REVISION.txt", "fixture\n");

		const auto configPath = temporary.path / "state" / "config.json";
		const std::string config =
			"{\"binary_ninja\":{\"installation_dir\":\"" + installation.generic_string() + "\"}}\n";
		const auto created = binjad::platform::CreatePrivateFileIfAbsent(configPath, config);
		Require(created.error.empty(), created.error);

		std::string argv0 = launcherPath.string();
		std::string option = "--config";
		std::string configArgument = configPath.string();
		char* arguments[] {argv0.data(), option.data(), configArgument.data(), nullptr};
		binjad::launcher::Launcher launcher(launcherPath);
		const auto defaultConfigPath = temporary.path / "default-state" / "config.json";
		std::string defaultConfigArgument = defaultConfigPath.string();
		char* defaultArguments[] {argv0.data(), option.data(), defaultConfigArgument.data(), nullptr};
		const auto defaultPreparation = launcher.Prepare(3, defaultArguments);
		Require(
			std::filesystem::is_regular_file(defaultConfigPath), "launcher did not create the default configuration");
		Require(
			defaultPreparation.configurationErrors.empty(), "launcher rejected the generated default configuration");

		const auto prepared = launcher.Prepare(3, arguments);
		Require(prepared.plan.has_value(), prepared.error);
		Require(prepared.configurationErrors.empty(), "launcher reported configuration errors");
		Require(prepared.plan->runtimeExecutable == runtimePath, "launcher selected the wrong runtime executable");
		Require(prepared.plan->binaryNinja.installationDirectory == installation,
			"launcher selected the wrong Binary Ninja root");
		Require(prepared.plan->binaryNinja.coreDirectory == coreDirectory,
			"launcher selected the wrong Binary Ninja core directory");

#if !defined(_WIN32)
		int outputDescriptors[2] {-1, -1};
		Require(::pipe(outputDescriptors) == 0, "cannot create launcher execution test pipe");
		const auto child = ::fork();
		Require(child >= 0, "cannot create launcher execution test process");
		if (child == 0)
		{
			::close(outputDescriptors[0]);
			if (::dup2(outputDescriptors[1], STDOUT_FILENO) < 0)
				::_exit(120);
			::close(outputDescriptors[1]);
			::setenv("BN_INSTALL_DIR", "/ignored/development/value", 1);
			::_exit(launcher.Run(3, arguments));
		}
		::close(outputDescriptors[1]);
		std::string output;
		char outputBuffer[1024];
		while (true)
		{
			const auto count = ::read(outputDescriptors[0], outputBuffer, sizeof(outputBuffer));
			if (count <= 0)
				break;
			output.append(outputBuffer, static_cast<std::size_t>(count));
		}
		::close(outputDescriptors[0]);
		int childStatus = 0;
		Require(::waitpid(child, &childStatus, 0) == child, "cannot wait for launcher execution test process");
		Require(WIFEXITED(childStatus) && WEXITSTATUS(childStatus) == 0, "launcher execution test process failed");
		Require(output.find("installation=" + installation.string()) != std::string::npos,
			"launcher did not pass the configured installation root");
		Require(output.find("search=" + coreDirectory.string()) != std::string::npos,
			"launcher did not pass the Binary Ninja library search path");
		Require(output.find("bn_install_dir=unset") != std::string::npos,
			"launcher retained the development BN_INSTALL_DIR variable");
#endif

		std::filesystem::remove(pluginDirectory / debuggerName);
		const auto missingPlugin = launcher.Prepare(3, arguments);
		Require(!missingPlugin.plan.has_value(), "launcher accepted a missing debugger library");
		Require(missingPlugin.error.find(debuggerName) != std::string::npos,
			"launcher did not identify the missing debugger library");

		std::cout << "Launcher tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "Launcher tests failed: " << exception.what() << '\n';
		return 1;
	}
}
