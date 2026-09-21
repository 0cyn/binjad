#include "binjad/launcher/Launcher.hpp"

#include "binjad/process/Role.hpp"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <initializer_list>
#include <stdexcept>
#include <system_error>
#include <utility>

#if defined(__APPLE__)
	#include <mach-o/dyld.h>
	#include <unistd.h>
#elif defined(__linux__)
	#include <unistd.h>
#elif defined(_WIN32)
	#include <Windows.h>
	#include <process.h>
#endif

namespace binjad::launcher {
	namespace {
#if defined(_WIN32)
		constexpr char kSearchPathSeparator = ';';
#else
		constexpr char kSearchPathSeparator = ':';
#endif

		std::string JoinSearchPath(const BinaryNinjaLayout& layout)
		{
			return layout.coreDirectory.string() + kSearchPathSeparator + layout.pluginDirectory.string()
				+ kSearchPathSeparator + layout.lldbLibraryDirectory.string();
		}

#if defined(__linux__)
		std::string JoinPreloadLibraries(const BinaryNinjaLayout& layout)
		{
			return layout.coreLibrary.string() + kSearchPathSeparator + layout.kernelCacheLibrary.string()
				+ kSearchPathSeparator + layout.sharedCacheLibrary.string() + kSearchPathSeparator
				+ layout.debuggerLibrary.string();
		}
#endif

		bool IsRegularFile(const std::filesystem::path& path)
		{
			std::error_code error;
			return std::filesystem::is_regular_file(path, error) && !error;
		}

		std::optional<std::filesystem::path> FirstRegularFile(
			const std::filesystem::path& directory, const std::initializer_list<std::string_view> names)
		{
			for (const auto name : names)
			{
				const auto candidate = directory / name;
				if (IsRegularFile(candidate))
					return candidate;
			}
			return std::nullopt;
		}

		void SetEnvironment(std::string_view name, std::string_view value)
		{
#if defined(_WIN32)
			if (::_putenv_s(std::string(name).c_str(), std::string(value).c_str()) != 0)
				throw std::runtime_error("cannot set launcher environment variable " + std::string(name));
#else
			if (::setenv(std::string(name).c_str(), std::string(value).c_str(), 1) != 0)
				throw std::system_error(
					errno, std::generic_category(), "cannot set launcher environment variable " + std::string(name));
#endif
		}

		void RemoveEnvironment(std::string_view name)
		{
#if defined(_WIN32)
			if (::_putenv_s(std::string(name).c_str(), "") != 0)
				throw std::runtime_error("cannot clear launcher environment variable " + std::string(name));
#else
			if (::unsetenv(std::string(name).c_str()) != 0)
				throw std::system_error(
					errno, std::generic_category(), "cannot clear launcher environment variable " + std::string(name));
#endif
		}
	}  // namespace

	Launcher::Launcher(std::filesystem::path executablePath) :
		executablePath_(std::filesystem::weakly_canonical(std::move(executablePath)))
	{
		if (executablePath_.empty() || !IsRegularFile(executablePath_))
			throw std::invalid_argument("launcher executable path must name a regular file");
	}

	std::filesystem::path Launcher::CurrentExecutablePath()
	{
#if defined(__APPLE__)
		std::uint32_t size = 0;
		_NSGetExecutablePath(nullptr, &size);
		std::vector<char> buffer(size + 1);
		if (_NSGetExecutablePath(buffer.data(), &size) != 0)
			throw std::runtime_error("cannot determine the launcher executable path");
		return std::filesystem::weakly_canonical(buffer.data());
#elif defined(__linux__)
		std::vector<char> buffer(1024);
		while (true)
		{
			const auto length = ::readlink("/proc/self/exe", buffer.data(), buffer.size());
			if (length < 0)
				throw std::system_error(
					errno, std::generic_category(), "cannot determine the launcher executable path");
			if (static_cast<std::size_t>(length) < buffer.size())
				return std::filesystem::weakly_canonical(std::string(buffer.data(), static_cast<std::size_t>(length)));
			buffer.resize(buffer.size() * 2);
		}
#elif defined(_WIN32)
		std::vector<wchar_t> buffer(1024);
		while (true)
		{
			const auto length = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
			if (length == 0)
				throw std::runtime_error("cannot determine the launcher executable path");
			if (length < buffer.size() - 1)
				return std::filesystem::weakly_canonical(std::wstring(buffer.data(), length));
			buffer.resize(buffer.size() * 2);
		}
#else
		throw std::runtime_error("launcher executable discovery is not implemented for this platform");
#endif
	}

	std::filesystem::path Launcher::ResolveRuntimeExecutable() const
	{
#if defined(_WIN32)
		constexpr std::string_view runtimeName = "binjad-runtime.exe";
#else
		constexpr std::string_view runtimeName = "binjad-runtime";
#endif
		const auto sibling = executablePath_.parent_path() / runtimeName;
		if (IsRegularFile(sibling))
			return sibling;
		const auto installed = executablePath_.parent_path().parent_path() / "libexec" / runtimeName;
		if (IsRegularFile(installed))
			return installed;
		throw std::runtime_error(
			"Binary Ninja runtime executable was not found at " + sibling.string() + " or " + installed.string());
	}

	std::optional<BinaryNinjaLayout> Launcher::ValidateInstallation(
		const std::filesystem::path& installationDirectory, std::string& error)
	{
		BinaryNinjaLayout layout;
		layout.installationDirectory = installationDirectory.lexically_normal();
		std::error_code filesystemError;
		if (!std::filesystem::is_directory(layout.installationDirectory, filesystemError) || filesystemError)
		{
			error = "Binary Ninja installation directory is unavailable: " + layout.installationDirectory.string();
			return std::nullopt;
		}

#if defined(__APPLE__)
		layout.coreDirectory = layout.installationDirectory / "Contents" / "MacOS";
		layout.apiRevisionFile = layout.installationDirectory / "Contents" / "Resources" / "api_REVISION.txt";
		const std::initializer_list<std::string_view> coreNames {
			"libbinaryninjacore.1.dylib", "libbinaryninjacore.dylib"};
		constexpr std::string_view kernelCacheName = "libkernelcache.dylib";
		constexpr std::string_view sharedCacheName = "libsharedcache.dylib";
		constexpr std::string_view debuggerName = "libdebuggercore.dylib";
#elif defined(__linux__)
		layout.coreDirectory = layout.installationDirectory;
		layout.apiRevisionFile = layout.installationDirectory / "api_REVISION.txt";
		const std::initializer_list<std::string_view> coreNames {"libbinaryninjacore.so.1", "libbinaryninjacore.so"};
		constexpr std::string_view kernelCacheName = "libkernelcache.so";
		constexpr std::string_view sharedCacheName = "libsharedcache.so";
		constexpr std::string_view debuggerName = "libdebuggercore.so";
#elif defined(_WIN32)
		layout.coreDirectory = layout.installationDirectory;
		layout.apiRevisionFile = layout.installationDirectory / "api_REVISION.txt";
		const std::initializer_list<std::string_view> coreNames {"binaryninjacore.dll"};
		constexpr std::string_view kernelCacheName = "kernelcache.dll";
		constexpr std::string_view sharedCacheName = "sharedcache.dll";
		constexpr std::string_view debuggerName = "debuggercore.dll";
#else
		error = "Binary Ninja installation validation is not implemented for this platform";
		return std::nullopt;
#endif
		layout.pluginDirectory = layout.coreDirectory / "plugins";
		layout.lldbLibraryDirectory = layout.pluginDirectory / "lldb" / "lib";

		const auto coreLibrary = FirstRegularFile(layout.coreDirectory, coreNames);
		if (!coreLibrary)
		{
			error = "Binary Ninja core library was not found in " + layout.coreDirectory.string();
			return std::nullopt;
		}
		layout.coreLibrary = *coreLibrary;
		layout.kernelCacheLibrary = layout.pluginDirectory / kernelCacheName;
		layout.sharedCacheLibrary = layout.pluginDirectory / sharedCacheName;
		layout.debuggerLibrary = layout.pluginDirectory / debuggerName;
		for (const auto& library : {layout.kernelCacheLibrary, layout.sharedCacheLibrary, layout.debuggerLibrary})
		{
			if (!IsRegularFile(library))
			{
				error = "required Binary Ninja plugin library was not found: " + library.string();
				return std::nullopt;
			}
		}
		if (!IsRegularFile(layout.apiRevisionFile))
		{
			error = "Binary Ninja API revision file was not found: " + layout.apiRevisionFile.string();
			return std::nullopt;
		}
		return layout;
	}

	LaunchPlanResult Launcher::Prepare(int argc, char* const argv[]) const
	{
		LaunchPlanResult result;
		const auto selectedConfig = SelectConfigPath(argc, argv);
		if (!selectedConfig.path)
		{
			result.error = selectedConfig.error;
			return result;
		}

		const auto configuration = LoadConfiguration(*selectedConfig.path);
		if (!configuration.config)
		{
			result.configurationErrors = configuration.errors;
			return result;
		}

		std::string installationError;
		auto installation = ValidateInstallation(configuration.config->installationDirectory, installationError);
		if (!installation)
		{
			result.error = std::move(installationError);
			return result;
		}

		try
		{
			result.plan = LaunchPlan {*selectedConfig.path, ResolveRuntimeExecutable(), std::move(*installation)};
		}
		catch (const std::exception& exception)
		{
			result.error = exception.what();
		}
		return result;
	}

	[[noreturn]] void Launcher::Execute(const LaunchPlan& plan, int argc, char* const argv[])
	{
		const auto searchPath = JoinSearchPath(plan.binaryNinja);
#if defined(__APPLE__)
		SetEnvironment("DYLD_LIBRARY_PATH", searchPath);
		SetEnvironment("DYLD_FALLBACK_LIBRARY_PATH", searchPath);
#elif defined(__linux__)
		SetEnvironment("LD_LIBRARY_PATH", searchPath);
		SetEnvironment("LD_PRELOAD", JoinPreloadLibraries(plan.binaryNinja));
#elif defined(_WIN32)
		std::string windowsPath = searchPath;
		if (const char* existingPath = std::getenv("PATH"); existingPath && *existingPath)
			windowsPath += kSearchPathSeparator + std::string(existingPath);
		SetEnvironment("PATH", windowsPath);
#endif
		SetEnvironment(kInstallationEnvironment, plan.binaryNinja.installationDirectory.string());
		RemoveEnvironment("BN_INSTALL_DIR");

		std::string runtimeArgv0 = plan.runtimeExecutable.string();
		if (argc > 0 && RoleFromArgv0(argv[0]) != ProcessRole::Overseer)
			runtimeArgv0 = std::filesystem::path(argv[0]).filename().string();
		std::vector<char*> arguments;
		arguments.reserve(static_cast<std::size_t>(argc) + 1);
		arguments.push_back(runtimeArgv0.data());
		for (int index = 1; index < argc; ++index)
			arguments.push_back(argv[index]);
		arguments.push_back(nullptr);

#if defined(_WIN32)
		::_execv(plan.runtimeExecutable.string().c_str(), arguments.data());
#else
		::execv(plan.runtimeExecutable.c_str(), arguments.data());
#endif
		throw std::system_error(
			errno, std::generic_category(), "cannot execute Binary Ninja runtime " + plan.runtimeExecutable.string());
	}

	int Launcher::Run(int argc, char* const argv[]) const
	{
		const auto prepared = Prepare(argc, argv);
		if (!prepared.plan)
		{
			if (!prepared.error.empty())
				std::cerr << "binjad launcher: " << prepared.error << '\n';
			for (const auto& error : prepared.configurationErrors)
				std::cerr << "binjad launcher: configuration " << error.path << ": " << error.message << '\n';
			return EXIT_FAILURE;
		}
		try
		{
			Execute(*prepared.plan, argc, argv);
		}
		catch (const std::exception& exception)
		{
			std::cerr << "binjad launcher: " << exception.what() << '\n';
			return EXIT_FAILURE;
		}
	}
}  // namespace binjad::launcher
