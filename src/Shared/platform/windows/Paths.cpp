#include "binjad/platform/Paths.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstdlib>
#include <limits>
#include <stdexcept>

namespace binjad::platform {
	std::filesystem::path UserDataDirectory()
	{
		const char* localAppData = std::getenv("LOCALAPPDATA");
		if (!localAppData || !*localAppData)
			throw std::runtime_error("LOCALAPPDATA is not set");
		return std::filesystem::path(localAppData) / "binjad";
	}

	std::filesystem::path DefaultConfigPath()
	{
		return UserDataDirectory() / "config.json";
	}

	std::string CreatePrivateDirectory(const std::filesystem::path& path)
	{
		if (path.empty())
			return "private directory path must not be empty";
		std::error_code error;
		std::filesystem::create_directories(path, error);
		return error ? "cannot create private directory: " + error.message() : std::string {};
	}

	PrivateFileCreationResult CreatePrivateFileIfAbsent(const std::filesystem::path& path, std::string_view contents)
	{
		std::error_code error;
		std::filesystem::create_directories(path.parent_path(), error);
		if (error)
			return {false, "cannot create private file directory: " + error.message()};

		const HANDLE file =
			::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (file == INVALID_HANDLE_VALUE)
		{
			if (::GetLastError() == ERROR_FILE_EXISTS || ::GetLastError() == ERROR_ALREADY_EXISTS)
				return {};
			return {false, "cannot create private file: Windows error " + std::to_string(::GetLastError())};
		}

		while (!contents.empty())
		{
			const auto chunk =
				static_cast<DWORD>(std::min<std::size_t>(contents.size(), std::numeric_limits<DWORD>::max()));
			DWORD written = 0;
			if (!::WriteFile(file, contents.data(), chunk, &written, nullptr) || written == 0)
			{
				const auto code = ::GetLastError();
				::CloseHandle(file);
				::DeleteFileW(path.c_str());
				return {false, "cannot write private file: Windows error " + std::to_string(code)};
			}
			contents.remove_prefix(written);
		}
		if (!::FlushFileBuffers(file))
		{
			const auto code = ::GetLastError();
			::CloseHandle(file);
			::DeleteFileW(path.c_str());
			return {false, "cannot flush private file: Windows error " + std::to_string(code)};
		}
		if (!::CloseHandle(file))
		{
			::DeleteFileW(path.c_str());
			return {false, "cannot close private file: Windows error " + std::to_string(::GetLastError())};
		}
		return {true, {}};
	}

	PrivateFileReadResult ReadPrivateFile(const std::filesystem::path&)
	{
		return {{}, "strict private-file reading is not implemented for Windows"};
	}

	PrivateFileReplacementResult ReplacePrivateFile(const std::filesystem::path&, std::string_view)
	{
		return {false, "private atomic file replacement is not implemented for Windows"};
	}

	PrivateFileCopyResult CopyRegularFilePrivate(const std::filesystem::path&, const std::filesystem::path&)
	{
		return {{}, "private regular-file copying is not implemented for Windows"};
	}

	PrivateFileReplacementResult InstallRegularFileAtomically(
		const std::filesystem::path&, const std::filesystem::path&, bool)
	{
		return {false, "atomic regular-file installation is not implemented for Windows"};
	}
}  // namespace binjad::platform
