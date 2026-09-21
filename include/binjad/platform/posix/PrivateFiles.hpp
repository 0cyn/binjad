#pragma once

#include <filesystem>
#include <string>

namespace binjad::platform::posix {
	struct PrivateDirectoryOpenResult
	{
		int descriptor = -1;
		std::filesystem::path path;
		std::string error;
	};

	PrivateDirectoryOpenResult OpenPrivateDirectory(const std::filesystem::path& path);
	std::string ValidatePrivateDirectoryDescriptor(int descriptor, const std::filesystem::path& path);
	std::string ValidatePrivateFileDescriptor(int descriptor, const std::filesystem::path& path);
	std::string PreparePrivateFileDescriptor(int descriptor, const std::filesystem::path& path);
}  // namespace binjad::platform::posix
