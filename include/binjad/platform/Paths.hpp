#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::platform {
	struct PrivateFileCreationResult
	{
		bool created = false;
		std::string error;
	};

	struct PrivateFileReadResult
	{
		std::optional<std::string> contents;
		std::string error;
	};

	struct PrivateFileReplacementResult
	{
		bool installed = false;
		std::string error;
	};

	struct PrivateFileCopyResult
	{
		std::optional<std::uint64_t> bytesCopied;
		std::string error;
	};

	std::filesystem::path UserDataDirectory();
	std::filesystem::path HomeDirectory();
	std::filesystem::path DefaultConfigPath();
	std::filesystem::path DefaultBinaryNinjaInstallationDirectory();
	std::string CreatePrivateDirectory(const std::filesystem::path& path);
	PrivateFileCreationResult CreatePrivateFileIfAbsent(const std::filesystem::path& path, std::string_view contents);
	PrivateFileReadResult ReadPrivateFile(const std::filesystem::path& path);
	PrivateFileReplacementResult ReplacePrivateFile(const std::filesystem::path& path, std::string_view contents);
	PrivateFileCopyResult CopyRegularFilePrivate(
		const std::filesystem::path& source, const std::filesystem::path& destination);
	PrivateFileReplacementResult InstallRegularFileAtomically(
		const std::filesystem::path& source, const std::filesystem::path& destination, bool replaceExisting);
}  // namespace binjad::platform
