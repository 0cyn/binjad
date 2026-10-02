#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>

namespace binjad::download {
	struct ZipArchiveResult
	{
		bool created = false;
		bool cancelled = false;
		std::uint64_t files = 0;
		std::uint64_t directories = 0;
		std::uint64_t inputBytes = 0;
		std::uint64_t archiveBytes = 0;
		std::string error;
	};

	using ZipProgress = std::function<bool(std::uint64_t completed, std::uint64_t total, std::string_view currentPath)>;

	ZipArchiveResult CreateZipArchive(const std::filesystem::path& sourceDirectory,
		const std::filesystem::path& destination, const ZipProgress& progress = {});
}  // namespace binjad::download
