#include "binjad/download/ZipArchive.hpp"

#include "binjad/platform/Paths.hpp"

#include <zip.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <system_error>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::download {
	namespace {
		struct SourceEntry
		{
			std::filesystem::path source;
			std::string archivePath;
			std::uint64_t size = 0;
		};

		bool WindowsReservedComponent(std::string_view component)
		{
			component = component.substr(0, component.find('.'));
			std::string upper;
			upper.reserve(component.size());
			for (const unsigned char character : component)
				upper.push_back(static_cast<char>(std::toupper(character)));
			if (upper == "CON" || upper == "PRN" || upper == "AUX" || upper == "NUL")
				return true;
			const bool reservedPrefix = upper.starts_with("COM") || upper.starts_with("LPT");
			return upper.size() == 4 && reservedPrefix && upper[3] >= '1' && upper[3] <= '9';
		}

		bool SafeArchivePath(std::string_view path)
		{
			if (path.empty() || path.front() == '/' || path.find('\\') != std::string_view::npos
				|| path.find(':') != std::string_view::npos)
				return false;
			std::size_t start = 0;
			while (start < path.size())
			{
				const auto end = path.find('/', start);
				const auto component =
					path.substr(start, end == std::string_view::npos ? path.size() - start : end - start);
				const bool unsafeName = component.empty() || component == "." || component == ".."
					|| component.back() == '.' || component.back() == ' ' || WindowsReservedComponent(component);
				const bool hasControl = std::any_of(component.begin(), component.end(), [](unsigned char character) {
					return std::iscntrl(character) != 0;
				});
				if (unsafeName || hasControl)
					return false;
				if (end == std::string_view::npos)
					break;
				start = end + 1;
			}
			return true;
		}

		zip_fileinfo FileInfo(bool directory)
		{
			zip_fileinfo result {};
			result.tmz_date.tm_mday = 1;
			result.tmz_date.tm_year = 1980;
			result.external_fa = static_cast<uLong>((directory ? 0040755 : 0100600) << 16);
			if (directory)
				result.external_fa |= 0x10;
			return result;
		}

		bool OpenEntry(zipFile archive, const SourceEntry& entry, bool directory)
		{
			const auto info = FileInfo(directory);
			const auto name = directory ? entry.archivePath + '/' : entry.archivePath;
			const bool zip64 = !directory && entry.size >= std::numeric_limits<std::uint32_t>::max();
			return zipOpenNewFileInZip4_64(archive, name.c_str(), &info, nullptr, 0, nullptr, 0, nullptr,
					   directory ? 0 : Z_DEFLATED, directory ? 0 : Z_DEFAULT_COMPRESSION, 0, -MAX_WBITS, DEF_MEM_LEVEL,
					   Z_DEFAULT_STRATEGY, nullptr, 0, (3u << 8) | 45u, 1u << 11, zip64 ? 1 : 0)
				== ZIP_OK;
		}

		void RemoveArchive(const std::filesystem::path& destination)
		{
			std::error_code ignored;
			std::filesystem::remove(destination, ignored);
		}
	}  // namespace

	ZipArchiveResult CreateZipArchive(const std::filesystem::path& sourceDirectory,
		const std::filesystem::path& destination, const ZipProgress& progress)
	{
		ZipArchiveResult result;
		const auto destinationRelative =
			destination.lexically_normal().lexically_relative(sourceDirectory.lexically_normal());
		if (!destinationRelative.empty() && !destinationRelative.is_absolute() && *destinationRelative.begin() != "..")
		{
			result.error = "ZIP destination must be outside the source directory";
			return result;
		}
		std::vector<SourceEntry> directories;
		std::vector<SourceEntry> files;
		std::unordered_set<std::string> portablePaths;
		try
		{
			const auto rootStatus = std::filesystem::symlink_status(sourceDirectory);
			if (std::filesystem::is_symlink(rootStatus) || !std::filesystem::is_directory(rootStatus))
			{
				result.error = "ZIP source is not a non-symlink directory";
				return result;
			}
			for (std::filesystem::recursive_directory_iterator iterator(sourceDirectory), end; iterator != end;
				++iterator)
			{
				const auto status = iterator->symlink_status();
				const auto relative = iterator->path().lexically_relative(sourceDirectory).generic_string();
				if (!SafeArchivePath(relative))
				{
					result.error = "ZIP source contains an unsafe path";
					return result;
				}
				std::string portable = relative;
				std::transform(portable.begin(), portable.end(), portable.begin(), [](unsigned char character) {
					return character < 0x80 ? static_cast<char>(std::tolower(character)) : static_cast<char>(character);
				});
				if (!portablePaths.insert(std::move(portable)).second)
				{
					result.error = "ZIP source contains paths that collide on a case-insensitive filesystem";
					return result;
				}
				if (std::filesystem::is_symlink(status))
				{
					result.error = "ZIP source contains a symbolic link";
					return result;
				}
				if (std::filesystem::is_directory(status))
				{
					directories.push_back({iterator->path(), relative, 0});
					continue;
				}
				if (!std::filesystem::is_regular_file(status))
				{
					result.error = "ZIP source contains an unsupported file type";
					return result;
				}
				const auto size = std::filesystem::file_size(iterator->path());
				if (size > std::numeric_limits<std::uint64_t>::max() - result.inputBytes)
				{
					result.error = "ZIP input size exceeds supported bounds";
					return result;
				}
				files.push_back({iterator->path(), relative, size});
				result.inputBytes += size;
			}
		}
		catch (const std::exception& exception)
		{
			result.error = exception.what();
			return result;
		}

		const auto byPath = [](const auto& left, const auto& right) {
			return left.archivePath < right.archivePath;
		};
		std::sort(directories.begin(), directories.end(), byPath);
		std::sort(files.begin(), files.end(), byPath);

		const auto placeholder = platform::CreatePrivateFileIfAbsent(destination, {});
		if (!placeholder.created || !placeholder.error.empty())
		{
			result.error = placeholder.error.empty() ? "cannot create ZIP destination" : placeholder.error;
			return result;
		}
		const auto destinationString = destination.string();
		zipFile archive = zipOpen64(destinationString.c_str(), APPEND_STATUS_CREATE);
		if (!archive)
		{
			RemoveArchive(destination);
			result.error = "cannot open ZIP destination";
			return result;
		}

		auto fail = [&](std::string error, bool cancelled = false) {
			(void)zipClose(archive, nullptr);
			RemoveArchive(destination);
			result.error = std::move(error);
			result.cancelled = cancelled;
			return result;
		};

		for (const auto& directory : directories)
		{
			if (progress && !progress(0, result.inputBytes, directory.archivePath))
				return fail("ZIP creation cancelled", true);
			if (!OpenEntry(archive, directory, true) || zipCloseFileInZip(archive) != ZIP_OK)
				return fail("cannot write ZIP directory entry");
			++result.directories;
		}

		std::vector<char> buffer(1024 * 1024);
		std::uint64_t completed = 0;
		for (const auto& file : files)
		{
			if (progress && !progress(completed, result.inputBytes, file.archivePath))
				return fail("ZIP creation cancelled", true);
			if (!OpenEntry(archive, file, false))
				return fail("cannot create ZIP file entry");
			std::ifstream input(file.source, std::ios::binary);
			if (!input)
				return fail("cannot open ZIP input file");
			while (input)
			{
				input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
				const auto count = input.gcount();
				if (count > 0
					&& zipWriteInFileInZip(archive, buffer.data(), static_cast<unsigned int>(count)) != ZIP_OK)
					return fail("cannot write ZIP file data");
				completed += static_cast<std::uint64_t>(count);
				if (progress && !progress(completed, result.inputBytes, file.archivePath))
					return fail("ZIP creation cancelled", true);
			}
			if (input.bad())
				return fail("cannot read ZIP input file");
			if (zipCloseFileInZip(archive) != ZIP_OK)
				return fail("cannot close ZIP file entry");
			++result.files;
		}

		if (zipClose(archive, nullptr) != ZIP_OK)
		{
			RemoveArchive(destination);
			result.error = "cannot finalize ZIP archive";
			return result;
		}
		try
		{
			result.archiveBytes = std::filesystem::file_size(destination);
		}
		catch (const std::exception& exception)
		{
			RemoveArchive(destination);
			result.error = exception.what();
			return result;
		}
		result.created = true;
		return result;
	}
}  // namespace binjad::download
