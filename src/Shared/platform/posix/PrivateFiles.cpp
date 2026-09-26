#include "binjad/platform/Paths.hpp"

#include <cerrno>
#include <array>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__)
	#include <sys/acl.h>
#elif defined(__linux__)
	#include <sys/xattr.h>
#endif

namespace binjad::platform {
	namespace {
		std::string ErrnoMessage(std::string_view operation, const std::filesystem::path& path)
		{
			return std::string(operation) + " '" + path.string() + "': " + std::strerror(errno);
		}

		std::string CreatePrivateDirectories(const std::filesystem::path& directory)
		{
			if (directory.empty())
				return {};

			std::filesystem::path current;
			for (const auto& component : directory)
			{
				current /= component;
				if (current == current.root_path())
					continue;
				if (::mkdir(current.c_str(), 0700) == 0)
					continue;
				if (errno != EEXIST)
					return ErrnoMessage("cannot create directory", current);

				struct stat metadata {};
				if (::stat(current.c_str(), &metadata) != 0)
					return ErrnoMessage("cannot inspect directory", current);
				if (!S_ISDIR(metadata.st_mode))
					return "path component is not a directory: '" + current.string() + "'";
			}
			return {};
		}

		bool WriteAll(int descriptor, std::string_view contents)
		{
			while (!contents.empty())
			{
				const auto written = ::write(descriptor, contents.data(), contents.size());
				if (written < 0)
				{
					if (errno == EINTR)
						continue;
					return false;
				}
				if (written == 0)
				{
					errno = EIO;
					return false;
				}
				contents.remove_prefix(static_cast<std::size_t>(written));
			}
			return true;
		}

		std::string FlushDirectory(const std::filesystem::path& path)
		{
			const auto parent = path.parent_path().empty() ? std::filesystem::path(".") : path.parent_path();
			const int directory = ::open(parent.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY);
			if (directory < 0)
				return ErrnoMessage("cannot open private file directory", parent);
			if (::fsync(directory) != 0)
			{
				const auto error = ErrnoMessage("cannot flush private file directory", parent);
				::close(directory);
				return error;
			}
			if (::close(directory) != 0)
				return ErrnoMessage("cannot close private file directory", parent);
			return {};
		}

		std::string ValidatePrivateMetadata(int descriptor, const std::filesystem::path& path)
		{
			struct stat metadata {};
			if (::fstat(descriptor, &metadata) != 0)
				return ErrnoMessage("cannot inspect private file", path);
			if (!S_ISREG(metadata.st_mode))
				return "private file is not a regular file: '" + path.string() + "'";
			if (metadata.st_uid != ::geteuid())
				return "private file is not owned by the current user: '" + path.string() + "'";
			if ((metadata.st_mode & 0077) != 0)
				return "private file permits group or other access: '" + path.string() + "'";
#if defined(__APPLE__)
			acl_t acl = ::acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
			if (!acl)
			{
				if (errno == ENOENT)
					return {};
				return ErrnoMessage("cannot inspect private file ACL", path);
			}
			acl_entry_t entry = nullptr;
			const int extended = ::acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
			::acl_free(acl);
			if (extended < 0)
				return ErrnoMessage("cannot inspect private file ACL", path);
			if (extended != 0)
				return "private file has an extended ACL: '" + path.string() + "'";
#elif defined(__linux__)
			if (::fgetxattr(descriptor, "system.posix_acl_access", nullptr, 0) >= 0)
				return "private file has an extended ACL: '" + path.string() + "'";
			if (errno != ENODATA && errno != ENOTSUP)
				return ErrnoMessage("cannot inspect private file ACL", path);
#endif
			return {};
		}

		std::filesystem::path TemporaryPath(const std::filesystem::path& path)
		{
			static std::atomic<std::uint64_t> sequence {0};
			return path.parent_path()
				/ (path.filename().string() + ".tmp." + std::to_string(::getpid()) + '.' + std::to_string(++sequence));
		}
	}  // namespace

	PrivateFileCreationResult CreatePrivateFileIfAbsent(const std::filesystem::path& path, std::string_view contents)
	{
		if (path.empty() || path.filename().empty())
			return {false, "private file path must name a file"};
		if (const auto error = CreatePrivateDirectories(path.parent_path()); !error.empty())
			return {false, error};

		const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (descriptor < 0)
		{
			if (errno == EEXIST)
				return {};
			return {false, ErrnoMessage("cannot create private file", path)};
		}

		if (!WriteAll(descriptor, contents))
		{
			const auto error = ErrnoMessage("cannot write private file", path);
			::close(descriptor);
			::unlink(path.c_str());
			return {false, error};
		}
		if (::fsync(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private file", path);
			::close(descriptor);
			::unlink(path.c_str());
			return {false, error};
		}
		if (::close(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot close private file", path);
			::unlink(path.c_str());
			return {false, error};
		}

		return {true, FlushDirectory(path)};
	}

	std::string CreatePrivateDirectory(const std::filesystem::path& path)
	{
		if (path.empty())
			return "private directory path must not be empty";
		return CreatePrivateDirectories(path);
	}

	PrivateFileReadResult ReadPrivateFile(const std::filesystem::path& path)
	{
		const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (descriptor < 0)
		{
			if (errno == ENOENT)
				return {};
			return {{}, ErrnoMessage("cannot open private file", path)};
		}
		if (const auto error = ValidatePrivateMetadata(descriptor, path); !error.empty())
		{
			::close(descriptor);
			return {{}, error};
		}

		std::string contents;
		std::array<char, 16384> buffer {};
		while (true)
		{
			const auto count = ::read(descriptor, buffer.data(), buffer.size());
			if (count > 0)
			{
				contents.append(buffer.data(), static_cast<std::size_t>(count));
				continue;
			}
			if (count == 0)
				break;
			if (errno == EINTR)
				continue;
			const auto error = ErrnoMessage("cannot read private file", path);
			::close(descriptor);
			return {{}, error};
		}
		if (::close(descriptor) != 0)
			return {{}, ErrnoMessage("cannot close private file", path)};
		return {std::move(contents), {}};
	}

	PrivateFileReplacementResult ReplacePrivateFile(const std::filesystem::path& path, std::string_view contents)
	{
		std::filesystem::path temporary;
		int descriptor = -1;
		for (int attempt = 0; attempt < 100; ++attempt)
		{
			temporary = TemporaryPath(path);
			descriptor = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
			if (descriptor >= 0)
				break;
			if (errno != EEXIST)
				return {false, ErrnoMessage("cannot create private temporary file", temporary)};
		}
		if (descriptor < 0)
			return {false, "cannot allocate a unique private temporary file"};

		if (!WriteAll(descriptor, contents))
		{
			const auto error = ErrnoMessage("cannot write private temporary file", temporary);
			::close(descriptor);
			::unlink(temporary.c_str());
			return {false, error};
		}
		if (::fsync(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private temporary file", temporary);
			::close(descriptor);
			::unlink(temporary.c_str());
			return {false, error};
		}
		if (::close(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot close private temporary file", temporary);
			::unlink(temporary.c_str());
			return {false, error};
		}
		if (::rename(temporary.c_str(), path.c_str()) != 0)
		{
			const auto error = ErrnoMessage("cannot install private file", path);
			::unlink(temporary.c_str());
			return {false, error};
		}
		return {true, FlushDirectory(path)};
	}

	PrivateFileCopyResult CopyRegularFilePrivate(
		const std::filesystem::path& source, const std::filesystem::path& destination)
	{
		if (const auto error = CreatePrivateDirectories(destination.parent_path()); !error.empty())
			return {{}, error};
		const int input = ::open(source.c_str(), O_RDONLY | O_CLOEXEC);
		if (input < 0)
			return {{}, ErrnoMessage("cannot open source file", source)};
		struct stat sourceMetadata {};
		if (::fstat(input, &sourceMetadata) != 0)
		{
			const auto error = ErrnoMessage("cannot inspect source file", source);
			::close(input);
			return {{}, error};
		}
		if (!S_ISREG(sourceMetadata.st_mode))
		{
			::close(input);
			return {{}, "source path does not resolve to a regular file: '" + source.string() + "'"};
		}
		const int output = ::open(destination.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
		if (output < 0)
		{
			const auto error = ErrnoMessage("cannot create private working copy", destination);
			::close(input);
			return {{}, error};
		}

		std::uint64_t total = 0;
		std::array<char, 65536> buffer {};
		while (true)
		{
			const auto count = ::read(input, buffer.data(), buffer.size());
			if (count > 0)
			{
				if (!WriteAll(output, std::string_view(buffer.data(), static_cast<std::size_t>(count))))
				{
					const auto error = ErrnoMessage("cannot write private working copy", destination);
					::close(input);
					::close(output);
					::unlink(destination.c_str());
					return {{}, error};
				}
				total += static_cast<std::uint64_t>(count);
				continue;
			}
			if (count == 0)
				break;
			if (errno == EINTR)
				continue;
			const auto error = ErrnoMessage("cannot read source file", source);
			::close(input);
			::close(output);
			::unlink(destination.c_str());
			return {{}, error};
		}
		if (::close(input) != 0)
		{
			const auto error = ErrnoMessage("cannot close source file", source);
			::close(output);
			::unlink(destination.c_str());
			return {{}, error};
		}
		if (::fsync(output) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private working copy", destination);
			::close(output);
			::unlink(destination.c_str());
			return {{}, error};
		}
		if (::close(output) != 0)
		{
			const auto error = ErrnoMessage("cannot close private working copy", destination);
			::unlink(destination.c_str());
			return {{}, error};
		}
		if (const auto error = FlushDirectory(destination); !error.empty())
			return {total, error};
		return {total, {}};
	}

	PrivateFileReplacementResult InstallRegularFileAtomically(
		const std::filesystem::path& source, const std::filesystem::path& destination, bool replaceExisting)
	{
		if (destination.empty() || destination.filename().empty())
			return {false, "destination must name a file"};
		const int input = ::open(source.c_str(), O_RDONLY | O_CLOEXEC);
		if (input < 0)
			return {false, ErrnoMessage("cannot open saved database", source)};
		struct stat metadata {};
		if (::fstat(input, &metadata) != 0 || !S_ISREG(metadata.st_mode))
		{
			::close(input);
			return {false, "saved database is not a regular file"};
		}
		mode_t destinationMode = 0600;
		if (replaceExisting)
		{
			struct stat destinationMetadata {};
			if (::lstat(destination.c_str(), &destinationMetadata) != 0 || !S_ISREG(destinationMetadata.st_mode))
			{
				::close(input);
				return {false, "save destination is not an existing regular file"};
			}
			destinationMode = destinationMetadata.st_mode & 0777;
		}

		std::filesystem::path temporary;
		int output = -1;
		for (int attempt = 0; attempt < 100; ++attempt)
		{
			temporary = TemporaryPath(destination);
			output = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, destinationMode);
			if (output >= 0)
				break;
			if (errno != EEXIST)
			{
				const auto error = ErrnoMessage("cannot create save temporary file", temporary);
				::close(input);
				return {false, error};
			}
		}
		if (output < 0)
		{
			::close(input);
			return {false, "cannot allocate a unique save temporary file"};
		}
		if (::fchmod(output, destinationMode) != 0)
		{
			const auto error = ErrnoMessage("cannot set save temporary permissions", temporary);
			::close(input);
			::close(output);
			::unlink(temporary.c_str());
			return {false, error};
		}

		std::array<char, 65536> buffer {};
		while (true)
		{
			const auto count = ::read(input, buffer.data(), buffer.size());
			if (count > 0)
			{
				if (!WriteAll(output, std::string_view(buffer.data(), static_cast<std::size_t>(count))))
				{
					const auto error = ErrnoMessage("cannot write save temporary file", temporary);
					::close(input);
					::close(output);
					::unlink(temporary.c_str());
					return {false, error};
				}
				continue;
			}
			if (count == 0)
				break;
			if (errno == EINTR)
				continue;
			const auto error = ErrnoMessage("cannot read saved database", source);
			::close(input);
			::close(output);
			::unlink(temporary.c_str());
			return {false, error};
		}
		std::string flushError;
		if (::close(input) != 0)
			flushError = ErrnoMessage("cannot close saved database", source);
		if (::fsync(output) != 0 && flushError.empty())
			flushError = ErrnoMessage("cannot flush saved database", temporary);
		if (::close(output) != 0 && flushError.empty())
			flushError = ErrnoMessage("cannot close saved database", temporary);
		if (!flushError.empty())
		{
			::unlink(temporary.c_str());
			return {false, flushError};
		}

		if (replaceExisting)
		{
			if (::rename(temporary.c_str(), destination.c_str()) != 0)
			{
				const auto error = ErrnoMessage("cannot replace save destination", destination);
				::unlink(temporary.c_str());
				return {false, error};
			}
		}
		else
		{
			if (::link(temporary.c_str(), destination.c_str()) != 0)
			{
				const auto error = errno == EEXIST ?
					std::string("save destination already exists") :
					ErrnoMessage("cannot install save destination", destination);
				::unlink(temporary.c_str());
				return {false, error};
			}
			::unlink(temporary.c_str());
		}
		return {true, FlushDirectory(destination)};
	}
}  // namespace binjad::platform
