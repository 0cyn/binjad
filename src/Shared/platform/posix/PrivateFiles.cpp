#include "binjad/platform/Paths.hpp"
#include "binjad/platform/posix/PrivateFiles.hpp"

#include <cerrno>
#include <array>
#include <atomic>
#include <cstring>
#include <cstdint>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#if defined(__APPLE__)
	#include <sys/acl.h>
	#include <sys/stdio.h>
#elif defined(__linux__)
	#include <linux/fs.h>
	#include <sys/syscall.h>
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

		std::string ValidateAcl(int descriptor, const std::filesystem::path& path, bool directory)
		{
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
				return std::string(directory ? "private directory" : "private file") + " has an extended ACL: '"
					+ path.string() + "'";
#elif defined(__linux__)
			if (::fgetxattr(descriptor, "system.posix_acl_access", nullptr, 0) >= 0)
				return std::string(directory ? "private directory" : "private file") + " has an extended ACL: '"
					+ path.string() + "'";
			if (errno != ENODATA && errno != ENOTSUP)
				return ErrnoMessage(
					directory ? "cannot inspect private directory ACL" : "cannot inspect private file ACL", path);
			if (directory)
			{
				if (::fgetxattr(descriptor, "system.posix_acl_default", nullptr, 0) >= 0)
					return "private directory has a default ACL: '" + path.string() + "'";
				if (errno != ENODATA && errno != ENOTSUP)
					return ErrnoMessage("cannot inspect private directory default ACL", path);
			}
#endif
			return {};
		}

		std::string RemoveAcl(int descriptor, const std::filesystem::path& path)
		{
#if defined(__APPLE__)
			acl_t acl = ::acl_init(0);
			if (!acl)
				return ErrnoMessage("cannot allocate an empty private file ACL", path);
			const int result = ::acl_set_fd_np(descriptor, acl, ACL_TYPE_EXTENDED);
			::acl_free(acl);
			if (result != 0)
				return ErrnoMessage("cannot clear private file ACL", path);
#elif defined(__linux__)
			if (::fremovexattr(descriptor, "system.posix_acl_access") != 0 && errno != ENODATA && errno != ENOTSUP)
				return ErrnoMessage("cannot clear private file ACL", path);
#endif
			return {};
		}

		std::string ValidateAncestorAcl(int descriptor, const std::filesystem::path& path)
		{
#if defined(__APPLE__)
			acl_t acl = ::acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
			if (!acl)
			{
				if (errno == ENOENT)
					return {};
				return ErrnoMessage("cannot inspect private path ancestor ACL", path);
			}
			acl_entry_t entry = nullptr;
			int status = ::acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
			while (status == 1)
			{
				acl_tag_t tag {};
				if (::acl_get_tag_type(entry, &tag) != 0)
				{
					::acl_free(acl);
					return ErrnoMessage("cannot inspect private path ancestor ACL entry", path);
				}
				if (tag == ACL_EXTENDED_ALLOW)
				{
					::acl_free(acl);
					return "private path ancestor has an allow ACL: '" + path.string() + "'";
				}
				status = ::acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
			}
			::acl_free(acl);
			if (status < 0)
				return ErrnoMessage("cannot inspect private path ancestor ACL", path);
#elif defined(__linux__)
			if (::fgetxattr(descriptor, "system.posix_acl_access", nullptr, 0) >= 0)
				return "private path ancestor has an access ACL: '" + path.string() + "'";
			if (errno != ENODATA && errno != ENOTSUP)
				return ErrnoMessage("cannot inspect private path ancestor ACL", path);
			if (::fgetxattr(descriptor, "system.posix_acl_default", nullptr, 0) >= 0)
				return "private path ancestor has a default ACL: '" + path.string() + "'";
			if (errno != ENODATA && errno != ENOTSUP)
				return ErrnoMessage("cannot inspect private path ancestor default ACL", path);
#endif
			return {};
		}

		std::string ValidateAncestorDirectory(int descriptor, const std::filesystem::path& path)
		{
			struct stat metadata {};
			if (::fstat(descriptor, &metadata) != 0)
				return ErrnoMessage("cannot inspect private path ancestor", path);
			if (!S_ISDIR(metadata.st_mode))
				return "private path ancestor is not a directory: '" + path.string() + "'";
			if (metadata.st_uid != 0 && metadata.st_uid != ::geteuid())
				return "private path ancestor has an untrusted owner: '" + path.string() + "'";
			if ((metadata.st_mode & 0022) != 0 && !(metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX) != 0))
				return "private path ancestor permits untrusted writes: '" + path.string() + "'";
			return ValidateAncestorAcl(descriptor, path);
		}

		std::filesystem::path TemporaryPath(const std::filesystem::path& path)
		{
			static std::atomic<std::uint64_t> sequence {0};
			return path.parent_path()
				/ (path.filename().string() + ".tmp." + std::to_string(::getpid()) + '.' + std::to_string(++sequence));
		}

		int RenameNoReplace(int directory, const char* source, const char* destination)
		{
#if defined(__APPLE__)
			return ::renameatx_np(directory, source, directory, destination, RENAME_EXCL);
#elif defined(__linux__)
			return static_cast<int>(
				::syscall(SYS_renameat2, directory, source, directory, destination, RENAME_NOREPLACE));
#else
			(void)directory;
			(void)source;
			(void)destination;
			errno = ENOTSUP;
			return -1;
#endif
		}
	}  // namespace

	namespace posix {
		PrivateDirectoryOpenResult OpenPrivateDirectory(const std::filesystem::path& path)
		{
			std::filesystem::path normalized;
			try
			{
				normalized = std::filesystem::absolute(path).lexically_normal();
			}
			catch (const std::filesystem::filesystem_error& error)
			{
				return {-1, {}, std::string("cannot resolve private directory: ") + error.what()};
			}
			if (normalized.empty() || !normalized.is_absolute())
				return {-1, {}, "private directory must resolve to an absolute path"};

			std::vector<std::string> components;
			for (const auto& component : normalized.relative_path())
			{
				if (component != ".")
					components.push_back(component.string());
			}
			if (components.empty())
				return {-1, {}, "private directory must not be the filesystem root"};

			int current = ::open("/", O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
			if (current < 0)
				return {-1, {}, ErrnoMessage("cannot open private path root", "/")};
			if (const auto error = ValidateAncestorDirectory(current, "/"); !error.empty())
			{
				::close(current);
				return {-1, {}, error};
			}

			std::filesystem::path currentPath = "/";
			for (std::size_t index = 0; index < components.size(); ++index)
			{
				const int next =
					::openat(current, components[index].c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
				currentPath /= components[index];
				if (next < 0)
				{
					const auto error = ErrnoMessage("cannot open private directory", currentPath);
					::close(current);
					return {-1, {}, error};
				}
				::close(current);
				current = next;
				const auto error = index + 1 == components.size() ?
					ValidatePrivateDirectoryDescriptor(current, currentPath) :
					ValidateAncestorDirectory(current, currentPath);
				if (!error.empty())
				{
					::close(current);
					return {-1, {}, error};
				}
			}
			return {current, std::move(normalized), {}};
		}

		std::string ValidatePrivateDirectoryDescriptor(int descriptor, const std::filesystem::path& path)
		{
			struct stat metadata {};
			if (::fstat(descriptor, &metadata) != 0)
				return ErrnoMessage("cannot inspect private directory", path);
			if (!S_ISDIR(metadata.st_mode))
				return "private directory is not a directory: '" + path.string() + "'";
			if (metadata.st_uid != ::geteuid())
				return "private directory is not owned by the current user: '" + path.string() + "'";
			if ((metadata.st_mode & 0022) != 0)
				return "private directory permits group or other writes: '" + path.string() + "'";
			return ValidateAcl(descriptor, path, true);
		}

		std::string ValidatePrivateFileDescriptor(int descriptor, const std::filesystem::path& path)
		{
			struct stat metadata {};
			if (::fstat(descriptor, &metadata) != 0)
				return ErrnoMessage("cannot inspect private file", path);
			if (!S_ISREG(metadata.st_mode))
				return "private file is not a regular file: '" + path.string() + "'";
			if (metadata.st_uid != ::geteuid())
				return "private file is not owned by the current user: '" + path.string() + "'";
			if (metadata.st_nlink != 1)
				return "private file has multiple hard links: '" + path.string() + "'";
			if ((metadata.st_mode & 0077) != 0)
				return "private file permits group or other access: '" + path.string() + "'";
			return ValidateAcl(descriptor, path, false);
		}

		std::string PreparePrivateFileDescriptor(int descriptor, const std::filesystem::path& path)
		{
			if (::fchmod(descriptor, 0600) != 0)
				return ErrnoMessage("cannot set private file permissions", path);
			if (const auto error = RemoveAcl(descriptor, path); !error.empty())
				return error;
			if (::fchmod(descriptor, 0600) != 0)
				return ErrnoMessage("cannot reset private file permissions", path);
			return ValidatePrivateFileDescriptor(descriptor, path);
		}
	}  // namespace posix

	PrivateFileCreationResult CreatePrivateFileIfAbsent(const std::filesystem::path& path, std::string_view contents)
	{
		if (path.empty() || path.filename().empty())
			return {false, "private file path must name a file"};
		if (const auto error = CreatePrivateDirectories(path.parent_path()); !error.empty())
			return {false, error};
		auto directory = posix::OpenPrivateDirectory(path.parent_path());
		if (!directory.error.empty())
			return {false, directory.error};
		const auto filename = path.filename().string();
		const int existing = ::openat(directory.descriptor, filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (existing >= 0)
		{
			const auto error = posix::ValidatePrivateFileDescriptor(existing, path);
			::close(existing);
			::close(directory.descriptor);
			return {false, error};
		}
		if (errno != ENOENT)
		{
			const auto error = ErrnoMessage("cannot inspect private file", path);
			::close(directory.descriptor);
			return {false, error};
		}

		const auto temporary = TemporaryPath(path);
		const auto temporaryName = temporary.filename().string();
		const int descriptor = ::openat(directory.descriptor, temporaryName.c_str(),
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(0600));
		if (descriptor < 0)
		{
			const auto error = ErrnoMessage("cannot create private temporary file", temporary);
			::close(directory.descriptor);
			return {false, error};
		}
		if (const auto error = posix::PreparePrivateFileDescriptor(descriptor, temporary); !error.empty())
		{
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}

		if (!WriteAll(descriptor, contents))
		{
			const auto error = ErrnoMessage("cannot write private temporary file", temporary);
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (const auto error = posix::ValidatePrivateFileDescriptor(descriptor, temporary); !error.empty())
		{
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::fsync(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private temporary file", temporary);
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::close(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot close private temporary file", temporary);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (RenameNoReplace(directory.descriptor, temporaryName.c_str(), filename.c_str()) != 0)
		{
			const auto error = errno == EEXIST ? std::string {} : ErrnoMessage("cannot install private file", path);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::fsync(directory.descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private file directory", directory.path);
			::close(directory.descriptor);
			return {true, error};
		}
		if (::close(directory.descriptor) != 0)
			return {true, ErrnoMessage("cannot close private file directory", directory.path)};
		return {true, {}};
	}

	std::string CreatePrivateDirectory(const std::filesystem::path& path)
	{
		if (path.empty())
			return "private directory path must not be empty";
		return CreatePrivateDirectories(path);
	}

	PrivateFileReadResult ReadPrivateFile(const std::filesystem::path& path)
	{
		if (path.empty() || path.filename().empty())
			return {{}, "private file path must name a file"};
		auto directory = posix::OpenPrivateDirectory(path.parent_path());
		if (!directory.error.empty())
			return {{}, directory.error};
		const auto filename = path.filename().string();
		const int descriptor = ::openat(directory.descriptor, filename.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
		if (descriptor < 0)
		{
			const auto savedErrno = errno;
			::close(directory.descriptor);
			errno = savedErrno;
			if (errno == ENOENT)
				return {};
			return {{}, ErrnoMessage("cannot open private file", path)};
		}
		::close(directory.descriptor);
		if (const auto error = posix::ValidatePrivateFileDescriptor(descriptor, path); !error.empty())
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
		if (path.empty() || path.filename().empty())
			return {false, "private file path must name a file"};
		auto directory = posix::OpenPrivateDirectory(path.parent_path());
		if (!directory.error.empty())
			return {false, directory.error};

		std::filesystem::path temporary;
		std::string temporaryName;
		int descriptor = -1;
		for (int attempt = 0; attempt < 100; ++attempt)
		{
			temporary = TemporaryPath(path);
			temporaryName = temporary.filename().string();
			descriptor = ::openat(directory.descriptor, temporaryName.c_str(),
				O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(0600));
			if (descriptor >= 0)
				break;
			if (errno != EEXIST)
			{
				const auto error = ErrnoMessage("cannot create private temporary file", temporary);
				::close(directory.descriptor);
				return {false, error};
			}
		}
		if (descriptor < 0)
		{
			::close(directory.descriptor);
			return {false, "cannot allocate a unique private temporary file"};
		}
		if (const auto error = posix::PreparePrivateFileDescriptor(descriptor, temporary); !error.empty())
		{
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}

		if (!WriteAll(descriptor, contents))
		{
			const auto error = ErrnoMessage("cannot write private temporary file", temporary);
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (const auto error = posix::ValidatePrivateFileDescriptor(descriptor, temporary); !error.empty())
		{
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::fsync(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private temporary file", temporary);
			::close(descriptor);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::close(descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot close private temporary file", temporary);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		const auto filename = path.filename().string();
		if (::renameat(directory.descriptor, temporaryName.c_str(), directory.descriptor, filename.c_str()) != 0)
		{
			const auto error = ErrnoMessage("cannot install private file", path);
			::unlinkat(directory.descriptor, temporaryName.c_str(), 0);
			::close(directory.descriptor);
			return {false, error};
		}
		if (::fsync(directory.descriptor) != 0)
		{
			const auto error = ErrnoMessage("cannot flush private file directory", directory.path);
			::close(directory.descriptor);
			return {true, error};
		}
		if (::close(directory.descriptor) != 0)
			return {true, ErrnoMessage("cannot close private file directory", directory.path)};
		return {true, {}};
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
		if (const auto error = posix::PreparePrivateFileDescriptor(output, destination); !error.empty())
		{
			::close(input);
			::close(output);
			::unlink(destination.c_str());
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
		if (const auto error = posix::ValidatePrivateFileDescriptor(output, destination); !error.empty())
		{
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
