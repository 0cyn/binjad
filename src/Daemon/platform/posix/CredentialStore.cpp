#include "binjad/platform/Paths.hpp"
#include "binjad/platform/posix/PrivateFiles.hpp"
#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/CredentialVault.hpp"

#include "../../security/PlatformCredentialStore.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace binjad::security {
	namespace {
		constexpr std::size_t kMaximumVaultBytes = 1024 * 1024;

		struct FileReadResult
		{
			std::optional<std::string> contents;
			std::string error;
		};

		struct FileInstallResult
		{
			bool installed = false;
			std::string error;
		};

		std::string ErrnoMessage(std::string_view operation, const std::filesystem::path& path)
		{
			return std::string(operation) + " '" + path.string() + "': " + std::strerror(errno);
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

		FileReadResult ReadFileAt(int directory, std::string_view name, const std::filesystem::path& displayPath)
		{
			const std::string terminatedName(name);
			const int descriptor = ::openat(directory, terminatedName.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
			if (descriptor < 0)
			{
				if (errno == ENOENT)
					return {};
				return {{}, ErrnoMessage("cannot open credential vault", displayPath)};
			}
			if (const auto error = platform::posix::ValidatePrivateFileDescriptor(descriptor, displayPath);
				!error.empty())
			{
				::close(descriptor);
				return {{}, error};
			}

			struct stat metadata {};
			if (::fstat(descriptor, &metadata) != 0)
			{
				const auto error = ErrnoMessage("cannot inspect credential vault", displayPath);
				::close(descriptor);
				return {{}, error};
			}
			if (metadata.st_size < 0 || static_cast<std::uintmax_t>(metadata.st_size) > kMaximumVaultBytes)
			{
				::close(descriptor);
				return {{}, "credential vault exceeds the 1 MiB limit"};
			}

			std::string contents;
			contents.reserve(static_cast<std::size_t>(metadata.st_size));
			std::array<char, 16384> buffer {};
			while (true)
			{
				const auto count = ::read(descriptor, buffer.data(), buffer.size());
				if (count > 0)
				{
					if (static_cast<std::size_t>(count) > kMaximumVaultBytes - contents.size())
					{
						::close(descriptor);
						return {{}, "credential vault exceeds the 1 MiB limit"};
					}
					contents.append(buffer.data(), static_cast<std::size_t>(count));
					continue;
				}
				if (count == 0)
					break;
				if (errno == EINTR)
					continue;
				const auto error = ErrnoMessage("cannot read credential vault", displayPath);
				::close(descriptor);
				return {{}, error};
			}
			if (::close(descriptor) != 0)
				return {{}, ErrnoMessage("cannot close credential vault", displayPath)};
			return {std::move(contents), {}};
		}

		FileInstallResult InstallFileAt(
			int directory, std::string_view name, const std::filesystem::path& displayPath, std::string_view contents)
		{
			static std::atomic<std::uint64_t> sequence {0};
			std::string temporaryName;
			int descriptor = -1;
			for (int attempt = 0; attempt < 100; ++attempt)
			{
				temporaryName =
					std::string(name) + ".tmp." + std::to_string(::getpid()) + '.' + std::to_string(++sequence);
				descriptor = ::openat(directory, temporaryName.c_str(),
					O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(0600));
				if (descriptor >= 0)
					break;
				if (errno != EEXIST)
					return {false, ErrnoMessage("cannot create credential temporary file", displayPath)};
			}
			if (descriptor < 0)
				return {false, "cannot allocate a unique credential temporary file"};

			auto removeTemporary = [&] {
				::unlinkat(directory, temporaryName.c_str(), 0);
			};
			if (const auto error = platform::posix::PreparePrivateFileDescriptor(descriptor, displayPath);
				!error.empty())
			{
				::close(descriptor);
				removeTemporary();
				return {false, error};
			}
			if (!WriteAll(descriptor, contents))
			{
				const auto error = ErrnoMessage("cannot write credential temporary file", displayPath);
				::close(descriptor);
				removeTemporary();
				return {false, error};
			}
			if (const auto error = platform::posix::ValidatePrivateFileDescriptor(descriptor, displayPath);
				!error.empty())
			{
				::close(descriptor);
				removeTemporary();
				return {false, error};
			}
			if (::fsync(descriptor) != 0)
			{
				const auto error = ErrnoMessage("cannot flush credential temporary file", displayPath);
				::close(descriptor);
				removeTemporary();
				return {false, error};
			}
			if (::close(descriptor) != 0)
			{
				const auto error = ErrnoMessage("cannot close credential temporary file", displayPath);
				removeTemporary();
				return {false, error};
			}

			const std::string terminatedName(name);
			if (::renameat(directory, temporaryName.c_str(), directory, terminatedName.c_str()) != 0)
			{
				const auto error = ErrnoMessage("cannot install credential vault", displayPath);
				removeTemporary();
				return {false, error};
			}
			if (::fsync(directory) != 0)
				return {true, ErrnoMessage("cannot flush credential directory", displayPath.parent_path())};
			return {true, {}};
		}

		class FileCredentialStore final : public CredentialStore
		{
		public:
			explicit FileCredentialStore(PlatformCredentialStoreOptions options) :
				path_(FileCredentialStorePath(options.configPath)), directoryPath_(path_.parent_path()),
				filename_(path_.filename().string()), lockFilename_(filename_ + ".lock")
			{
				if (const auto error = platform::CreatePrivateDirectory(directoryPath_); !error.empty())
					throw std::runtime_error("cannot prepare credential directory: " + error);
				auto directory = platform::posix::OpenPrivateDirectory(directoryPath_);
				if (!directory.error.empty())
					throw std::runtime_error(directory.error);
				directoryDescriptor_ = directory.descriptor;
				directoryPath_ = std::move(directory.path);

				bool created = false;
				lockDescriptor_ = ::openat(directoryDescriptor_, lockFilename_.c_str(),
					O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, static_cast<mode_t>(0600));
				if (lockDescriptor_ >= 0)
					created = true;
				else if (errno == EEXIST)
					lockDescriptor_ =
						::openat(directoryDescriptor_, lockFilename_.c_str(), O_RDWR | O_CLOEXEC | O_NOFOLLOW);
				if (lockDescriptor_ < 0)
				{
					const auto error = ErrnoMessage("cannot open credential lock", path_.string() + ".lock");
					::close(directoryDescriptor_);
					directoryDescriptor_ = -1;
					throw std::runtime_error(error);
				}
				const auto lockPath = std::filesystem::path(path_.string() + ".lock");
				if (::flock(lockDescriptor_, LOCK_EX | LOCK_NB) != 0)
				{
					const auto error = errno == EWOULDBLOCK ?
						std::string("another daemon is using this credential store") :
						ErrnoMessage("cannot lock credential store", lockPath);
					CloseDescriptors();
					throw std::runtime_error(error);
				}
				const auto metadataError = created ?
					platform::posix::PreparePrivateFileDescriptor(lockDescriptor_, lockPath) :
					platform::posix::ValidatePrivateFileDescriptor(lockDescriptor_, lockPath);
				if (!metadataError.empty())
				{
					CloseDescriptors();
					throw std::runtime_error("invalid credential lock: " + metadataError);
				}
				if (created && (::fsync(lockDescriptor_) != 0 || ::fsync(directoryDescriptor_) != 0))
				{
					const auto error = ErrnoMessage("cannot flush credential lock", lockPath);
					CloseDescriptors();
					throw std::runtime_error(error);
				}
			}

			~FileCredentialStore() override { CloseDescriptors(); }

			CredentialReadResult Read(std::string_view key) override
			{
				std::lock_guard lock(mutex_);
				if (!fatalError_.empty())
					return {{}, fatalError_};
				if (const auto error = LoadLocked(); !error.empty())
					return {{}, error};
				const auto value = values_.find(std::string(key));
				return value == values_.end() ? CredentialReadResult {} : CredentialReadResult {value->second, {}};
			}

			std::string Write(std::string_view key, std::string_view value) override
			{
				if (key.empty())
					return "credential key must not be empty";
				std::lock_guard lock(mutex_);
				if (!fatalError_.empty())
					return fatalError_;
				if (const auto error = LoadLocked(); !error.empty())
					return error;
				auto updated = values_;
				updated[std::string(key)] = std::string(value);
				return PersistLocked(std::move(updated));
			}

			std::string Remove(std::string_view key) override
			{
				std::lock_guard lock(mutex_);
				if (!fatalError_.empty())
					return fatalError_;
				if (const auto error = LoadLocked(); !error.empty())
					return error;
				if (!values_.contains(std::string(key)))
					return {};
				auto updated = values_;
				updated.erase(std::string(key));
				return PersistLocked(std::move(updated));
			}

		private:
			void CloseDescriptors()
			{
				if (lockDescriptor_ >= 0)
				{
					::close(lockDescriptor_);
					lockDescriptor_ = -1;
				}
				if (directoryDescriptor_ >= 0)
				{
					::close(directoryDescriptor_);
					directoryDescriptor_ = -1;
				}
			}

			std::string LoadLocked()
			{
				if (loaded_)
					return {};
				const auto file = ReadFileAt(directoryDescriptor_, filename_, path_);
				if (!file.error.empty())
					return file.error;
				if (!file.contents)
				{
					values_.clear();
					persistedContents_.reset();
					loaded_ = true;
					return {};
				}
				auto parsed = ParseCredentialVault(*file.contents);
				if (!parsed.values)
					return parsed.error;
				values_ = std::move(*parsed.values);
				persistedContents_ = *file.contents;
				loaded_ = true;
				return {};
			}

			std::string PersistLocked(CredentialVaultValues updated)
			{
				const auto current = ReadFileAt(directoryDescriptor_, filename_, path_);
				if (!current.error.empty())
					return current.error;
				if (!persistedContents_)
				{
					if (current.contents)
						return "credential vault appeared after the store was loaded";
				}
				else if (!current.contents || *current.contents != *persistedContents_)
				{
					return "credential vault changed after the store was loaded";
				}

				const auto contents = SerializeCredentialVault(updated);
				if (contents.size() > kMaximumVaultBytes)
					return "credential vault exceeds the 1 MiB limit";
				const auto installation = InstallFileAt(directoryDescriptor_, filename_, path_, contents);
				if (!installation.installed)
					return installation.error.empty() ? "credential vault was not installed" : installation.error;

				values_ = std::move(updated);
				persistedContents_ = contents;
				if (!installation.error.empty())
				{
					fatalError_ = "credential vault was installed but its durability is uncertain; restart the daemon: "
						+ installation.error;
					return fatalError_;
				}
				return {};
			}

			std::filesystem::path path_;
			std::filesystem::path directoryPath_;
			std::string filename_;
			std::string lockFilename_;
			CredentialVaultValues values_;
			std::optional<std::string> persistedContents_;
			std::string fatalError_;
			bool loaded_ = false;
			int directoryDescriptor_ = -1;
			int lockDescriptor_ = -1;
			std::mutex mutex_;
		};
	}  // namespace

	std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(PlatformCredentialStoreOptions options)
	{
		return std::make_unique<FileCredentialStore>(std::move(options));
	}
}  // namespace binjad::security
