#include "binjad/platform/ToolControl.hpp"

#include "binjad/portal/Api.hpp"

#include <rapidjsonwrapper.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <fcntl.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>
#include <utility>

namespace binjad::platform {
	namespace {
		constexpr std::size_t kMaximumRequestBytes = 4096;

		std::string SystemError(std::string_view operation)
		{
			return std::string(operation) + ": " + std::strerror(errno);
		}

		template <typename WriterType>
		void WritePacks(WriterType& writer, const ToolConfig& tools)
		{
			writer.StartObject();
			writer.Key("project_management");
			writer.Bool(tools.projectManagement);
			writer.Key("function_analysis");
			writer.Bool(tools.functionAnalysis);
			writer.Key("binary_data");
			writer.Bool(tools.binaryData);
			writer.Key("search");
			writer.Bool(tools.search);
			writer.Key("types");
			writer.Bool(tools.types);
			writer.Key("annotations");
			writer.Bool(tools.annotations);
			writer.Key("binary_editing");
			writer.Bool(tools.binaryEditing);
			writer.Key("history");
			writer.Bool(tools.history);
			writer.Key("header_parsing");
			writer.Bool(tools.headerParsing);
			writer.Key("url_generation");
			writer.Bool(tools.urlGeneration);
			writer.Key("diffing");
			writer.Bool(tools.diffing);
			writer.Key("kernel_cache");
			writer.Bool(tools.kernelCache);
			writer.Key("shared_cache");
			writer.Bool(tools.sharedCache);
			writer.Key("debugger");
			writer.Bool(tools.debugger);
			writer.EndObject();
		}

		std::string Success(const ToolConfig& tools)
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("ok");
			writer.Bool(true);
			writer.Key("packs");
			WritePacks(writer, tools);
			writer.EndObject();
			return std::string(buffer.GetString(), buffer.GetSize()) + '\n';
		}

		std::string Failure(std::string_view error)
		{
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("ok");
			writer.Bool(false);
			writer.Key("error");
			writer.String(error.data(), static_cast<rapidjson::SizeType>(error.size()));
			writer.EndObject();
			return std::string(buffer.GetString(), buffer.GetSize()) + '\n';
		}

		bool OnlyFields(const rapidjson::Value& object, std::initializer_list<std::string_view> allowed)
		{
			std::unordered_set<std::string_view> seen;
			for (const auto& member : object.GetObject())
			{
				const std::string_view name(member.name.GetString(), member.name.GetStringLength());
				if (!seen.insert(name).second
					|| std::find(allowed.begin(), allowed.end(), name) == allowed.end())
					return false;
			}
			return true;
		}

		bool SendAll(int socket, std::string_view response)
		{
			while (!response.empty())
			{
				const auto count = ::send(socket, response.data(), response.size(), MSG_NOSIGNAL);
				if (count < 0)
				{
					if (errno == EINTR)
						continue;
					return false;
				}
				if (count == 0)
					return false;
				response.remove_prefix(static_cast<std::size_t>(count));
			}
			return true;
		}

		class NativeToolControlServer final : public ToolControlServer
		{
		public:
			NativeToolControlServer(std::filesystem::path path, std::shared_ptr<portal::Api> api) :
				path_(std::move(path)), api_(std::move(api))
			{
				if (!api_)
					throw std::invalid_argument("tool control API must not be null");
				if (path_.empty() || path_.string().size() >= sizeof(sockaddr_un::sun_path))
					throw std::invalid_argument("tool control socket path is too long");

				struct stat existing {};
				if (::lstat(path_.c_str(), &existing) == 0)
				{
					if (!S_ISSOCK(existing.st_mode) || existing.st_uid != ::geteuid())
						throw std::runtime_error("refusing to replace unsafe tool control socket path");
					if (::unlink(path_.c_str()) != 0)
						throw std::runtime_error(SystemError("cannot remove stale tool control socket"));
				}
				else if (errno != ENOENT)
				{
					throw std::runtime_error(SystemError("cannot inspect tool control socket path"));
				}

				listener_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
				if (listener_ < 0)
					throw std::runtime_error(SystemError("cannot create tool control socket"));
				if (::fcntl(listener_, F_SETFD, FD_CLOEXEC) != 0)
				{
					const auto error = SystemError("cannot protect tool control socket descriptor");
					::close(listener_);
					listener_ = -1;
					throw std::runtime_error(error);
				}
				sockaddr_un address {};
				address.sun_family = AF_UNIX;
				std::memcpy(address.sun_path, path_.c_str(), path_.string().size() + 1);
				if (::bind(listener_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0
					|| ::chmod(path_.c_str(), 0600) != 0 || ::listen(listener_, 8) != 0)
				{
					const auto error = SystemError("cannot bind tool control socket");
					::close(listener_);
					listener_ = -1;
					::unlink(path_.c_str());
					throw std::runtime_error(error);
				}
				if (::lstat(path_.c_str(), &socketMetadata_) != 0)
				{
					const auto error = SystemError("cannot inspect bound tool control socket");
					::close(listener_);
					listener_ = -1;
					::unlink(path_.c_str());
					throw std::runtime_error(error);
				}
				try
				{
					thread_ = std::jthread([this](std::stop_token token) { Run(token); });
				}
				catch (...)
				{
					::close(listener_);
					listener_ = -1;
					::unlink(path_.c_str());
					throw;
				}
			}

			~NativeToolControlServer() override
			{
				thread_.request_stop();
				if (listener_ >= 0)
				{
					::shutdown(listener_, SHUT_RDWR);
					::close(listener_);
					listener_ = -1;
				}
				if (thread_.joinable())
					thread_.join();
				struct stat current {};
				if (::lstat(path_.c_str(), &current) == 0 && current.st_dev == socketMetadata_.st_dev
					&& current.st_ino == socketMetadata_.st_ino)
					::unlink(path_.c_str());
			}

		private:
			std::string Handle(std::string_view request)
			{
				rapidjson::Document document;
				try
				{
					document.Parse<rapidjson::kParseValidateEncodingFlag>(request.data(), request.size());
				}
				catch (const ParseException&)
				{
					return Failure("invalid request JSON");
				}
				if (document.HasParseError() || !document.IsObject())
					return Failure("request must be a JSON object");
				const auto operation = document.FindMember("operation");
				if (operation == document.MemberEnd() || !operation->value.IsString())
					return Failure("operation is required");
				const std::string_view name(operation->value.GetString(), operation->value.GetStringLength());
				if (name == "list")
				{
					if (!OnlyFields(document, {"operation"}))
						return Failure("list accepts only operation");
					return Success(api_->ActiveToolConfig());
				}
				if (name != "set" || !OnlyFields(document, {"operation", "pack", "enabled"}))
					return Failure("unknown operation or fields");
				const auto pack = document.FindMember("pack");
				const auto enabled = document.FindMember("enabled");
				if (pack == document.MemberEnd() || !pack->value.IsString() || enabled == document.MemberEnd()
					|| !enabled->value.IsBool())
					return Failure("set requires string pack and boolean enabled");
				const std::string packName(pack->value.GetString(), pack->value.GetStringLength());
				const auto updated = api_->UpdateToolPacks({{packName, enabled->value.GetBool()}});
				return updated.value ? Success(updated.value->tools) : Failure(updated.error);
			}

			void HandleClient(int client)
			{
				uid_t peerUser = 0;
				gid_t peerGroup = 0;
				if (::getpeereid(client, &peerUser, &peerGroup) != 0 || peerUser != ::geteuid())
					return;
				const timeval timeout {2, 0};
				::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
				::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

				std::string request;
				std::array<char, 1024> buffer {};
				while (request.size() <= kMaximumRequestBytes)
				{
					const auto count = ::recv(client, buffer.data(), buffer.size(), 0);
					if (count > 0)
					{
						request.append(buffer.data(), static_cast<std::size_t>(count));
						const auto newline = request.find('\n');
						if (newline != std::string::npos)
						{
							if (newline + 1 != request.size() || newline > kMaximumRequestBytes)
								SendAll(client, Failure("request must contain one bounded line"));
							else
								SendAll(client, Handle(std::string_view(request).substr(0, newline)));
							return;
						}
						continue;
					}
					if (count < 0 && errno == EINTR)
						continue;
					return;
				}
				SendAll(client, Failure("request is too large"));
			}

			void Run(std::stop_token token)
			{
				while (!token.stop_requested())
				{
					const int client = ::accept(listener_, nullptr, nullptr);
					if (client < 0)
					{
						if (errno == EINTR)
							continue;
						return;
					}
					if (::fcntl(client, F_SETFD, FD_CLOEXEC) != 0)
					{
						::close(client);
						continue;
					}
					HandleClient(client);
					::close(client);
				}
			}

			std::filesystem::path path_;
			std::shared_ptr<portal::Api> api_;
			int listener_ = -1;
			struct stat socketMetadata_ {};
			std::jthread thread_;
		};
	}  // namespace

	std::filesystem::path ToolControlSocketPath(const std::filesystem::path& configPath)
	{
		return std::filesystem::absolute(configPath).lexically_normal().parent_path() / kToolControlSocketName;
	}

	ToolControlServerStart StartToolControlServer(
		const std::filesystem::path& path, std::shared_ptr<portal::Api> api)
	{
		try
		{
			return {std::make_unique<NativeToolControlServer>(path, std::move(api)), {}};
		}
		catch (const std::exception& exception)
		{
			return {{}, exception.what()};
		}
	}
}  // namespace binjad::platform
