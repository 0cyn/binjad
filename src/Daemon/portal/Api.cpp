#include "binjad/portal/Api.hpp"

#include "binjad/platform/Paths.hpp"
#include "binjad/Version.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::portal {
	namespace {
		using rapidjson::Document;
		using rapidjson::PrettyWriter;
		using rapidjson::StringBuffer;
		using rapidjson::Value;
		using rapidjson::Writer;

		http::ImmediateResponse Json(int status, std::string body)
		{
			return {status, "application/json", std::move(body), {{"Cache-Control", "no-store"}}};
		}

		http::ImmediateResponse Error(int status, std::string_view message)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("error");
			writer.String(message.data(), static_cast<rapidjson::SizeType>(message.size()));
			writer.EndObject();
			return Json(status, {buffer.GetString(), buffer.GetSize()});
		}

		http::ImmediateResponse Unauthorized()
		{
			return Error(401, "unauthorized");
		}

		std::optional<std::string> DecodeBase64(std::string_view encoded)
		{
			static constexpr std::string_view alphabet =
				"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
			if (encoded.empty() || encoded.size() % 4 != 0)
				return std::nullopt;
			std::string output;
			output.reserve(encoded.size() / 4 * 3);
			for (std::size_t offset = 0; offset < encoded.size(); offset += 4)
			{
				std::uint32_t value = 0;
				int padding = 0;
				for (std::size_t index = 0; index < 4; ++index)
				{
					const char character = encoded[offset + index];
					if (character == '=')
					{
						if (index < 2 || offset + 4 != encoded.size())
							return std::nullopt;
						++padding;
						value <<= 6;
						continue;
					}
					if (padding != 0)
						return std::nullopt;
					const auto digit = alphabet.find(character);
					if (digit == std::string_view::npos)
						return std::nullopt;
					value = (value << 6) | static_cast<std::uint32_t>(digit);
				}
				output.push_back(static_cast<char>((value >> 16) & 0xff));
				if (padding < 2)
					output.push_back(static_cast<char>((value >> 8) & 0xff));
				if (padding < 1)
					output.push_back(static_cast<char>(value & 0xff));
			}
			return output;
		}

		std::optional<std::pair<std::string, std::string>> BasicCredentials(
			const std::optional<std::string>& authorization)
		{
			if (!authorization || authorization->size() < 7)
				return std::nullopt;
			const auto scheme = std::string_view(*authorization).substr(0, 5);
			if (!std::equal(scheme.begin(), scheme.end(), "Basic",
					[](char left, char right) {
						return std::tolower(static_cast<unsigned char>(left))
							== std::tolower(static_cast<unsigned char>(right));
					})
				|| (*authorization)[5] != ' ')
				return std::nullopt;
			const auto decoded = DecodeBase64(std::string_view(*authorization).substr(6));
			if (!decoded)
				return std::nullopt;
			const auto separator = decoded->find(':');
			if (separator == std::string::npos || separator == 0)
				return std::nullopt;
			return std::pair(decoded->substr(0, separator), decoded->substr(separator + 1));
		}

		std::optional<Document> ParseObject(std::string_view json, std::string& error)
		{
			Document document;
			try
			{
				document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
			}
			catch (const ParseException& exception)
			{
				error = std::string("invalid JSON at byte ") + std::to_string(exception.Offset()) + ": "
					+ rapidjson::GetParseError_En(exception.Code());
				return std::nullopt;
			}
			if (document.HasParseError())
			{
				error = std::string("invalid JSON at byte ") + std::to_string(document.GetErrorOffset()) + ": "
					+ rapidjson::GetParseError_En(document.GetParseError());
				return std::nullopt;
			}
			if (!document.IsObject())
			{
				error = "request body must be a JSON object";
				return std::nullopt;
			}
			return document;
		}

		bool OnlyFields(const Value& object, std::initializer_list<std::string_view> fields, std::string& error)
		{
			std::unordered_set<std::string_view> seen;
			for (const auto& member : object.GetObject())
			{
				const std::string_view name(member.name.GetString(), member.name.GetStringLength());
				if (std::find(fields.begin(), fields.end(), name) == fields.end())
				{
					error = "unknown field '" + std::string(name) + "'";
					return false;
				}
				if (!seen.insert(name).second)
				{
					error = "duplicate field '" + std::string(name) + "'";
					return false;
				}
			}
			return true;
		}

		bool StringField(const Value& object, const char* name, std::string& output, bool required, std::string& error)
		{
			const auto member = object.FindMember(name);
			if (member == object.MemberEnd())
			{
				if (required)
					error = std::string(name) + " is required";
				return !required;
			}
			if (!member->value.IsString())
			{
				error = std::string(name) + " must be a string";
				return false;
			}
			output.assign(member->value.GetString(), member->value.GetStringLength());
			return true;
		}

		bool BoolField(const Value& object, const char* name, bool& output, bool required, std::string& error)
		{
			const auto member = object.FindMember(name);
			if (member == object.MemberEnd())
			{
				if (required)
					error = std::string(name) + " is required";
				return !required;
			}
			if (!member->value.IsBool())
			{
				error = std::string(name) + " must be a boolean";
				return false;
			}
			output = member->value.GetBool();
			return true;
		}

		bool HasControl(std::string_view value)
		{
			return std::any_of(value.begin(), value.end(), [](const unsigned char character) {
				return character < 0x20 || character == 0x7f;
			});
		}

		bool ValidOnboardingUsername(std::string_view value)
		{
			const auto validCharacter = [](const unsigned char character) {
				return std::isalnum(character) != 0 || character == '.' || character == '_' || character == '-';
			};
			return !value.empty() && value.size() <= 64 && std::all_of(value.begin(), value.end(), validCharacter);
		}

		std::optional<std::filesystem::path> ResolveOnboardingProjectRoot(
			std::string_view input, const std::filesystem::path& configPath, std::string& error)
		{
			if (input.empty())
			{
				error = "project_root must not be empty";
				return std::nullopt;
			}
			if (HasControl(input))
			{
				error = "project_root must not contain control characters";
				return std::nullopt;
			}

			try
			{
				std::filesystem::path root;
				if (input == "~")
				{
					root = platform::HomeDirectory();
				}
				else if (input.starts_with("~/") || input.starts_with("~\\"))
				{
					root = platform::HomeDirectory() / std::filesystem::path(input.substr(2));
				}
				else
				{
					if (input.front() == '~')
					{
						error = "project_root can use '~' only for the current user's home directory";
						return std::nullopt;
					}
					root = std::filesystem::path(input);
				}
				if (!root.is_absolute())
					root = std::filesystem::absolute(configPath).parent_path() / root;
				return root.lexically_normal();
			}
			catch (const std::exception& exception)
			{
				error = "cannot resolve project_root: " + std::string(exception.what());
				return std::nullopt;
			}
		}

		std::string DisplayOnboardingPath(const std::filesystem::path& path)
		{
			try
			{
				const auto home = platform::HomeDirectory().lexically_normal();
				const auto normalized = path.lexically_normal();
				auto homeIterator = home.begin();
				auto pathIterator = normalized.begin();
				while (homeIterator != home.end() && pathIterator != normalized.end() && *homeIterator == *pathIterator)
				{
					++homeIterator;
					++pathIterator;
				}
				if (homeIterator == home.end())
				{
					std::filesystem::path relative;
					for (; pathIterator != normalized.end(); ++pathIterator)
						relative /= *pathIterator;
					return relative.empty() ? "~" : "~/" + relative.generic_string();
				}
			}
			catch (...)
			{}
			return path.string();
		}

		struct DirectoryStatus
		{
			bool exists = false;
			bool directory = false;
			std::string error;
		};

		DirectoryStatus InspectDirectory(const std::filesystem::path& path)
		{
			std::error_code error;
			const auto status = std::filesystem::status(path, error);
			if (error == std::errc::no_such_file_or_directory)
				return {};
			if (error)
				return {false, false, error.message()};
			return {std::filesystem::exists(status), std::filesystem::is_directory(status), {}};
		}

		Value& EnsureObjectMember(Value& parent, const char* name, Document::AllocatorType& allocator)
		{
			auto member = parent.FindMember(name);
			if (member != parent.MemberEnd())
			{
				if (!member->value.IsObject())
					member->value.SetObject();
				return member->value;
			}
			Value key;
			key.SetString(name, static_cast<rapidjson::SizeType>(std::char_traits<char>::length(name)), allocator);
			Value object(rapidjson::kObjectType);
			parent.AddMember(key, object, allocator);
			return parent.FindMember(name)->value;
		}

		Value& EnsureArrayMember(Value& parent, const char* name, Document::AllocatorType& allocator)
		{
			auto member = parent.FindMember(name);
			if (member != parent.MemberEnd())
			{
				if (!member->value.IsArray())
					member->value.SetArray();
				return member->value;
			}
			Value key;
			key.SetString(name, static_cast<rapidjson::SizeType>(std::char_traits<char>::length(name)), allocator);
			Value array(rapidjson::kArrayType);
			parent.AddMember(key, array, allocator);
			return parent.FindMember(name)->value;
		}

		void SetStringMember(
			Value& object, const char* name, std::string_view value, Document::AllocatorType& allocator)
		{
			auto member = object.FindMember(name);
			if (member != object.MemberEnd())
			{
				member->value.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), allocator);
				return;
			}
			Value key;
			key.SetString(name, static_cast<rapidjson::SizeType>(std::char_traits<char>::length(name)), allocator);
			Value stored;
			stored.SetString(value.data(), static_cast<rapidjson::SizeType>(value.size()), allocator);
			object.AddMember(key, stored, allocator);
		}

		void SetBoolMember(Value& object, const char* name, bool value, Document::AllocatorType& allocator)
		{
			auto member = object.FindMember(name);
			if (member != object.MemberEnd())
			{
				member->value.SetBool(value);
				return;
			}
			Value key;
			key.SetString(name, static_cast<rapidjson::SizeType>(std::char_traits<char>::length(name)), allocator);
			object.AddMember(key, value, allocator);
		}

		template <typename WriteValue>
		std::string JsonResult(WriteValue writeValue)
		{
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			writer.StartObject();
			writer.Key("result");
			writeValue(writer);
			writer.EndObject();
			return {buffer.GetString(), buffer.GetSize()};
		}

		template <typename WriterType>
		void WriteAccount(WriterType& writer, const security::AccountRecord& account)
		{
			writer.StartObject();
			writer.Key("username");
			writer.String(account.username.data(), static_cast<rapidjson::SizeType>(account.username.size()));
			writer.Key("created_at");
			writer.Uint64(account.createdAt);
			writer.EndObject();
		}

		template <typename WriterType>
		void WriteToken(WriterType& writer, const security::TokenRecord& token)
		{
			writer.StartObject();
			writer.Key("created_at");
			writer.Uint64(token.createdAt);
			writer.Key("expires_at");
			writer.Uint64(token.expiresAt.value_or(0));
			writer.EndObject();
		}

		std::string_view SegmentAfter(std::string_view path, std::string_view prefix)
		{
			return path.starts_with(prefix) ? path.substr(prefix.size()) : std::string_view {};
		}

		std::string NormalizeJson(std::string_view json)
		{
			std::string error;
			const auto document = ParseObject(json, error);
			if (!document)
				return {};
			StringBuffer buffer;
			Writer<StringBuffer> writer(buffer);
			document->Accept(writer);
			return {buffer.GetString(), buffer.GetSize()};
		}

		bool SameToolPacks(const ToolConfig& left, const ToolConfig& right)
		{
			return left.projectManagement == right.projectManagement && left.functionAnalysis == right.functionAnalysis
				&& left.binaryData == right.binaryData && left.search == right.search && left.types == right.types
				&& left.annotations == right.annotations && left.binaryEditing == right.binaryEditing
				&& left.history == right.history && left.headerParsing == right.headerParsing
				&& left.urlGeneration == right.urlGeneration && left.diffing == right.diffing
				&& left.kernelCache == right.kernelCache && left.sharedCache == right.sharedCache
				&& left.debugger == right.debugger;
		}

		bool SameRestartGatedConfig(const Config& left, const Config& right)
		{
			return left.binaryNinja.installationDirectory == right.binaryNinja.installationDirectory
				&& left.tools.discoveryMode == right.tools.discoveryMode
				&& left.listener.addresses == right.listener.addresses && left.listener.port == right.listener.port
				&& left.http.publicBaseUrl == right.http.publicBaseUrl && left.http.mcpPath == right.http.mcpPath
				&& left.http.uploadPath == right.http.uploadPath && left.http.portalPath == right.http.portalPath
				&& left.http.healthPath == right.http.healthPath
				&& left.http.mcpMaxBodyBytes == right.http.mcpMaxBodyBytes
				&& left.cpu.percentage == right.cpu.percentage && left.cpu.fairness == right.cpu.fairness
				&& left.cpu.subdivision == right.cpu.subdivision && left.sessions.ttl == right.sessions.ttl
				&& left.jobs.detachAfter == right.jobs.detachAfter
				&& left.jobs.cancellationGrace == right.jobs.cancellationGrace
				&& left.uploads.maxBytes == right.uploads.maxBytes
				&& left.uploads.memoryThresholdBytes == right.uploads.memoryThresholdBytes
				&& left.uploads.urlTtl == right.uploads.urlTtl && left.projects.roots == right.projects.roots
				&& left.projects.defaultRoot == right.projects.defaultRoot
				&& left.projects.allowArbitraryPaths == right.projects.allowArbitraryPaths
				&& left.projects.allowProjectRegistration == right.projects.allowProjectRegistration
				&& left.storage.tokensPath == right.storage.tokensPath
				&& left.storage.accountsPath == right.storage.accountsPath
				&& left.storage.spoolPath == right.storage.spoolPath;
		}

		bool SetToolPackField(ToolConfig& tools, std::string_view name, bool enabled)
		{
			if (name == "project_management")
				tools.projectManagement = enabled;
			else if (name == "function_analysis")
				tools.functionAnalysis = enabled;
			else if (name == "binary_data")
				tools.binaryData = enabled;
			else if (name == "search")
				tools.search = enabled;
			else if (name == "types")
				tools.types = enabled;
			else if (name == "annotations")
				tools.annotations = enabled;
			else if (name == "binary_editing")
				tools.binaryEditing = enabled;
			else if (name == "history")
				tools.history = enabled;
			else if (name == "header_parsing")
				tools.headerParsing = enabled;
			else if (name == "url_generation")
				tools.urlGeneration = enabled;
			else if (name == "diffing")
				tools.diffing = enabled;
			else if (name == "kernel_cache")
				tools.kernelCache = enabled;
			else if (name == "shared_cache")
				tools.sharedCache = enabled;
			else if (name == "debugger")
				tools.debugger = enabled;
			else
				return false;
			return true;
		}

		bool ReadToolPackChanges(
			const Value& object, std::vector<std::pair<std::string, bool>>& changes, std::string& error)
		{
			constexpr std::string_view fields[] {"project_management", "function_analysis", "binary_data", "search",
				"types", "annotations", "binary_editing", "history", "header_parsing", "url_generation", "diffing",
				"kernel_cache", "shared_cache", "debugger"};
			if (object.MemberCount() == 0)
			{
				error = "at least one tool pack is required";
				return false;
			}
			std::unordered_set<std::string_view> seen;
			for (const auto& member : object.GetObject())
			{
				const std::string_view name(member.name.GetString(), member.name.GetStringLength());
				if (std::find(std::begin(fields), std::end(fields), name) == std::end(fields))
				{
					error = name == "discovery_mode" ?
						"discovery_mode must be changed through configuration and requires restart" :
						"unknown field '" + std::string(name) + "'";
					return false;
				}
				if (!seen.insert(name).second)
				{
					error = "duplicate field '" + std::string(name) + "'";
					return false;
				}
				if (!member.value.IsBool())
				{
					error = std::string(name) + " must be a boolean";
					return false;
				}
				changes.emplace_back(name, member.value.GetBool());
			}
			return true;
		}

		template <typename WriterType>
		void WriteToolConfig(WriterType& writer, const ToolConfig& tools)
		{
			writer.StartObject();
			writer.Key("discovery_mode");
			const auto discoveryMode = ToolDiscoveryModeName(tools.discoveryMode);
			writer.String(discoveryMode.data(), static_cast<rapidjson::SizeType>(discoveryMode.size()));
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

		Value ToolConfigValue(const ToolConfig& tools, Document::AllocatorType& allocator)
		{
			Value result(rapidjson::kObjectType);
			result.AddMember("_comment",
				Value("Tool packs apply immediately. Discovery mode requires save and restart. Brokered discovery "
					  "advertises 15 lifecycle/control tools to modern clients and 13 to legacy clients, and routes "
					  "every other enabled tool through bn_tools.",
					allocator),
				allocator);
			const auto discoveryMode = ToolDiscoveryModeName(tools.discoveryMode);
			result.AddMember("discovery_mode",
				Value(discoveryMode.data(), static_cast<rapidjson::SizeType>(discoveryMode.size()), allocator),
				allocator);
			result.AddMember("project_management", tools.projectManagement, allocator);
			result.AddMember("function_analysis", tools.functionAnalysis, allocator);
			result.AddMember("binary_data", tools.binaryData, allocator);
			result.AddMember("search", tools.search, allocator);
			result.AddMember("types", tools.types, allocator);
			result.AddMember("annotations", tools.annotations, allocator);
			result.AddMember("binary_editing", tools.binaryEditing, allocator);
			result.AddMember("history", tools.history, allocator);
			result.AddMember("header_parsing", tools.headerParsing, allocator);
			result.AddMember("url_generation", tools.urlGeneration, allocator);
			result.AddMember("diffing", tools.diffing, allocator);
			result.AddMember("kernel_cache", tools.kernelCache, allocator);
			result.AddMember("shared_cache", tools.sharedCache, allocator);
			result.AddMember("debugger", tools.debugger, allocator);
			return result;
		}

		std::string Serialize(const Value& value)
		{
			StringBuffer buffer;
			PrettyWriter<StringBuffer> writer(buffer);
			value.Accept(writer);
			return {buffer.GetString(), buffer.GetSize()};
		}

		template <typename WriterType>
		void WriteProject(WriterType& writer, const ProjectSummary& project)
		{
			writer.StartObject();
			writer.Key("project");
			writer.String(project.reference.data(), static_cast<rapidjson::SizeType>(project.reference.size()));
			writer.Key("name");
			writer.String(project.name.data(), static_cast<rapidjson::SizeType>(project.name.size()));
			writer.Key("description");
			writer.String(project.description.data(), static_cast<rapidjson::SizeType>(project.description.size()));
			writer.EndObject();
		}
	}  // namespace

	Api::Api(Config config, Service& service, std::filesystem::path configPath) :
		config_(std::move(config)), service_(service), apiPath_(config_.http.portalPath + "/api"),
		configPath_(std::move(configPath))
	{
		if (!configPath_.empty())
		{
			const auto current = platform::ReadPrivateFile(configPath_);
			if (current.contents)
				activeConfiguration_ = NormalizeJson(*current.contents);
		}
		if (activeConfiguration_.empty())
			activeConfiguration_ = NormalizeJson(DefaultConfigJson());
	}

	void Api::SetProjectDeleteCallback(ProjectDelete callback)
	{
		projectDelete_ = std::move(callback);
	}

	void Api::SetProjectCreateCallback(ProjectCreate callback)
	{
		projectCreate_ = std::move(callback);
	}

	void Api::SetProjectListCallback(ProjectList callback)
	{
		projectList_ = std::move(callback);
	}

	void Api::SetRuntimeStatusProvider(RuntimeStatusProvider callback)
	{
		runtimeStatus_ = std::move(callback);
	}

	void Api::SetToolConfigCallback(ToolConfigApply callback)
	{
		toolConfigApply_ = std::move(callback);
	}

	void Api::SetRestartCallback(RestartCallback callback)
	{
		std::lock_guard lock(configurationMutex_);
		restartCallback_ = std::move(callback);
	}

	void Api::SetMcpDocumentationProviders(McpContextProvider context, McpToolsProvider tools)
	{
		mcpContext_ = std::move(context);
		mcpTools_ = std::move(tools);
	}

	ToolConfig Api::ActiveToolConfig() const
	{
		std::lock_guard lock(configurationMutex_);
		return config_.tools;
	}

	Result<ToolPackUpdate> Api::UpdateToolPacks(const std::vector<std::pair<std::string, bool>>& changes)
	{
		if (changes.empty())
			return {{}, "at least one tool pack is required"};

		ToolConfig applied;
		bool changed = false;
		bool restartRequired = false;
		{
			std::lock_guard lock(configurationMutex_);
			applied = config_.tools;
			for (const auto& [name, enabled] : changes)
			{
				if (!SetToolPackField(applied, name, enabled))
					return {{}, "unknown tool pack '" + name + "'"};
			}

			const auto current = platform::ReadPrivateFile(configPath_);
			if (!current.error.empty())
				return {{}, current.error};
			if (!current.contents)
				return {{}, "configuration file is unavailable"};
			std::string error;
			auto document = ParseObject(*current.contents, error);
			if (!document)
				return {{}, "cannot update malformed configuration: " + error};
			const auto configured = ParseConfig(*current.contents, configPath_);
			if (!configured.config)
				return {{}, "cannot update invalid configuration"};
			ToolConfig persistedTools = applied;
			persistedTools.discoveryMode = configured.config->tools.discoveryMode;
			auto tools = ToolConfigValue(persistedTools, document->GetAllocator());
			if (document->HasMember("tools"))
				(*document)["tools"] = std::move(tools);
			else
				document->AddMember("tools", std::move(tools), document->GetAllocator());
			document->RemoveMember("plugins");
			const auto serialized = Serialize(*document);
			const auto parsed = ParseConfig(serialized, configPath_);
			if (!parsed.config)
				return {{}, "tool-pack update produced an invalid configuration"};
			const auto persisted = platform::ReplacePrivateFile(configPath_, serialized + "\n");
			if (!persisted.installed)
				return {{}, persisted.error};

			changed = !SameToolPacks(config_.tools, applied);
			config_.tools = applied;
			restartRequired_ = !SameRestartGatedConfig(config_, *parsed.config);
			restartRequired = restartRequired_;
		}
		if (changed && toolConfigApply_)
			toolConfigApply_(applied);
		return {ToolPackUpdate {applied, restartRequired}, {}};
	}

	http::ImmediateResponse Api::Handle(const ApiRequest& request)
	{
		if (request.body.size() > kMaxBodyBytes)
			return Error(413, "payload_too_large");
		if (request.path == apiPath_ + "/onboarding" && request.method == http::Method::Get)
		{
			const auto required = service_.SetupRequired();
			if (!required.value)
				return Error(500, required.error);
			if (!*required.value)
			{
				return Json(200, JsonResult([&](auto& writer) {
					writer.StartObject();
					writer.Key("required");
					writer.Bool(false);
					writer.EndObject();
				}));
			}

			Config configured;
			{
				std::lock_guard lock(configurationMutex_);
				configured = config_;
				if (!configPath_.empty())
				{
					const auto current = platform::ReadPrivateFile(configPath_);
					if (!current.error.empty())
						return Error(500, current.error);
					if (current.contents)
					{
						const auto parsed = ParseConfig(*current.contents, configPath_);
						if (!parsed.config)
							return Error(500, "saved configuration is invalid");
						configured = *parsed.config;
					}
				}
			}
			std::filesystem::path projectRoot;
			try
			{
				if (configured.projects.defaultRoot)
					projectRoot = *configured.projects.defaultRoot;
				else if (!configured.projects.roots.empty())
					projectRoot = configured.projects.roots.front();
				else
					projectRoot = platform::HomeDirectory() / "binja-projects";
			}
			catch (const std::exception& exception)
			{
				return Error(500, "cannot determine the default project root: " + std::string(exception.what()));
			}
			const auto projectRootStatus = InspectDirectory(projectRoot);
			if (!projectRootStatus.error.empty())
				return Error(500, "cannot inspect the project root: " + projectRootStatus.error);
			if (projectRootStatus.exists && !projectRootStatus.directory)
				return Error(500, "the configured project root is not a directory");

			const auto displayedRoot = DisplayOnboardingPath(projectRoot);
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("required");
				writer.Bool(true);
				writer.Key("project_root");
				writer.String(displayedRoot.data(), static_cast<rapidjson::SizeType>(displayedRoot.size()));
				writer.Key("project_root_exists");
				writer.Bool(projectRootStatus.exists);
				writer.Key("public_base_url");
				writer.String(configured.http.publicBaseUrl.data(),
					static_cast<rapidjson::SizeType>(configured.http.publicBaseUrl.size()));
				writer.Key("allow_arbitrary_paths");
				writer.Bool(configured.projects.allowArbitraryPaths);
				writer.Key("allow_project_registration");
				writer.Bool(configured.projects.allowProjectRegistration);
				writer.EndObject();
			}));
		}
		if (request.path == apiPath_ + "/onboarding" && request.method == http::Method::Post)
		{
			if (configPath_.empty())
				return Error(503, "configuration persistence is unavailable");
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body
				|| !OnlyFields(*body,
					{"username", "password", "project_root", "create_project_root", "public_base_url",
						"allow_arbitrary_paths", "allow_project_registration"},
					error))
				return Error(400, error);

			std::string username;
			std::string password;
			std::string projectRootInput;
			std::string publicBaseUrl;
			bool createProjectRoot = false;
			bool allowArbitraryPaths = false;
			bool allowProjectRegistration = false;
			if (!StringField(*body, "username", username, true, error)
				|| !StringField(*body, "password", password, true, error)
				|| !StringField(*body, "project_root", projectRootInput, true, error)
				|| !BoolField(*body, "create_project_root", createProjectRoot, true, error)
				|| !StringField(*body, "public_base_url", publicBaseUrl, true, error)
				|| !BoolField(*body, "allow_arbitrary_paths", allowArbitraryPaths, true, error)
				|| !BoolField(*body, "allow_project_registration", allowProjectRegistration, true, error))
				return Error(400, error);
			if (!ValidOnboardingUsername(username))
				return Error(400, "username must be 1 through 64 ASCII letters, digits, '.', '_', or '-'");
			if (!security::IsValidPortalPassword(password))
				return Error(400, "password must be valid UTF-8 from 9 through 1024 bytes");
			if (publicBaseUrl.empty())
				return Error(400, "public_base_url must not be empty");
			const auto projectRoot = ResolveOnboardingProjectRoot(projectRootInput, configPath_, error);
			if (!projectRoot)
				return Error(400, error);

			security::AccountRecord account;
			bool restartRequired = false;
			std::string portalUrl;
			{
				std::lock_guard lock(configurationMutex_);
				const auto required = service_.SetupRequired();
				if (!required.value)
					return Error(500, required.error);
				if (!*required.value)
					return Error(409, "account is already configured");

				const auto current = platform::ReadPrivateFile(configPath_);
				if (!current.error.empty())
					return Error(500, current.error);
				if (!current.contents)
					return Error(500, "configuration file is unavailable");
				auto document = ParseObject(*current.contents, error);
				if (!document)
					return Error(500, "cannot update malformed configuration: " + error);
				const auto currentConfig = ParseConfig(*current.contents, configPath_);
				if (!currentConfig.config)
					return Error(500, "cannot update invalid configuration");

				auto& allocator = document->GetAllocator();
				auto& projects = EnsureObjectMember(*document, "projects", allocator);
				auto& roots = EnsureArrayMember(projects, "roots", allocator);
				if (std::find(currentConfig.config->projects.roots.begin(), currentConfig.config->projects.roots.end(),
						*projectRoot)
					== currentConfig.config->projects.roots.end())
				{
					Value storedRoot;
					const auto rootString = projectRoot->string();
					storedRoot.SetString(
						rootString.data(), static_cast<rapidjson::SizeType>(rootString.size()), allocator);
					roots.PushBack(storedRoot, allocator);
				}
				const auto rootString = projectRoot->string();
				SetStringMember(projects, "default_root", rootString, allocator);
				SetBoolMember(projects, "allow_arbitrary_paths", allowArbitraryPaths, allocator);
				SetBoolMember(projects, "allow_project_registration", allowProjectRegistration, allocator);
				auto& http = EnsureObjectMember(*document, "http", allocator);
				SetStringMember(http, "public_base_url", publicBaseUrl, allocator);

				const auto serialized = Serialize(*document);
				const auto configured = ParseConfig(serialized, configPath_);
				if (!configured.config)
				{
					if (configured.errors.empty())
						return Error(400, "onboarding produced an invalid configuration");
					return Error(400, configured.errors.front().path + ": " + configured.errors.front().message);
				}

				const auto projectRootStatus = InspectDirectory(*projectRoot);
				if (!projectRootStatus.error.empty())
					return Error(400, "cannot inspect project_root: " + projectRootStatus.error);
				if (projectRootStatus.exists && !projectRootStatus.directory)
					return Error(400, "project_root exists but is not a directory");
				if (!projectRootStatus.exists && !createProjectRoot)
					return Error(400, "project_root does not exist; select create_project_root or choose a directory");
				if (!projectRootStatus.exists)
				{
					if (const auto createError = platform::CreatePrivateDirectory(*projectRoot); !createError.empty())
						return Error(400, createError);
				}

				const auto persisted = platform::ReplacePrivateFile(configPath_, serialized + "\n");
				if (!persisted.installed)
					return Error(500, persisted.error);
				const auto created = service_.CreateInitialAccount(username, password);
				if (!created.value)
					return Error(created.error == "account is already configured" ? 409 : 400, created.error);
				account = *created.value;
				restartRequired_ = !SameRestartGatedConfig(config_, *configured.config);
				restartRequired = restartRequired_;
				portalUrl = configured.config->http.publicBaseUrl + configured.config->http.portalPath;
			}

			return Json(201, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("account");
				WriteAccount(writer, account);
				writer.Key("project_root");
				const auto rootString = projectRoot->string();
				writer.String(rootString.data(), static_cast<rapidjson::SizeType>(rootString.size()));
				writer.Key("restart_required");
				writer.Bool(restartRequired);
				writer.Key("portal_url");
				writer.String(portalUrl.data(), static_cast<rapidjson::SizeType>(portalUrl.size()));
				writer.EndObject();
			}));
		}
		if (request.path == apiPath_ + "/setup" && request.method == http::Method::Get)
		{
			const auto required = service_.SetupRequired();
			if (!required.value)
				return Error(500, required.error);
			return Json(200, JsonResult([&](auto& writer) { writer.Bool(*required.value); }));
		}
		if (request.path == apiPath_ + "/setup" && request.method == http::Method::Post)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {"username", "password"}, error))
				return Error(400, error);
			std::string username;
			std::string password;
			if (!StringField(*body, "username", username, true, error)
				|| !StringField(*body, "password", password, true, error))
				return Error(400, error);
			std::lock_guard lock(configurationMutex_);
			const auto created = service_.CreateInitialAccount(std::move(username), std::move(password));
			if (!created.value)
				return Error(created.error == "account is already configured" ? 409 : 400, created.error);
			return Json(201, JsonResult([&](auto& writer) { WriteAccount(writer, *created.value); }));
		}

		http::ImmediateResponse authenticationError;
		const auto actor = Authenticate(request, authenticationError);
		if (!actor)
			return authenticationError;

		if (request.path == apiPath_ + "/status" && request.method == http::Method::Get)
		{
			const auto status = runtimeStatus_ ? runtimeStatus_() : RuntimeStatus {};
			const auto token = service_.Token(*actor);
			if (!token.value)
				return Error(500, token.error);
			auto projects = projectList_ ? projectList_() : std::vector<ProjectSummary> {};
			std::sort(projects.begin(), projects.end(), [](const auto& left, const auto& right) {
				return left.name < right.name || (left.name == right.name && left.reference < right.reference);
			});
			bool restartRequired = false;
			ToolConfig tools;
			{
				std::lock_guard lock(configurationMutex_);
				restartRequired = restartRequired_;
				tools = config_.tools;
			}
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("version");
				writer.String(BINJAD_VERSION);
				writer.Key("mode");
				writer.String("local");
				writer.Key("restart_required");
				writer.Bool(restartRequired);
				writer.Key("actor");
				WriteAccount(writer, *actor);
				writer.Key("token");
				if (token.value->token)
					WriteToken(writer, *token.value->token);
				else
					writer.Null();
				writer.Key("projects");
				writer.StartArray();
				for (const auto& project : projects)
					WriteProject(writer, project);
				writer.EndArray();
				writer.Key("tools");
				WriteToolConfig(writer, tools);
				writer.Key("runtime");
				writer.StartObject();
				writer.Key("analysis_sessions");
				writer.Uint64(status.analysisSessions);
				writer.Key("open_items");
				writer.Uint64(status.openItems);
				writer.Key("jobs");
				writer.Uint64(status.jobs);
				writer.Key("projects");
				writer.Uint64(status.projects);
				writer.Key("logical_cpu_count");
				writer.Uint64(status.logicalCpuCount);
				writer.Key("worker_budget");
				writer.Uint64(status.workerBudget);
				writer.Key("allocated_workers");
				writer.Uint64(status.allocatedWorkers);
				writer.Key("active_analyses");
				writer.Uint64(status.activeAnalyses);
				writer.Key("queued_analyses");
				writer.Uint64(status.queuedAnalyses);
				writer.Key("memory_bytes");
				writer.Uint64(status.memoryBytes);
				writer.EndObject();
				writer.EndObject();
			}));
		}

		if (request.path == apiPath_ + "/restart" && request.method == http::Method::Post)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {}, error))
				return Error(400, error);

			RestartCallback restart;
			Config configured;
			bool schedule = false;
			{
				std::lock_guard lock(configurationMutex_);
				if (!restartRequired_)
					return Error(409, "daemon restart is not required");
				if (!restartCallback_)
					return Error(503, "daemon restart is unavailable");
				if (configPath_.empty())
					return Error(503, "configuration persistence is unavailable");

				const auto current = platform::ReadPrivateFile(configPath_);
				if (!current.error.empty())
					return Error(500, current.error);
				if (!current.contents)
					return Error(500, "configuration file is unavailable");
				const auto parsed = ParseConfig(*current.contents, configPath_);
				if (!parsed.config)
					return Error(409, "saved configuration is invalid");

				configured = *parsed.config;
				restart = restartCallback_;
				if (!restartScheduled_)
				{
					restartScheduled_ = true;
					schedule = true;
				}
			}

			if (schedule)
			{
				try
				{
					restart();
				}
				catch (...)
				{
					std::lock_guard lock(configurationMutex_);
					restartScheduled_ = false;
					return Error(500, "daemon restart could not be scheduled");
				}
			}

			const auto portalUrl = configured.http.publicBaseUrl + configured.http.portalPath;
			auto response = Json(202, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("restarting");
				writer.Bool(true);
				writer.Key("portal_url");
				writer.String(portalUrl.data(), static_cast<rapidjson::SizeType>(portalUrl.size()));
				writer.Key("retry_after_seconds");
				writer.Uint(10);
				writer.EndObject();
			}));
			response.headers.emplace_back("Retry-After", "10");
			return response;
		}

		if ((request.path == apiPath_ + "/mcp/context" || request.path == apiPath_ + "/mcp/tools")
			&& request.method == http::Method::Post)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			const bool context = request.path == apiPath_ + "/mcp/context";
			if (!body
				|| !OnlyFields(*body,
					context ? std::initializer_list<std::string_view> {"protocol", "client"} :
							  std::initializer_list<std::string_view> {"protocol"},
					error))
				return Error(400, error);
			std::string protocolName;
			if (!StringField(*body, "protocol", protocolName, true, error))
				return Error(400, error);
			const auto protocol = mcp::ParseProtocolVersion(protocolName);
			if (!protocol)
				return Error(400, "protocol must be a supported MCP protocol version");
			std::string result;
			if (context)
			{
				std::string client = "binjad";
				if (!StringField(*body, "client", client, false, error))
					return Error(400, error);
				if (client.empty() || client.size() > 64
					|| !std::all_of(client.begin(), client.end(), [](unsigned char character) {
						   return std::isalnum(character) != 0 || character == '_' || character == '-';
					   }))
					return Error(400, "client must contain 1 through 64 ASCII letters, digits, '_' or '-'");
				if (!mcpContext_)
					return Error(503, "MCP context documentation is unavailable");
				result = mcpContext_(*protocol, security::TokenRole::Admin, client);
			}
			else
			{
				if (!mcpTools_)
					return Error(503, "MCP tool documentation is unavailable");
				result = mcpTools_(*protocol, security::TokenRole::Admin);
			}
			Document documented;
			documented.Parse(result.data(), result.size());
			if (documented.HasParseError() || !documented.IsObject())
				return Error(500, "MCP documentation provider returned invalid JSON");
			return Json(200, JsonResult([&](auto& writer) { documented.Accept(writer); }));
		}

		if (request.path == apiPath_ + "/tools" && request.method == http::Method::Get)
		{
			std::lock_guard lock(configurationMutex_);
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("tools");
				WriteToolConfig(writer, config_.tools);
				writer.Key("restart_required");
				writer.Bool(restartRequired_);
				writer.EndObject();
			}));
		}
		if (request.path == apiPath_ + "/tools" && request.method == http::Method::Patch)
		{
			if (configPath_.empty())
				return Error(503, "configuration persistence is unavailable");
			std::string error;
			const auto patch = ParseObject(request.body, error);
			if (!patch)
				return Error(400, error);

			std::vector<std::pair<std::string, bool>> changes;
			if (!ReadToolPackChanges(*patch, changes, error))
				return Error(400, error);
			const auto updated = UpdateToolPacks(changes);
			if (!updated.value)
				return Error(500, updated.error);
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("tools");
				WriteToolConfig(writer, updated.value->tools);
				writer.Key("restart_required");
				writer.Bool(updated.value->restartRequired);
				writer.EndObject();
			}));
		}

		if (request.path == apiPath_ + "/config" && request.method == http::Method::Get)
		{
			std::lock_guard lock(configurationMutex_);
			std::string configured = activeConfiguration_;
			if (!configPath_.empty())
			{
				const auto current = platform::ReadPrivateFile(configPath_);
				if (!current.error.empty())
					return Error(500, current.error);
				if (current.contents)
					configured = NormalizeJson(*current.contents);
			}
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("configuration");
				writer.RawValue(configured.data(), configured.size(), rapidjson::kObjectType);
				writer.Key("restart_required");
				writer.Bool(restartRequired_);
				writer.EndObject();
			}));
		}
		if (request.path == apiPath_ + "/config" && request.method == http::Method::Put)
		{
			if (configPath_.empty())
				return Error(503, "configuration persistence is unavailable");
			const auto parsed = ParseConfig(request.body, configPath_);
			if (!parsed.config)
			{
				return Json(400, JsonResult([&](auto& writer) {
					writer.StartObject();
					writer.Key("valid");
					writer.Bool(false);
					writer.Key("errors");
					writer.StartArray();
					for (const auto& item : parsed.errors)
					{
						writer.StartObject();
						writer.Key("path");
						writer.String(item.path.data(), static_cast<rapidjson::SizeType>(item.path.size()));
						writer.Key("message");
						writer.String(item.message.data(), static_cast<rapidjson::SizeType>(item.message.size()));
						writer.EndObject();
					}
					writer.EndArray();
					writer.EndObject();
				}));
			}
			const auto normalized = NormalizeJson(request.body);
			if (normalized.empty())
				return Error(400, "invalid configuration JSON");
			bool restartRequired = false;
			bool toolsChanged = false;
			ToolConfig appliedTools = parsed.config->tools;
			{
				std::lock_guard lock(configurationMutex_);
				const auto persisted = platform::ReplacePrivateFile(configPath_, request.body + "\n");
				if (!persisted.installed)
					return Error(500, persisted.error);
				appliedTools.discoveryMode = config_.tools.discoveryMode;
				toolsChanged = !SameToolPacks(config_.tools, appliedTools);
				config_.tools = appliedTools;
				restartRequired_ = !SameRestartGatedConfig(config_, *parsed.config);
				restartRequired = restartRequired_;
			}
			if (toolsChanged && toolConfigApply_)
				toolConfigApply_(appliedTools);
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("valid");
				writer.Bool(true);
				writer.Key("restart_required");
				writer.Bool(restartRequired);
				writer.Key("effective_mode");
				writer.String("local");
				writer.EndObject();
			}));
		}

		if (request.path == apiPath_ + "/projects" && request.method == http::Method::Post)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {"name", "path", "description"}, error))
				return Error(400, error);
			std::string name;
			std::string path;
			std::string description;
			if (!StringField(*body, "name", name, true, error) || !StringField(*body, "path", path, false, error)
				|| !StringField(*body, "description", description, false, error))
				return Error(400, error);
			if (!projectCreate_)
				return Error(503, "local project creation is unavailable");
			const auto created = projectCreate_(std::move(name),
				path.empty() ? std::nullopt : std::optional<std::string>(std::move(path)), std::move(description));
			if (!created.value)
				return Error(400, created.error);
			return Json(201, JsonResult([&](auto& writer) { WriteProject(writer, *created.value); }));
		}

		if (request.path == apiPath_ + "/projects" && request.method == http::Method::Get)
		{
			auto projects = projectList_ ? projectList_() : std::vector<ProjectSummary> {};
			std::sort(projects.begin(), projects.end(), [](const auto& left, const auto& right) {
				return left.name < right.name || (left.name == right.name && left.reference < right.reference);
			});
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartArray();
				for (const auto& project : projects)
					WriteProject(writer, project);
				writer.EndArray();
			}));
		}

		if (request.path == apiPath_ + "/account" && request.method == http::Method::Get)
		{
			const auto account = service_.CurrentAccount(*actor);
			if (!account.value)
				return Error(404, account.error);
			return Json(200, JsonResult([&](auto& writer) { WriteAccount(writer, *account.value); }));
		}
		if (request.path == apiPath_ + "/account" && request.method == http::Method::Patch)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {"password"}, error))
				return Error(400, error);
			std::string password;
			if (!StringField(*body, "password", password, true, error))
				return Error(400, error);
			const auto updated = service_.UpdatePassword(*actor, std::move(password));
			if (!updated.value)
				return Error(updated.error == "account not found" ? 404 : 400, updated.error);
			return Json(200, JsonResult([&](auto& writer) { WriteAccount(writer, *updated.value); }));
		}

		const auto projectsPrefix = apiPath_ + "/projects/";
		if (request.path.starts_with(projectsPrefix) && request.method == http::Method::Delete)
		{
			const auto project = SegmentAfter(request.path, projectsPrefix);
			if (project.empty() || project.find('/') != std::string_view::npos)
				return Error(404, "project not found");
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {"delete"}, error))
				return Error(400, error);
			const auto confirmed = body->FindMember("delete");
			if (confirmed == body->MemberEnd() || !confirmed->value.IsBool() || !confirmed->value.GetBool())
				return Error(400, "delete must be true");
			if (!projectDelete_)
				return Error(400, "local project deletion is unavailable");
			const auto deleted = projectDelete_(project);
			if (!deleted.value)
			{
				const auto status = deleted.error == "project not found" ?
					404 :
					deleted.error == "project has open analysis handles" ?
					409 :
					400;
				return Error(status, deleted.error);
			}
			return Json(200, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("project");
				writer.String(project.data(), static_cast<rapidjson::SizeType>(project.size()));
				writer.Key("deleted");
				writer.Bool(*deleted.value);
				writer.EndObject();
			}));
		}

		if (request.path == apiPath_ + "/token" && request.method == http::Method::Get)
		{
			const auto token = service_.Token(*actor);
			if (!token.value)
				return Error(400, token.error);
			return Json(200, JsonResult([&](auto& writer) {
				if (token.value->token)
					WriteToken(writer, *token.value->token);
				else
					writer.Null();
			}));
		}
		if (request.path == apiPath_ + "/token" && request.method == http::Method::Post)
		{
			std::string error;
			const auto body = ParseObject(request.body, error);
			if (!body || !OnlyFields(*body, {"ttl_seconds"}, error))
				return Error(400, error);
			TokenRequest tokenRequest;
			const auto ttl = body->FindMember("ttl_seconds");
			if (ttl == body->MemberEnd() || !ttl->value.IsUint64())
				return Error(400, "ttl_seconds must be an unsigned integer");
			tokenRequest.ttlSeconds = ttl->value.GetUint64();
			const auto issued = service_.RotateToken(*actor, tokenRequest);
			if (!issued.value || !issued.value->token || !issued.value->record)
				return Error(400, issued.error);
			return Json(201, JsonResult([&](auto& writer) {
				writer.StartObject();
				writer.Key("token");
				writer.String(
					issued.value->token->data(), static_cast<rapidjson::SizeType>(issued.value->token->size()));
				writer.Key("metadata");
				WriteToken(writer, *issued.value->record);
				writer.EndObject();
			}));
		}
		if (request.path == apiPath_ + "/token" && request.method == http::Method::Delete)
		{
			const auto revoked = service_.RevokeToken(*actor);
			if (!revoked.value || !*revoked.value)
				return revoked.error.empty() ? Error(404, "token not found") : Error(400, revoked.error);
			return {204, {}, {}, {{"Cache-Control", "no-store"}}};
		}
		return Error(404, "not found");
	}

	http::ImmediateResponse Api::PublicStatus() const
	{
		const auto status = runtimeStatus_ ? runtimeStatus_() : RuntimeStatus {};
		StringBuffer buffer;
		Writer<StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("analysis_sessions");
		writer.Uint64(status.analysisSessions);
		writer.Key("open_items");
		writer.Uint64(status.openItems);
		writer.Key("active_analyses");
		writer.Uint64(status.activeAnalyses);
		writer.Key("queued_analyses");
		writer.Uint64(status.queuedAnalyses);
		writer.Key("memory_bytes");
		writer.Uint64(status.memoryBytes);
		writer.EndObject();
		return Json(200, {buffer.GetString(), buffer.GetSize()});
	}

	http::ImmediateResponse Api::Page() const
	{
		const auto required = service_.SetupRequired();
		if (!required.value)
			return Error(500, required.error);
		if (*required.value)
		{
			return {302, "text/plain; charset=utf-8", {},
				{{"Location", config_.http.portalPath + "/setup"}, {"Cache-Control", "no-store"}}};
		}
		return RenderPage("index.html");
	}

	http::ImmediateResponse Api::SetupPage() const
	{
		const auto required = service_.SetupRequired();
		if (!required.value)
			return Error(500, required.error);
		if (!*required.value)
		{
			return {302, "text/plain; charset=utf-8", {},
				{{"Location", config_.http.portalPath}, {"Cache-Control", "no-store"}}};
		}
		return RenderPage("setup.html");
	}

	http::ImmediateResponse Api::RenderPage(std::string_view name) const
	{
		auto response = Asset(name);
		const auto escapeAttribute = [](std::string_view value) {
			std::string escaped;
			escaped.reserve(value.size());
			for (const auto character : value)
			{
				switch (character)
				{
				case '&':
					escaped += "&amp;";
					break;
				case '"':
					escaped += "&quot;";
					break;
				case '<':
					escaped += "&lt;";
					break;
				case '>':
					escaped += "&gt;";
					break;
				default:
					escaped += character;
				}
			}
			return escaped;
		};
		const auto replaceMarker = [&](std::string_view marker, std::string_view value) {
			for (auto position = response.body.find(marker); position != std::string::npos;
				position = response.body.find(marker, position + value.size()))
				response.body.replace(position, marker.size(), value);
		};
		const auto portalPath = escapeAttribute(config_.http.portalPath);
		replaceMarker("{{PORTAL_PATH}}", portalPath);
		const auto statusPath = escapeAttribute(config_.http.healthPath + "/status");
		replaceMarker("{{STATUS_PATH}}", statusPath);
		response.headers.emplace_back("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
			"connect-src 'self'; form-action 'self'; base-uri 'none'");
		return response;
	}

	http::ImmediateResponse Api::Asset(std::string_view name) const
	{
		if (name != "index.html" && name != "setup.html" && name != "app.css" && name != "app.js" && name != "setup.js"
			&& name != "binjad.png")
			return Error(404, "not found");
		const std::filesystem::path candidates[] {
			std::filesystem::path(BINJAD_PORTAL_SOURCE_DIR) / name,
			std::filesystem::path(BINJAD_PORTAL_INSTALL_DIR) / name,
		};
		for (const auto& path : candidates)
		{
			std::ifstream stream(path, std::ios::binary);
			if (!stream)
				continue;
			const std::string contents {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
			const auto contentType = name == "index.html" || name == "setup.html" ?
				"text/html; charset=utf-8" :
				name == "app.css" ?
				"text/css; charset=utf-8" :
				name == "app.js" || name == "setup.js" ?
				"text/javascript; charset=utf-8" :
				"image/png";
			return {200, contentType, contents, {{"Cache-Control", "no-store"}}};
		}
		return Error(500, "portal asset is unavailable");
	}

	std::optional<security::AccountRecord> Api::Authenticate(
		const ApiRequest& request, http::ImmediateResponse& error) const
	{
		const auto credentials = BasicCredentials(request.authorization);
		if (!credentials)
		{
			error = Unauthorized();
			return std::nullopt;
		}
		const auto authenticated = service_.Authenticate(credentials->first, credentials->second);
		if (authenticated.result != security::PasswordVerification::Match || !authenticated.account)
		{
			error = authenticated.result == security::PasswordVerification::Error ?
				Error(500, "authentication backend failure") :
				Unauthorized();
			return std::nullopt;
		}
		return authenticated.account;
	}
}  // namespace binjad::portal
