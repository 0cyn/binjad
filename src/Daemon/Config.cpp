#include "binjad/Config.hpp"
#include "binjad/platform/Paths.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>

namespace binjad {
	namespace {
		using rapidjson::Value;

		void AddError(std::vector<ConfigError>& errors, std::string path, std::string message)
		{
			errors.push_back({std::move(path), std::move(message)});
		}

		const Value* ReadObject(
			const Value& parent, const char* name, std::string_view parentPath, std::vector<ConfigError>& errors)
		{
			const auto member = parent.FindMember(name);
			if (member == parent.MemberEnd())
				return nullptr;
			if (!member->value.IsObject())
			{
				AddError(errors, std::string(parentPath) + '.' + name, "must be an object");
				return nullptr;
			}
			return &member->value;
		}

		std::optional<std::string> ReadString(
			const Value& parent, const char* name, std::string_view parentPath, std::vector<ConfigError>& errors)
		{
			const auto member = parent.FindMember(name);
			if (member == parent.MemberEnd())
				return std::nullopt;
			if (!member->value.IsString())
			{
				AddError(errors, std::string(parentPath) + '.' + name, "must be a string");
				return std::nullopt;
			}
			return std::string(member->value.GetString(), member->value.GetStringLength());
		}

		std::optional<std::uint64_t> ReadUnsigned(
			const Value& parent, const char* name, std::string_view parentPath, std::vector<ConfigError>& errors)
		{
			const auto member = parent.FindMember(name);
			if (member == parent.MemberEnd())
				return std::nullopt;
			if (!member->value.IsUint64())
			{
				AddError(errors, std::string(parentPath) + '.' + name, "must be an unsigned integer");
				return std::nullopt;
			}
			return member->value.GetUint64();
		}

		std::optional<bool> ReadBool(
			const Value& parent, const char* name, std::string_view parentPath, std::vector<ConfigError>& errors)
		{
			const auto member = parent.FindMember(name);
			if (member == parent.MemberEnd())
				return std::nullopt;
			if (!member->value.IsBool())
			{
				AddError(errors, std::string(parentPath) + '.' + name, "must be a boolean");
				return std::nullopt;
			}
			return member->value.GetBool();
		}

		std::filesystem::path ResolvePath(
			const std::filesystem::path& value, const std::filesystem::path& configDirectory)
		{
			if (value.is_absolute())
				return value.lexically_normal();
			return (configDirectory / value).lexically_normal();
		}

		bool IsIpv4Loopback(std::string_view address)
		{
			std::uint32_t octets[4] {};
			std::size_t start = 0;
			for (std::size_t octet = 0; octet < 4; ++octet)
			{
				const auto end = address.find('.', start);
				if ((octet < 3 && end == std::string_view::npos) || (octet == 3 && end != std::string_view::npos))
					return false;
				const auto part = address.substr(start, end == std::string_view::npos ? end : end - start);
				if (part.empty() || part.size() > 3)
					return false;
				std::uint32_t value = 0;
				for (const char character : part)
				{
					if (!std::isdigit(static_cast<unsigned char>(character)))
						return false;
					value = value * 10 + static_cast<unsigned>(character - '0');
				}
				if (value > 255)
					return false;
				octets[octet] = value;
				if (end == std::string_view::npos)
					break;
				start = end + 1;
			}
			return octets[0] == 127;
		}

		bool IsLoopbackAddress(std::string_view address)
		{
			return address == "::1" || IsIpv4Loopback(address);
		}

		bool HasWhitespaceOrControl(std::string_view value)
		{
			return std::any_of(value.begin(), value.end(), [](const char character) {
				return std::isspace(static_cast<unsigned char>(character))
					|| std::iscntrl(static_cast<unsigned char>(character));
			});
		}

		std::optional<std::string> HttpOrigin(std::string_view url)
		{
			const auto schemeEnd = url.find("://");
			if (schemeEnd == std::string_view::npos)
				return std::nullopt;
			const auto scheme = url.substr(0, schemeEnd);
			if (scheme != "http" && scheme != "https")
				return std::nullopt;
			const auto authorityStart = schemeEnd + 3;
			const auto authorityEnd = url.find_first_of("/?#", authorityStart);
			const auto authority = url.substr(authorityStart, authorityEnd - authorityStart);
			if (authority.empty() || HasWhitespaceOrControl(authority))
				return std::nullopt;
			return std::string(url.substr(0, authorityStart)) + std::string(authority);
		}

		bool ValidEndpointPath(std::string_view path)
		{
			return !path.empty() && path.front() == '/' && path.find_first_of("?#") == std::string_view::npos;
		}

		std::string DerivedPublicBase(const ListenerConfig& listener)
		{
			const auto& address = listener.addresses.front();
			const bool ipv6 = address.find(':') != std::string::npos;
			return "http://" + (ipv6 ? '[' + address + ']' : address) + ':' + std::to_string(listener.port);
		}

		void ParseListener(const Value& root, Config& config, std::vector<ConfigError>& errors)
		{
			const auto* section = ReadObject(root, "listener", "$", errors);
			if (!section)
				return;

			if (const auto member = section->FindMember("addresses"); member != section->MemberEnd())
			{
				if (!member->value.IsArray())
				{
					AddError(errors, "$.listener.addresses", "must be an array of loopback IP strings");
				}
				else
				{
					std::vector<std::string> addresses;
					std::set<std::string> unique;
					for (rapidjson::SizeType index = 0; index < member->value.Size(); ++index)
					{
						const auto& value = member->value[index];
						const auto path = "$.listener.addresses[" + std::to_string(index) + ']';
						if (!value.IsString())
						{
							AddError(errors, path, "must be a string");
							continue;
						}
						std::string address(value.GetString(), value.GetStringLength());
						if (!IsLoopbackAddress(address))
						{
							AddError(errors, path, "must be a numeric loopback IP address");
							continue;
						}
						if (!unique.insert(address).second)
						{
							AddError(errors, path, "duplicates an earlier listener address");
							continue;
						}
						addresses.push_back(std::move(address));
					}
					if (addresses.empty())
						AddError(errors, "$.listener.addresses", "must contain at least one valid address");
					else
						config.listener.addresses = std::move(addresses);
				}
			}

			if (const auto port = ReadUnsigned(*section, "port", "$.listener", errors))
			{
				if (*port == 0 || *port > std::numeric_limits<std::uint16_t>::max())
					AddError(errors, "$.listener.port", "must be between 1 and 65535");
				else
					config.listener.port = static_cast<std::uint16_t>(*port);
			}
		}

		void ParseHttp(const Value& root, Config& config, std::vector<ConfigError>& errors)
		{
			const auto* section = ReadObject(root, "http", "$", errors);
			if (section)
			{
				if (const auto value = ReadString(*section, "public_base_url", "$.http", errors))
					config.http.publicBaseUrl = *value;
				if (const auto value = ReadString(*section, "mcp_path", "$.http", errors))
					config.http.mcpPath = *value;
				if (const auto value = ReadString(*section, "upload_path", "$.http", errors))
					config.http.uploadPath = *value;
				if (const auto value = ReadString(*section, "portal_path", "$.http", errors))
					config.http.portalPath = *value;
				if (const auto value = ReadString(*section, "health_path", "$.http", errors))
					config.http.healthPath = *value;
				if (const auto value = ReadUnsigned(*section, "mcp_max_body_bytes", "$.http", errors))
				{
					if (*value == 0)
						AddError(errors, "$.http.mcp_max_body_bytes", "must be greater than zero");
					else
						config.http.mcpMaxBodyBytes = *value;
				}
				if (const auto origins = section->FindMember("allowed_origins"); origins != section->MemberEnd())
				{
					if (!origins->value.IsArray())
					{
						AddError(errors, "$.http.allowed_origins", "must be an array of HTTP origins");
					}
					else
					{
						config.http.allowedOrigins.clear();
						for (rapidjson::SizeType index = 0; index < origins->value.Size(); ++index)
						{
							const auto& value = origins->value[index];
							const auto path = "$.http.allowed_origins[" + std::to_string(index) + ']';
							if (!value.IsString())
							{
								AddError(errors, path, "must be a string");
								continue;
							}
							const std::string origin(value.GetString(), value.GetStringLength());
							const auto normalized = HttpOrigin(origin);
							if (!normalized || *normalized != origin)
							{
								AddError(errors, path, "must be an absolute HTTP origin without a path");
								continue;
							}
							config.http.allowedOrigins.push_back(origin);
						}
					}
				}
			}

			if (config.http.publicBaseUrl.empty())
				config.http.publicBaseUrl = DerivedPublicBase(config.listener);
			while (config.http.publicBaseUrl.size() > 1 && config.http.publicBaseUrl.back() == '/')
				config.http.publicBaseUrl.pop_back();

			const auto publicOrigin = HttpOrigin(config.http.publicBaseUrl);
			if (!publicOrigin)
				AddError(errors, "$.http.public_base_url", "must be an absolute HTTP or HTTPS URL");
			else if (std::find(config.http.allowedOrigins.begin(), config.http.allowedOrigins.end(), *publicOrigin)
				== config.http.allowedOrigins.end())
				config.http.allowedOrigins.push_back(*publicOrigin);

			const std::pair<std::string_view, std::string_view> paths[] = {
				{"$.http.mcp_path", config.http.mcpPath},
				{"$.http.upload_path", config.http.uploadPath},
				{"$.http.portal_path", config.http.portalPath},
				{"$.http.health_path", config.http.healthPath},
			};
			std::set<std::string_view> uniquePaths;
			for (const auto& [pathName, path] : paths)
			{
				if (!ValidEndpointPath(path))
					AddError(errors, std::string(pathName), "must begin with '/' and contain no query or fragment");
				else if (!uniquePaths.insert(path).second)
					AddError(errors, std::string(pathName), "must not duplicate another HTTP endpoint path");
			}
		}

		void ParseCpu(const Value& root, Config& config, std::vector<ConfigError>& errors)
		{
			const auto* section = ReadObject(root, "cpu", "$", errors);
			if (!section)
				return;
			if (const auto percentage = ReadUnsigned(*section, "percentage", "$.cpu", errors))
			{
				if (*percentage < 1 || *percentage > 100)
					AddError(errors, "$.cpu.percentage", "must be between 1 and 100");
				else
					config.cpu.percentage = static_cast<std::uint8_t>(*percentage);
			}
			if (const auto fairness = ReadString(*section, "fairness", "$.cpu", errors))
			{
				if (*fairness == "analysis_session")
					config.cpu.fairness = FairnessUnit::AnalysisSession;
				else if (*fairness == "bearer_token")
					config.cpu.fairness = FairnessUnit::BearerToken;
				else if (*fairness == "file")
					config.cpu.fairness = FairnessUnit::File;
				else if (*fairness == "job")
					config.cpu.fairness = FairnessUnit::AnalysisJob;
				else
					AddError(errors, "$.cpu.fairness", "must be analysis_session, bearer_token, file, or job");
			}
			if (const auto subdivision = ReadString(*section, "subdivision", "$.cpu", errors))
			{
				if (*subdivision != "serial" && *subdivision != "equal")
					AddError(errors, "$.cpu.subdivision", "must be serial or equal");
				else
					config.cpu.subdivision = *subdivision;
			}
		}

		void ParseDurationsAndUploads(const Value& root, Config& config, std::vector<ConfigError>& errors)
		{
			if (const auto* section = ReadObject(root, "sessions", "$", errors))
			{
				if (const auto value = ReadUnsigned(*section, "ttl_seconds", "$.sessions", errors))
				{
					if (*value == 0 || *value > static_cast<std::uint64_t>(std::chrono::seconds::max().count()))
						AddError(errors, "$.sessions.ttl_seconds", "must be greater than zero");
					else
						config.sessions.ttl = std::chrono::seconds(*value);
				}
			}
			if (const auto* section = ReadObject(root, "jobs", "$", errors))
			{
				if (const auto value = ReadUnsigned(*section, "detach_after_seconds", "$.jobs", errors))
				{
					if (*value > static_cast<std::uint64_t>(std::chrono::seconds::max().count()))
						AddError(errors, "$.jobs.detach_after_seconds", "is too large");
					else
						config.jobs.detachAfter = std::chrono::seconds(*value);
				}
				if (const auto value = ReadUnsigned(*section, "cancellation_grace_seconds", "$.jobs", errors))
				{
					if (*value == 0 || *value > static_cast<std::uint64_t>(std::chrono::seconds::max().count()))
						AddError(errors, "$.jobs.cancellation_grace_seconds", "must be greater than zero");
					else
						config.jobs.cancellationGrace = std::chrono::seconds(*value);
				}
			}
			if (const auto* section = ReadObject(root, "uploads", "$", errors))
			{
				if (const auto value = ReadUnsigned(*section, "max_bytes", "$.uploads", errors))
				{
					if (*value == 0)
						AddError(errors, "$.uploads.max_bytes", "must be greater than zero");
					else
						config.uploads.maxBytes = *value;
				}
				if (const auto value = ReadUnsigned(*section, "memory_threshold_bytes", "$.uploads", errors))
					config.uploads.memoryThresholdBytes = *value;
				if (const auto value = ReadUnsigned(*section, "url_ttl_seconds", "$.uploads", errors))
				{
					if (*value == 0 || *value > static_cast<std::uint64_t>(std::chrono::seconds::max().count()))
						AddError(errors, "$.uploads.url_ttl_seconds", "must be greater than zero");
					else
						config.uploads.urlTtl = std::chrono::seconds(*value);
				}
				if (const auto value = ReadBool(*section, "require_bearer_authentication", "$.uploads", errors))
					config.uploads.requireBearerAuthentication = *value;
			}
			if (config.uploads.memoryThresholdBytes > config.uploads.maxBytes)
				AddError(errors, "$.uploads.memory_threshold_bytes", "must not exceed max_bytes");
		}

		void ParseProjects(const Value& root, Config& config, const std::filesystem::path& configDirectory,
			std::vector<ConfigError>& errors)
		{
			const auto* section = ReadObject(root, "projects", "$", errors);
			if (!section)
				return;
			if (const auto roots = section->FindMember("roots"); roots != section->MemberEnd())
			{
				if (!roots->value.IsArray())
				{
					AddError(errors, "$.projects.roots", "must be an array of paths");
				}
				else
				{
					config.projects.roots.clear();
					std::set<std::filesystem::path> unique;
					for (rapidjson::SizeType index = 0; index < roots->value.Size(); ++index)
					{
						const auto& value = roots->value[index];
						const auto path = "$.projects.roots[" + std::to_string(index) + ']';
						if (!value.IsString())
						{
							AddError(errors, path, "must be a string");
							continue;
						}
						const std::filesystem::path raw(std::string(value.GetString(), value.GetStringLength()));
						if (raw.empty())
						{
							AddError(errors, path, "must not be empty");
							continue;
						}
						auto resolved = ResolvePath(raw, configDirectory);
						if (!unique.insert(resolved).second)
						{
							AddError(errors, path, "duplicates an earlier project root");
							continue;
						}
						config.projects.roots.push_back(std::move(resolved));
					}
				}
			}
			if (const auto value = ReadString(*section, "default_root", "$.projects", errors); value && !value->empty())
				config.projects.defaultRoot = ResolvePath(std::filesystem::path(*value), configDirectory);
			if (const auto value = ReadBool(*section, "allow_arbitrary_paths", "$.projects", errors))
				config.projects.allowArbitraryPaths = *value;
			if (const auto value = ReadBool(*section, "allow_project_registration", "$.projects", errors))
				config.projects.allowProjectRegistration = *value;

			if (config.projects.defaultRoot
				&& std::find(config.projects.roots.begin(), config.projects.roots.end(), *config.projects.defaultRoot)
					== config.projects.roots.end())
				AddError(errors, "$.projects.default_root", "must name one of projects.roots");
		}

		void ParseStorage(const Value& root, Config& config, const std::filesystem::path& configDirectory,
			std::vector<ConfigError>& errors)
		{
			std::string tokens;
			std::string accounts;
			std::string spool;
			if (const auto* section = ReadObject(root, "storage", "$", errors))
			{
				tokens = ReadString(*section, "tokens_path", "$.storage", errors).value_or("");
				accounts = ReadString(*section, "accounts_path", "$.storage", errors).value_or("");
				spool = ReadString(*section, "spool_path", "$.storage", errors).value_or("");
			}
			config.storage.tokensPath = ResolvePath(tokens.empty() ? "tokens.json" : tokens, configDirectory);
			config.storage.accountsPath = ResolvePath(accounts.empty() ? "accounts.json" : accounts, configDirectory);
			config.storage.spoolPath = ResolvePath(spool.empty() ? "spool" : spool, configDirectory);
		}

		void ParseTools(const Value& root, Config& config, std::vector<ConfigError>& errors)
		{
			const bool hasTools = root.HasMember("tools");
			const auto* section = ReadObject(root, hasTools ? "tools" : "plugins", "$", errors);
			if (!section)
				return;
			const std::string path = hasTools ? "$.tools" : "$.plugins";
			if (hasTools)
			{
				if (const auto value = ReadString(*section, "discovery_mode", path, errors))
				{
					const auto mode = ParseToolDiscoveryMode(*value);
					if (mode)
						config.tools.discoveryMode = *mode;
					else
						AddError(errors, path + ".discovery_mode", "must be 'full' or 'brokered'");
				}
				if (const auto value = ReadBool(*section, "project_management", path, errors))
					config.tools.projectManagement = *value;
				if (const auto value = ReadBool(*section, "function_analysis", path, errors))
					config.tools.functionAnalysis = *value;
				if (const auto value = ReadBool(*section, "binary_data", path, errors))
					config.tools.binaryData = *value;
				if (const auto value = ReadBool(*section, "search", path, errors))
					config.tools.search = *value;
				if (const auto value = ReadBool(*section, "types", path, errors))
					config.tools.types = *value;
				if (const auto value = ReadBool(*section, "annotations", path, errors))
					config.tools.annotations = *value;
				if (const auto value = ReadBool(*section, "binary_editing", path, errors))
					config.tools.binaryEditing = *value;
				if (const auto value = ReadBool(*section, "history", path, errors))
					config.tools.history = *value;
				if (const auto value = ReadBool(*section, "header_parsing", path, errors))
					config.tools.headerParsing = *value;
				if (const auto value = ReadBool(*section, "url_generation", path, errors))
					config.tools.urlGeneration = *value;
				if (const auto value = ReadBool(*section, "diffing", path, errors))
					config.tools.diffing = *value;
			}
			if (const auto value = ReadBool(*section, "kernel_cache", path, errors))
				config.tools.kernelCache = *value;
			if (const auto value = ReadBool(*section, "shared_cache", path, errors))
				config.tools.sharedCache = *value;
			if (const auto value = ReadBool(*section, "debugger", path, errors))
				config.tools.debugger = *value;
		}
	}  // namespace

	std::string_view ToolDiscoveryModeName(ToolDiscoveryMode mode)
	{
		switch (mode)
		{
		case ToolDiscoveryMode::Full:
			return "full";
		case ToolDiscoveryMode::Brokered:
			return "brokered";
		}
		return "full";
	}

	std::optional<ToolDiscoveryMode> ParseToolDiscoveryMode(std::string_view name)
	{
		if (name == "full")
			return ToolDiscoveryMode::Full;
		if (name == "brokered")
			return ToolDiscoveryMode::Brokered;
		return std::nullopt;
	}

	ConfigResult ParseConfig(std::string_view json, const std::filesystem::path& configPath)
	{
		ConfigResult result;
		rapidjson::Document document;
		try
		{
			document.Parse(json.data(), json.size());
		}
		catch (const ParseException& exception)
		{
			AddError(result.errors, "$",
				std::string("invalid JSON at byte ") + std::to_string(exception.Offset()) + ": "
					+ rapidjson::GetParseError_En(exception.Code()));
			return result;
		}
		if (document.HasParseError())
		{
			AddError(result.errors, "$",
				std::string("invalid JSON at byte ") + std::to_string(document.GetErrorOffset()) + ": "
					+ rapidjson::GetParseError_En(document.GetParseError()));
			return result;
		}
		if (!document.IsObject())
		{
			AddError(result.errors, "$", "must be a JSON object");
			return result;
		}

		Config config;
		std::filesystem::path configDirectory;
		try
		{
			configDirectory = std::filesystem::absolute(configPath).parent_path().lexically_normal();
		}
		catch (const std::filesystem::filesystem_error& error)
		{
			AddError(result.errors, "$", std::string("cannot resolve configuration path: ") + error.what());
			return result;
		}
		ParseListener(document, config, result.errors);
		ParseHttp(document, config, result.errors);
		ParseCpu(document, config, result.errors);
		ParseDurationsAndUploads(document, config, result.errors);
		ParseProjects(document, config, configDirectory, result.errors);
		ParseStorage(document, config, configDirectory, result.errors);
		ParseTools(document, config, result.errors);

		if (result.errors.empty())
			result.config = std::move(config);
		return result;
	}

	ConfigResult LoadConfig(const std::filesystem::path& configPath)
	{
		std::ifstream stream(configPath, std::ios::binary);
		if (!stream)
			return {std::nullopt, {{"$", "cannot open configuration file: " + configPath.string()}}};
		const std::string contents {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
		if (stream.bad())
			return {std::nullopt, {{"$", "cannot read configuration file: " + configPath.string()}}};
		return ParseConfig(contents, configPath);
	}

	ConfigResult LoadOrCreateConfig(const std::filesystem::path& configPath)
	{
		const auto creation = platform::CreatePrivateFileIfAbsent(configPath, DefaultConfigJson());
		if (!creation.error.empty())
			return {std::nullopt, {{"$", creation.error}}};
		return LoadConfig(configPath);
	}

	std::string_view DefaultConfigJson()
	{
		return R"json({
  "_comment": "Unknown fields such as _comment are ignored. Known fields are validated strictly.",
  "listener": {
    "addresses": [
      "127.0.0.1",
      "::1"
    ],
    "port": 8712
  },
  "http": {
    "_comment": "Leave public_base_url empty to derive it from the first loopback listener.",
    "public_base_url": "",
    "mcp_path": "/mcp",
    "upload_path": "/uploads",
    "portal_path": "/portal",
    "health_path": "/healthz",
    "allowed_origins": [],
    "mcp_max_body_bytes": 8388608
  },
  "cpu": {
    "percentage": 75,
    "fairness": "job",
    "subdivision": "serial"
  },
  "sessions": {
    "ttl_seconds": 1800
  },
  "jobs": {
    "detach_after_seconds": 30,
    "cancellation_grace_seconds": 5
  },
  "uploads": {
    "max_bytes": 4294967296,
    "memory_threshold_bytes": 268435456,
    "url_ttl_seconds": 3600,
    "require_bearer_authentication": false
  },
  "projects": {
    "_comment": "Relative roots are resolved against this file's directory. Outside-root project creation and registration are disabled unless allow_project_registration is true.",
    "roots": [],
    "default_root": "",
    "allow_arbitrary_paths": true,
    "allow_project_registration": false
  },
  "storage": {
    "_comment": "Empty paths default beside this file.",
    "tokens_path": "",
    "accounts_path": "",
    "spool_path": ""
  },
  "tools": {
    "_comment": "Tool discovery and extended tool-pack changes are persisted and applied immediately. Brokered discovery advertises six setup/lifecycle calls and routes every other enabled tool through bn_tools.",
    "discovery_mode": "full",
    "project_management": true,
    "function_analysis": true,
    "binary_data": true,
    "search": true,
    "types": true,
    "annotations": true,
    "binary_editing": true,
    "history": true,
    "header_parsing": true,
    "url_generation": true,
    "diffing": true,
    "kernel_cache": true,
    "shared_cache": true,
    "debugger": true
  }
}
)json";
	}
}  // namespace binjad
