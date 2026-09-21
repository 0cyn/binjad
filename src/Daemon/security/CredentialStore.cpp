#include "binjad/security/CredentialStore.hpp"

#include "binjad/platform/Paths.hpp"
#include "binjad/security/CredentialVault.hpp"
#include "binjad/security/Crypto.hpp"
#include "binjad/security/IntegrityFile.hpp"
#include "PlatformCredentialStore.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <filesystem>
#include <set>

namespace binjad::security {
	std::string CredentialNamespace(const std::filesystem::path& configPath)
	{
		const auto normalized = std::filesystem::absolute(configPath).lexically_normal().generic_string();
		return Sha256Hex(normalized);
	}

	std::filesystem::path FileCredentialStorePath(const std::filesystem::path& configPath)
	{
		auto normalized = std::filesystem::absolute(configPath).lexically_normal();
		normalized += ".credentials";
		return normalized;
	}

	std::unique_ptr<CredentialStore> CreateCredentialStore(const std::filesystem::path& configPath)
	{
		const auto normalized = std::filesystem::absolute(configPath).lexically_normal();
		const auto defaultPath = std::filesystem::absolute(platform::DefaultConfigPath()).lexically_normal();
		return CreatePlatformCredentialStore({CredentialNamespace(configPath), normalized == defaultPath, normalized});
	}

	CredentialVaultParseResult ParseCredentialVault(std::string_view contents)
	{
		rapidjson::Document document;
		try
		{
			document.Parse<rapidjson::kParseValidateEncodingFlag>(contents.data(), contents.size());
		}
		catch (const ParseException& exception)
		{
			return {{}, std::string("invalid credential vault JSON at byte ") + std::to_string(exception.Offset())};
		}
		if (document.HasParseError() || !document.IsObject())
			return {{}, "credential vault must be a JSON object"};

		std::set<std::string_view> fields;
		for (const auto& member : document.GetObject())
		{
			const std::string_view name(member.name.GetString(), member.name.GetStringLength());
			if (name != "version" && name != "values")
				return {{}, "credential vault contains unknown field '" + std::string(name) + "'"};
			if (!fields.insert(name).second)
				return {{}, "credential vault contains duplicate field '" + std::string(name) + "'"};
		}
		const auto version = document.FindMember("version");
		const auto values = document.FindMember("values");
		if (version == document.MemberEnd() || !version->value.IsUint() || version->value.GetUint() != 1)
			return {{}, "credential vault version must be 1"};
		if (values == document.MemberEnd() || !values->value.IsObject())
			return {{}, "credential vault values must be an object"};

		CredentialVaultValues result;
		for (const auto& member : values->value.GetObject())
		{
			const std::string key(member.name.GetString(), member.name.GetStringLength());
			if (key.empty())
				return {{}, "credential vault key must not be empty"};
			if (!member.value.IsString())
				return {{}, "credential vault value for '" + key + "' must be a string"};
			if (!result.emplace(key, std::string(member.value.GetString(), member.value.GetStringLength())).second)
				return {{}, "credential vault contains duplicate key '" + key + "'"};
		}
		return {std::move(result), {}};
	}

	std::string SerializeCredentialVault(const CredentialVaultValues& values)
	{
		rapidjson::StringBuffer buffer;
		rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
		writer.StartObject();
		writer.Key("version");
		writer.Uint(1);
		writer.Key("values");
		writer.StartObject();
		for (const auto& [key, value] : values)
		{
			writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
			writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
		}
		writer.EndObject();
		writer.EndObject();
		return {buffer.GetString(), buffer.GetSize()};
	}

	namespace {
		struct Anchor
		{
			std::string current;
			std::string pending;
		};

		bool IsHexDigest(std::string_view value)
		{
			return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char character) {
				return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
			});
		}

		std::optional<Anchor> ParseAnchor(std::string_view value)
		{
			constexpr std::string_view prefix = "1\n";
			if (!value.starts_with(prefix))
				return std::nullopt;
			value.remove_prefix(prefix.size());
			const auto separator = value.find('\n');
			if (separator == std::string_view::npos || value.find('\n', separator + 1) != std::string_view::npos)
				return std::nullopt;
			Anchor anchor {std::string(value.substr(0, separator)), std::string(value.substr(separator + 1))};
			if (!IsHexDigest(anchor.current) || (!anchor.pending.empty() && !IsHexDigest(anchor.pending)))
				return std::nullopt;
			return anchor;
		}

		std::string SerializeAnchor(std::string_view current, std::string_view pending = {})
		{
			return "1\n" + std::string(current) + '\n' + std::string(pending);
		}
	}  // namespace

	IntegrityFile::IntegrityFile(CredentialStore& credentials, std::filesystem::path path, std::string credentialKey) :
		credentials_(credentials), path_(std::move(path)), credentialKey_(std::move(credentialKey))
	{}

	IntegrityFileLoadResult IntegrityFile::LoadOrCreate(
		std::string_view initialContents, const EnrollExisting& mayEnrollExisting)
	{
		std::lock_guard lock(mutex_);
		if (currentDigest_)
			return {{}, false, "integrity file is already loaded"};

		auto file = platform::ReadPrivateFile(path_);
		if (!file.error.empty())
			return {{}, false, file.error};
		bool created = false;
		if (!file.contents)
		{
			const auto creation = platform::CreatePrivateFileIfAbsent(path_, initialContents);
			if (!creation.error.empty())
				return {{}, false, creation.error};
			created = creation.created;
			file = platform::ReadPrivateFile(path_);
			if (!file.error.empty())
				return {{}, created, file.error};
			if (!file.contents)
				return {{}, created, "private file disappeared during creation"};
		}

		const auto digest = Sha256Hex(*file.contents);
		const auto stored = credentials_.Read(credentialKey_);
		if (!stored.error.empty())
			return {{}, created, "cannot read integrity anchor: " + stored.error};
		if (!stored.value)
		{
			if (!created && (!mayEnrollExisting || !mayEnrollExisting(*file.contents)))
				return {{}, false, "existing private file has no integrity anchor"};
			if (const auto error = credentials_.Write(credentialKey_, SerializeAnchor(digest)); !error.empty())
				return {{}, created, "cannot create integrity anchor: " + error};
			currentDigest_ = digest;
			return {std::move(file.contents), created, {}};
		}

		const auto anchor = ParseAnchor(*stored.value);
		if (!anchor)
			return {{}, created, "integrity anchor is malformed"};
		if (ConstantTimeEqual(digest, anchor->current))
		{
			if (!anchor->pending.empty())
			{
				if (const auto error = credentials_.Write(credentialKey_, SerializeAnchor(anchor->current));
					!error.empty())
					return {{}, created, "cannot finish integrity recovery: " + error};
			}
			currentDigest_ = anchor->current;
		}
		else if (!anchor->pending.empty() && ConstantTimeEqual(digest, anchor->pending))
		{
			if (const auto error = credentials_.Write(credentialKey_, SerializeAnchor(anchor->pending)); !error.empty())
				return {{}, created, "cannot finish integrity recovery: " + error};
			currentDigest_ = anchor->pending;
		}
		else
		{
			return {{}, created, "private file does not match its integrity anchor"};
		}
		return {std::move(file.contents), created, {}};
	}

	std::string IntegrityFile::Replace(std::string_view contents)
	{
		std::lock_guard lock(mutex_);
		if (!currentDigest_)
			return "integrity file must be loaded before replacement";

		const auto existing = platform::ReadPrivateFile(path_);
		if (!existing.error.empty())
			return existing.error;
		if (!existing.contents)
			return "private file disappeared before replacement";
		if (!ConstantTimeEqual(Sha256Hex(*existing.contents), *currentDigest_))
			return "private file changed after it was loaded";

		const auto pending = Sha256Hex(contents);
		if (const auto error = credentials_.Write(credentialKey_, SerializeAnchor(*currentDigest_, pending));
			!error.empty())
			return "cannot stage integrity anchor: " + error;

		const auto replacement = platform::ReplacePrivateFile(path_, contents);
		if (replacement.installed)
			currentDigest_ = pending;
		if (!replacement.error.empty())
			return replacement.error;
		if (!replacement.installed)
			return "private file replacement did not install new contents";

		if (const auto error = credentials_.Write(credentialKey_, SerializeAnchor(*currentDigest_)); !error.empty())
			return "cannot finalize integrity anchor: " + error;
		return {};
	}
}  // namespace binjad::security
