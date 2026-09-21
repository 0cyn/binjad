#include "binjad/launcher/Launcher.hpp"

#include "binjad/platform/Paths.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <string>

#define RAPIDJSON_NAMESPACE       binjad_launcher_rapidjson
#define RAPIDJSON_NAMESPACE_BEGIN namespace binjad_launcher_rapidjson {
#define RAPIDJSON_NAMESPACE_END   }
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>

namespace binjad::launcher {
	namespace {
		bool HasControl(std::string_view value)
		{
			return std::any_of(value.begin(), value.end(), [](const unsigned char character) {
				return character < 0x20 || character == 0x7f;
			});
		}

		void AddError(std::vector<ConfigError>& errors, std::string path, std::string message)
		{
			errors.push_back({std::move(path), std::move(message)});
		}
	}  // namespace

	LauncherConfigurationResult Launcher::LoadConfiguration(const std::filesystem::path& configurationPath)
	{
		LauncherConfigurationResult result;
		const auto creation = platform::CreatePrivateFileIfAbsent(configurationPath, DefaultConfigJson());
		if (!creation.error.empty())
		{
			AddError(result.errors, "$", creation.error);
			return result;
		}
		const auto file = platform::ReadPrivateFile(configurationPath);
		if (!file.error.empty())
		{
			AddError(result.errors, "$", file.error);
			return result;
		}
		if (!file.contents)
		{
			AddError(result.errors, "$", "configuration file is unavailable: " + configurationPath.string());
			return result;
		}

		binjad_launcher_rapidjson::Document document;
		document.Parse(file.contents->data(), file.contents->size());
		if (document.HasParseError())
		{
			AddError(result.errors, "$",
				"invalid JSON at byte " + std::to_string(document.GetErrorOffset()) + ": "
					+ binjad_launcher_rapidjson::GetParseError_En(document.GetParseError()));
			return result;
		}
		if (!document.IsObject())
		{
			AddError(result.errors, "$", "must be a JSON object");
			return result;
		}

		BinaryNinjaConfig config;
		try
		{
			config.installationDirectory = platform::DefaultBinaryNinjaInstallationDirectory().lexically_normal();
		}
		catch (const std::exception& exception)
		{
			AddError(result.errors, "$.binary_ninja.installation_dir",
				"cannot determine the platform default: " + std::string(exception.what()));
			return result;
		}

		const auto section = document.FindMember("binary_ninja");
		if (section == document.MemberEnd())
		{
			result.config = std::move(config);
			return result;
		}
		if (!section->value.IsObject())
		{
			AddError(result.errors, "$.binary_ninja", "must be an object");
			return result;
		}
		const auto installation = section->value.FindMember("installation_dir");
		if (installation == section->value.MemberEnd())
		{
			result.config = std::move(config);
			return result;
		}
		if (!installation->value.IsString())
		{
			AddError(result.errors, "$.binary_ninja.installation_dir", "must be a string");
			return result;
		}
		const std::string value(installation->value.GetString(), installation->value.GetStringLength());
		if (value.empty())
		{
			result.config = std::move(config);
			return result;
		}
		if (HasControl(value))
		{
			AddError(result.errors, "$.binary_ninja.installation_dir", "must not contain control characters");
			return result;
		}
		const std::filesystem::path path(value);
		if (!path.is_absolute())
		{
			AddError(result.errors, "$.binary_ninja.installation_dir", "must be an absolute path or an empty string");
			return result;
		}
		config.installationDirectory = path.lexically_normal();
		result.config = std::move(config);
		return result;
	}
}  // namespace binjad::launcher
