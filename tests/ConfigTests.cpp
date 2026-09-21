#include "binjad/Config.hpp"
#include "binjad/platform/Paths.hpp"

#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}

	bool HasError(const binjad::ConfigResult& result, std::string_view path)
	{
		for (const auto& error : result.errors)
		{
			if (error.path == path)
				return true;
		}
		return false;
	}
}  // namespace

int main()
{
	try
	{
		const auto configPath = std::filesystem::temp_directory_path() / "binjad-config-tests" / "config.json";
		const auto defaults = binjad::ParseConfig(binjad::DefaultConfigJson(), configPath);
		Require(defaults.config.has_value(), "default configuration did not parse");
		Require(defaults.config->binaryNinja.installationDirectory
				== binjad::platform::DefaultBinaryNinjaInstallationDirectory().lexically_normal(),
			"empty Binary Ninja path did not select the platform default");

#if defined(_WIN32)
		const std::filesystem::path customPath = "C:\\Binary Ninja Custom";
		const std::string customJson = R"json({"binary_ninja":{"installation_dir":"C:\\Binary Ninja Custom"}})json";
#else
		const std::filesystem::path customPath = "/opt/Binary Ninja Custom";
		const std::string customJson = R"json({"binary_ninja":{"installation_dir":"/opt/Binary Ninja Custom"}})json";
#endif
		const auto custom = binjad::ParseConfig(customJson, configPath);
		Require(custom.config.has_value(), "absolute Binary Ninja path did not parse");
		Require(custom.config->binaryNinja.installationDirectory == customPath.lexically_normal(),
			"custom Binary Ninja path changed during parsing");

		const auto relative =
			binjad::ParseConfig(R"json({"binary_ninja":{"installation_dir":"relative/binaryninja"}})json", configPath);
		Require(!relative.config.has_value(), "relative Binary Ninja path was accepted");
		Require(HasError(relative, "$.binary_ninja.installation_dir"),
			"relative Binary Ninja path did not report its field");

		std::string argv0 = "binjad";
		std::string option = "--config";
		std::string selectedPath = configPath.string();
		char* arguments[] {argv0.data(), option.data(), selectedPath.data(), nullptr};
		const auto selected = binjad::SelectConfigPath(3, arguments);
		Require(selected.path == configPath, "--config did not select the requested path");

		std::string missingValue = "--config";
		char* missingArguments[] {argv0.data(), missingValue.data(), nullptr};
		const auto missing = binjad::SelectConfigPath(2, missingArguments);
		Require(!missing.path && missing.error == "--config requires a path", "missing --config value was accepted");

		std::cout << "Configuration tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "Configuration tests failed: " << exception.what() << '\n';
		return 1;
	}
}
