#include "binjad/Config.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace
{
bool HasError(const binjad::ConfigResult& result, const std::string& path)
{
    return std::any_of(
        result.errors.begin(), result.errors.end(), [&](const auto& error) { return error.path == path; });
}
} // namespace

TEST(ConfigTest, AppliesDocumentedDefaults)
{
    const auto result = binjad::ParseConfig("{}", "/tmp/binjad/config.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_TRUE(result.errors.empty());
    EXPECT_EQ(result.config->listener.addresses, (std::vector<std::string>{"127.0.0.1", "::1"}));
    EXPECT_EQ(result.config->listener.port, 8712);
    EXPECT_EQ(result.config->http.publicBaseUrl, "http://127.0.0.1:8712");
    EXPECT_EQ(result.config->http.allowedOrigins, (std::vector<std::string>{"http://127.0.0.1:8712"}));
    EXPECT_EQ(result.config->http.mcpMaxBodyBytes, 8U * 1024 * 1024);
    EXPECT_EQ(result.config->jobs.cancellationGrace, std::chrono::seconds(5));
    EXPECT_FALSE(result.config->uploads.requireBearerAuthentication);
    EXPECT_EQ(result.config->storage.tokensPath, "/tmp/binjad/tokens.json");
    EXPECT_EQ(result.config->storage.accountsPath, "/tmp/binjad/accounts.json");
    EXPECT_EQ(result.config->storage.spoolPath, "/tmp/binjad/spool");
    EXPECT_TRUE(result.config->projects.allowArbitraryPaths);
    EXPECT_FALSE(result.config->projects.allowProjectRegistration);
    EXPECT_TRUE(result.config->tools.projectManagement);
    EXPECT_TRUE(result.config->tools.functionAnalysis);
    EXPECT_TRUE(result.config->tools.binaryData);
    EXPECT_TRUE(result.config->tools.search);
    EXPECT_TRUE(result.config->tools.types);
    EXPECT_TRUE(result.config->tools.annotations);
    EXPECT_TRUE(result.config->tools.binaryEditing);
    EXPECT_TRUE(result.config->tools.history);
    EXPECT_TRUE(result.config->tools.headerParsing);
    EXPECT_TRUE(result.config->tools.urlGeneration);
    EXPECT_TRUE(result.config->tools.diffing);
    EXPECT_TRUE(result.config->tools.kernelCache);
    EXPECT_TRUE(result.config->tools.sharedCache);
    EXPECT_TRUE(result.config->tools.debugger);
}

TEST(ConfigTest, ResolvesRelativePaths)
{
    constexpr auto json = R"({
        "projects": {"roots": ["projects"], "default_root": "projects", "allow_arbitrary_paths": false,
            "allow_project_registration": true},
        "storage": {"spool_path": "temporary/uploads"}
    })";
    const auto result = binjad::ParseConfig(json, "/srv/binjad/config.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_EQ(result.config->projects.roots, (std::vector<std::filesystem::path>{"/srv/binjad/projects"}));
    ASSERT_TRUE(result.config->projects.defaultRoot.has_value());
    EXPECT_EQ(*result.config->projects.defaultRoot, "/srv/binjad/projects");
    EXPECT_FALSE(result.config->projects.allowArbitraryPaths);
    EXPECT_TRUE(result.config->projects.allowProjectRegistration);
    EXPECT_EQ(result.config->storage.spoolPath, "/srv/binjad/temporary/uploads");
}

TEST(ConfigTest, CollectsIndependentValidationErrors)
{
    constexpr auto json = R"({
        "listener": {"addresses": ["0.0.0.0"], "port": 0},
        "http": {"mcp_path": "mcp", "portal_path": "/mcp", "mcp_max_body_bytes": 0},
        "cpu": {"percentage": 0, "fairness": "everyone"},
        "sessions": {"ttl_seconds": 0},
        "jobs": {"cancellation_grace_seconds": 0},
        "uploads": {"max_bytes": 0, "memory_threshold_bytes": 5, "url_ttl_seconds": 0,
            "require_bearer_authentication": "yes"},
        "tools": {"project_management": "yes", "function_analysis": 1,
            "binary_data": null, "search": "yes", "types": 1,
            "annotations": null, "binary_editing": "yes", "history": 1, "header_parsing": [],
            "url_generation": null, "diffing": null,
            "kernel_cache": "yes", "shared_cache": 1, "debugger": null}
    })";
    const auto result = binjad::ParseConfig(json, "/tmp/config.json");
    EXPECT_FALSE(result.config.has_value());
    EXPECT_GE(result.errors.size(), 9U);
    EXPECT_TRUE(HasError(result, "$.listener.addresses[0]"));
    EXPECT_TRUE(HasError(result, "$.listener.port"));
    EXPECT_TRUE(HasError(result, "$.cpu.percentage"));
    EXPECT_TRUE(HasError(result, "$.sessions.ttl_seconds"));
    EXPECT_TRUE(HasError(result, "$.jobs.cancellation_grace_seconds"));
    EXPECT_TRUE(HasError(result, "$.uploads.max_bytes"));
    EXPECT_TRUE(HasError(result, "$.uploads.require_bearer_authentication"));
    EXPECT_TRUE(HasError(result, "$.http.mcp_max_body_bytes"));
    EXPECT_TRUE(HasError(result, "$.tools.project_management"));
    EXPECT_TRUE(HasError(result, "$.tools.function_analysis"));
    EXPECT_TRUE(HasError(result, "$.tools.binary_data"));
    EXPECT_TRUE(HasError(result, "$.tools.search"));
    EXPECT_TRUE(HasError(result, "$.tools.types"));
    EXPECT_TRUE(HasError(result, "$.tools.annotations"));
    EXPECT_TRUE(HasError(result, "$.tools.binary_editing"));
    EXPECT_TRUE(HasError(result, "$.tools.history"));
    EXPECT_TRUE(HasError(result, "$.tools.header_parsing"));
    EXPECT_TRUE(HasError(result, "$.tools.url_generation"));
    EXPECT_TRUE(HasError(result, "$.tools.diffing"));
    EXPECT_TRUE(HasError(result, "$.tools.kernel_cache"));
    EXPECT_TRUE(HasError(result, "$.tools.shared_cache"));
    EXPECT_TRUE(HasError(result, "$.tools.debugger"));
}

TEST(ConfigTest, LoadsToolPackToggles)
{
    const auto result = binjad::ParseConfig(R"({"tools":{
        "project_management":false,"function_analysis":false,"binary_data":false,
        "search":false,"types":false,"annotations":false,"binary_editing":false,
        "history":false,"header_parsing":false,"url_generation":false,"diffing":false,"kernel_cache":false,"shared_cache":false,
        "debugger":false}})",
        "/tmp/config.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_FALSE(result.config->tools.projectManagement);
    EXPECT_FALSE(result.config->tools.functionAnalysis);
    EXPECT_FALSE(result.config->tools.binaryData);
    EXPECT_FALSE(result.config->tools.search);
    EXPECT_FALSE(result.config->tools.types);
    EXPECT_FALSE(result.config->tools.annotations);
    EXPECT_FALSE(result.config->tools.binaryEditing);
    EXPECT_FALSE(result.config->tools.history);
    EXPECT_FALSE(result.config->tools.headerParsing);
    EXPECT_FALSE(result.config->tools.urlGeneration);
    EXPECT_FALSE(result.config->tools.diffing);
    EXPECT_FALSE(result.config->tools.kernelCache);
    EXPECT_FALSE(result.config->tools.sharedCache);
    EXPECT_FALSE(result.config->tools.debugger);
}

TEST(ConfigTest, LoadsLegacyPluginTogglesWhenToolsAreAbsent)
{
    const auto result = binjad::ParseConfig(R"({"plugins":{
        "kernel_cache":false,"shared_cache":false,"debugger":false}})",
        "/tmp/config.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_TRUE(result.config->tools.functionAnalysis);
    EXPECT_FALSE(result.config->tools.kernelCache);
    EXPECT_FALSE(result.config->tools.sharedCache);
    EXPECT_FALSE(result.config->tools.debugger);
}

TEST(ConfigTest, RejectsJsonComments)
{
    const auto result = binjad::ParseConfig("{// comment\n}", "/tmp/config.json");
    EXPECT_FALSE(result.config.has_value());
    ASSERT_EQ(result.errors.size(), 1U);
    EXPECT_EQ(result.errors.front().path, "$");
}

TEST(ConfigTest, AcceptsUnknownCommentFields)
{
    const auto result = binjad::ParseConfig(
        R"({"_comment": "listener documentation", "listener": {"_comment": "loopback"}})", "/tmp/config.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_TRUE(result.errors.empty());
}

TEST(ConfigTest, LoadsCheckedInExample)
{
    const auto result = binjad::LoadConfig(std::filesystem::path(BINJAD_SOURCE_DIR) / "config" / "config.example.json");
    ASSERT_TRUE(result.config.has_value());
    EXPECT_TRUE(result.errors.empty());
}

TEST(ConfigTest, CheckedInExampleMatchesGeneratedDefault)
{
    std::ifstream stream(std::filesystem::path(BINJAD_SOURCE_DIR) / "config" / "config.example.json", std::ios::binary);
    ASSERT_TRUE(stream);
    const std::string contents{std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
    EXPECT_EQ(contents, binjad::DefaultConfigJson());
}

#if !defined(_WIN32)
TEST(ConfigTest, CreatesPrivateDefaultWithoutOverwritingIt)
{
    const auto root = std::filesystem::temp_directory_path() / ("binjad-config-test-" + std::to_string(::getpid()));
    std::error_code ignored;
    std::filesystem::remove_all(root, ignored);
    const auto path = root / "nested" / "config.json";

    const auto first = binjad::LoadOrCreateConfig(path);
    ASSERT_TRUE(first.config.has_value());
    ASSERT_TRUE(first.errors.empty());

    struct stat fileMetadata{};
    ASSERT_EQ(::stat(path.c_str(), &fileMetadata), 0);
    EXPECT_EQ(fileMetadata.st_mode & 0777, 0600);
    struct stat directoryMetadata{};
    ASSERT_EQ(::stat(path.parent_path().c_str(), &directoryMetadata), 0);
    EXPECT_EQ(directoryMetadata.st_mode & 0777, 0700);

    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(stream);
        stream << R"({"cpu":{"percentage":42}})";
    }
    const auto second = binjad::LoadOrCreateConfig(path);
    ASSERT_TRUE(second.config.has_value());
    EXPECT_EQ(second.config->cpu.percentage, 42);

    std::filesystem::remove_all(root, ignored);
}
#endif
