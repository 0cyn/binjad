#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad
{
enum class FairnessUnit
{
    AnalysisSession,
    BearerToken,
    File,
    AnalysisJob,
};

struct ListenerConfig
{
    std::vector<std::string> addresses{"127.0.0.1", "::1"};
    std::uint16_t port = 8712;
};

struct HttpConfig
{
    std::string publicBaseUrl;
    std::string mcpPath = "/mcp";
    std::string uploadPath = "/uploads";
    std::string portalPath = "/portal";
    std::string healthPath = "/healthz";
    std::vector<std::string> allowedOrigins;
    std::uint64_t mcpMaxBodyBytes = 8ULL * 1024 * 1024;
};

struct CpuConfig
{
    std::uint8_t percentage = 75;
    FairnessUnit fairness = FairnessUnit::AnalysisJob;
    std::string subdivision = "serial";
};

struct SessionConfig
{
    std::chrono::seconds ttl{1800};
};

struct JobConfig
{
    std::chrono::seconds detachAfter{30};
    std::chrono::seconds cancellationGrace{5};
};

struct UploadConfig
{
    std::uint64_t maxBytes = 4ULL * 1024 * 1024 * 1024;
    std::uint64_t memoryThresholdBytes = 256ULL * 1024 * 1024;
    std::chrono::seconds urlTtl{3600};
    bool requireBearerAuthentication = false;
};

struct ProjectConfig
{
    std::vector<std::filesystem::path> roots;
    std::optional<std::filesystem::path> defaultRoot;
    bool allowArbitraryPaths = true;
    bool allowProjectRegistration = false;
};

struct StorageConfig
{
    std::filesystem::path tokensPath;
    std::filesystem::path accountsPath;
    std::filesystem::path spoolPath;
};

struct ToolConfig
{
    bool projectManagement = true;
    bool functionAnalysis = true;
    bool binaryData = true;
    bool search = true;
    bool types = true;
    bool annotations = true;
    bool binaryEditing = true;
    bool history = true;
    bool headerParsing = true;
    bool urlGeneration = true;
    bool diffing = true;
    bool kernelCache = true;
    bool sharedCache = true;
    bool debugger = true;
};

struct Config
{
    ListenerConfig listener;
    HttpConfig http;
    CpuConfig cpu;
    SessionConfig sessions;
    JobConfig jobs;
    UploadConfig uploads;
    ProjectConfig projects;
    StorageConfig storage;
    ToolConfig tools;
};

struct ConfigError
{
    std::string path;
    std::string message;
};

struct ConfigResult
{
    std::optional<Config> config;
    std::vector<ConfigError> errors;
};

ConfigResult ParseConfig(std::string_view json, const std::filesystem::path& configPath);
ConfigResult LoadConfig(const std::filesystem::path& configPath);
ConfigResult LoadOrCreateConfig(const std::filesystem::path& configPath);
std::string_view DefaultConfigJson();
} // namespace binjad
