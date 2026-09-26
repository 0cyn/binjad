#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::security
{
struct CredentialReadResult
{
    std::optional<std::string> value;
    std::string error;
};

class CredentialStore
{
  public:
    virtual ~CredentialStore() = default;
    virtual CredentialReadResult Read(std::string_view key) = 0;
    virtual std::string Write(std::string_view key, std::string_view value) = 0;
    virtual std::string Remove(std::string_view key) = 0;
};

std::string CredentialNamespace(const std::filesystem::path& configPath);
std::unique_ptr<CredentialStore> CreateNativeCredentialStore(
    const std::filesystem::path& configPath);
}
