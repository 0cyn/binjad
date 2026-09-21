#include "binjad/security/credential_store.hpp"

#include "binjad/security/crypto.hpp"
#include "platform_credential_store.hpp"

#include <filesystem>

namespace binjad::security
{
std::string CredentialNamespace(const std::filesystem::path& configPath)
{
    const auto normalized = std::filesystem::absolute(configPath).lexically_normal().generic_string();
    return Sha256Hex(normalized);
}

std::unique_ptr<CredentialStore> CreateNativeCredentialStore(
    const std::filesystem::path& configPath)
{
    return CreatePlatformCredentialStore(CredentialNamespace(configPath));
}
}
