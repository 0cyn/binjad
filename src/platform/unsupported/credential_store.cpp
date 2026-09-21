#include "binjad/security/credential_store.hpp"

#include "../../security/platform_credential_store.hpp"

#include <stdexcept>

namespace binjad::security
{
std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(std::string_view)
{
    throw std::runtime_error("native credential storage is not implemented for this platform");
}
}
