#pragma once

#include "binjad/security/CredentialStore.hpp"

#include <memory>
#include <string>

namespace binjad::security
{
struct PlatformCredentialStoreOptions
{
    std::string namespaceId;
    bool standardInstallation = false;
};

std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(
    PlatformCredentialStoreOptions options);
}
