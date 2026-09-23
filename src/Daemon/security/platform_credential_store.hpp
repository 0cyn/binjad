#pragma once

#include "binjad/security/credential_store.hpp"

#include <memory>
#include <string_view>

namespace binjad::security
{
std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(std::string_view namespaceId);
}
