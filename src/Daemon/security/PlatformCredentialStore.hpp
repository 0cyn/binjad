#pragma once

#include "binjad/security/CredentialStore.hpp"

#include <filesystem>
#include <memory>
#include <string>

namespace binjad::security {
	struct PlatformCredentialStoreOptions
	{
		std::string namespaceId;
		bool standardInstallation = false;
		std::filesystem::path configPath;
	};

	std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(PlatformCredentialStoreOptions options);
}  // namespace binjad::security
