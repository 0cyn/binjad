#include "binjad/security/CredentialStore.hpp"

#include "../../security/PlatformCredentialStore.hpp"

#include <stdexcept>

namespace binjad::security {
	std::unique_ptr<CredentialStore> CreatePlatformCredentialStore(PlatformCredentialStoreOptions)
	{
		throw std::runtime_error("native credential storage is not implemented for this platform");
	}
}  // namespace binjad::security
