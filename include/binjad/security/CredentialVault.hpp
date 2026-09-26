#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace binjad::security {
	using CredentialVaultValues = std::map<std::string, std::string>;

	struct CredentialVaultParseResult
	{
		std::optional<CredentialVaultValues> values;
		std::string error;
	};

	CredentialVaultParseResult ParseCredentialVault(std::string_view contents);
	std::string SerializeCredentialVault(const CredentialVaultValues& values);
}  // namespace binjad::security
