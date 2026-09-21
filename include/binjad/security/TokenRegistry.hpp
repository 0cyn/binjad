#pragma once

#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/IntegrityFile.hpp"
#include "binjad/security/TokenAuthenticator.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace binjad::security {
	struct TokenIssueRequest
	{
		std::string issuerAccountId;
		TokenRole role = TokenRole::User;
		std::string label;
		std::uint64_t createdAt = 0;
		std::optional<std::uint64_t> expiresAt;
	};

	struct TokenIssueResult
	{
		std::optional<std::string> token;
		std::optional<TokenRecord> record;
		std::vector<TokenRecord> replaced;
		std::string error;
	};

	struct TokenRegistryParseResult
	{
		std::optional<TokenAuthenticator::Records> records;
		std::string error;
	};

	TokenRegistryParseResult ParseTokenRegistry(std::string_view json);
	std::string SerializeTokenRegistry(const TokenAuthenticator::Records& records);

	class TokenRegistry
	{
	public:
		TokenRegistry(CredentialStore& credentials, std::filesystem::path path);
		std::string Load();
		bool IsLoaded() const;
		const TokenAuthenticator& Authenticator() const;
		TokenAuthenticator::Records Records() const;
		std::vector<TokenRecord> RecordsForIssuer(std::string_view issuerAccountId) const;
		TokenIssueResult ReplaceForIssuer(const TokenIssueRequest& request);
		std::string Revoke(std::string_view tokenId, bool& removed);
		std::string RevokeByIssuer(std::string_view issuerAccountId, std::size_t& removed);

	private:
		CredentialStore& credentials_;
		IntegrityFile file_;
		std::string hmacKey_;
		TokenAuthenticator::Records records_;
		std::unique_ptr<TokenAuthenticator> authenticator_;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::security
