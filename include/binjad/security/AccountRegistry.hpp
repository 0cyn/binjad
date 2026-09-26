#pragma once

#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/IntegrityFile.hpp"
#include "binjad/security/Password.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binjad::security {
	struct AccountRecord
	{
		std::string id;
		std::string username;
		std::uint64_t createdAt = 0;
	};

	using AccountRecords = std::unordered_map<std::string, AccountRecord>;

	struct AccountRegistryParseResult
	{
		std::optional<AccountRecords> records;
		std::string error;
	};

	struct AccountCreateRequest
	{
		std::string username;
		std::string password;
		std::uint64_t createdAt = 0;
	};

	struct AccountCreateResult
	{
		std::optional<AccountRecord> record;
		std::string error;
	};

	struct AccountAuthenticationResult
	{
		PasswordVerification result = PasswordVerification::Mismatch;
		std::optional<AccountRecord> account;
		std::string error;
	};

	struct AccountUpdateResult
	{
		std::optional<AccountRecord> record;
		std::string error;
	};

	AccountRegistryParseResult ParseAccountRegistry(std::string_view json);
	std::string SerializeAccountRegistry(const AccountRecords& records);

	class AccountRegistry
	{
	public:
		AccountRegistry(CredentialStore& credentials, std::filesystem::path path,
			Argon2Profile passwordProfile = kPortalPasswordProfile);
		std::string Load();
		bool IsLoaded() const;
		AccountRecords Records() const;
		std::optional<AccountRecord> FindActive(std::string_view username) const;
		std::optional<AccountRecord> Account() const;
		AccountCreateResult CreateInitial(const AccountCreateRequest& request);
		AccountAuthenticationResult Authenticate(std::string_view username, std::string_view password) const;
		AccountUpdateResult UpdatePassword(std::string_view accountId, std::string password);

	private:
		CredentialStore& credentials_;
		IntegrityFile file_;
		Argon2Profile passwordProfile_;
		AccountRecords records_;
		bool loaded_ = false;
		mutable std::mutex mutex_;
	};
}  // namespace binjad::security
