#pragma once

#include "binjad/security/credential_store.hpp"
#include "binjad/security/integrity_file.hpp"
#include "binjad/security/password.hpp"

#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binjad::security
{
enum class PortalRole
{
    Admin,
    SelfService,
};

struct AccountRecord
{
    std::string id;
    std::string username;
    PortalRole role = PortalRole::SelfService;
    std::uint64_t createdAt = 0;
    std::optional<std::string> collaborationUsername;
    std::optional<std::uint64_t> deletedAt;
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
    PortalRole role = PortalRole::SelfService;
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

struct AccountUpdateRequest
{
    std::optional<PortalRole> role;
    std::optional<std::string> password;
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
    AccountCreateResult Create(const AccountCreateRequest& request);
    AccountAuthenticationResult Authenticate(
        std::string_view username, std::string_view password) const;
    AccountUpdateResult Update(std::string_view accountId, const AccountUpdateRequest& request);
    std::string SetCollaborationBinding(std::string_view accountId,
        std::string collaborationUsername, std::string_view accessToken);
    CredentialReadResult CollaborationAccessToken(std::string_view accountId) const;
    std::string Delete(std::string_view accountId, std::uint64_t deletedAt, bool& deleted);

  private:
    CredentialStore& credentials_;
    IntegrityFile file_;
    Argon2Profile passwordProfile_;
    AccountRecords records_;
    bool loaded_ = false;
    mutable std::mutex mutex_;

    std::size_t ActiveAdministratorCount() const;
};
}
