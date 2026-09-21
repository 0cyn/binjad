#pragma once

#include "binjad/config.hpp"
#include "binjad/security/account_registry.hpp"
#include "binjad/security/bootstrap_credential.hpp"
#include "binjad/security/token_registry.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::portal
{
template <typename T>
struct Result
{
    std::optional<T> value;
    std::string error;
};

struct TokenRequest
{
    std::optional<std::string> label;
    std::optional<security::TokenRole> role;
    std::optional<std::uint64_t> ttlSeconds;
};

struct AccountDeletionResult
{
    bool deleted = false;
    std::size_t revokedTokens = 0;
};

class Service
{
  public:
    using UnixNow = std::function<std::uint64_t()>;
    using TokenRevoked = std::function<void(std::string_view)>;

    Service(Config config, security::AccountRegistry& accounts,
        security::TokenRegistry& tokens, security::BootstrapCredential& bootstrap,
        UnixNow unixNow = {});
    void SetTokenRevokedCallback(TokenRevoked callback);

    Result<security::AccountRecord> CreateBootstrapAdministrator(
        std::string_view credential, std::string username, std::string password);
    Result<bool> BootstrapAvailable();
    security::AccountAuthenticationResult Authenticate(
        std::string_view username, std::string_view password) const;
    Result<security::AccountRecord> AuthenticateAdminBearer(
        std::string_view token) const;
    Result<security::AccountRecord> UnauthenticatedAdministrator() const;
    Result<std::vector<security::AccountRecord>> ListAccounts(
        const security::AccountRecord& actor) const;
    Result<security::AccountRecord> CreateAccount(const security::AccountRecord& actor,
        std::string username, std::string password, security::PortalRole role);
    Result<security::AccountRecord> UpdateAccount(const security::AccountRecord& actor,
        std::string_view accountId, const security::AccountUpdateRequest& update);
    Result<AccountDeletionResult> DeleteAccount(const security::AccountRecord& actor,
        std::string_view accountId, bool revokeTokens);
    Result<security::AccountRecord> SetCollaborationBinding(
        const security::AccountRecord& actor, std::string_view accountId,
        std::string collaborationUsername, std::string accessToken);
    Result<security::TokenIssueResult> IssueToken(
        const security::AccountRecord& actor, const TokenRequest& request);
    Result<std::vector<security::TokenRecord>> ListTokens(
        const security::AccountRecord& actor) const;
    Result<bool> RevokeToken(
        const security::AccountRecord& actor, std::string_view tokenId);

  private:
    std::optional<security::AccountRecord> Account(std::string_view accountId) const;
    bool CanManage(const security::AccountRecord& actor, std::string_view accountId) const;

    Config config_;
    security::AccountRegistry& accounts_;
    security::TokenRegistry& tokens_;
    security::BootstrapCredential& bootstrap_;
    UnixNow unixNow_;
    TokenRevoked tokenRevoked_;
};
}
