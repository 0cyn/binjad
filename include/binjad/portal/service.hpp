#pragma once

#include "binjad/security/AccountRegistry.hpp"
#include "binjad/security/TokenRegistry.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::portal
{
template <typename T> struct Result
{
    std::optional<T> value;
    std::string error;
};

struct TokenRequest
{
    std::uint64_t ttlSeconds = 7 * 24 * 60 * 60;
};

struct TokenStatus
{
    std::optional<security::TokenRecord> token;
};

class Service
{
public:
    using UnixNow = std::function<std::uint64_t()>;
    using TokenRevoked = std::function<void(std::string_view)>;

    Service(security::AccountRegistry& accounts, security::TokenRegistry& tokens, UnixNow unixNow = {});
    void SetTokenRevokedCallback(TokenRevoked callback);

    Result<security::AccountRecord> CreateInitialAccount(std::string username, std::string password);
    Result<bool> SetupRequired() const;
    security::AccountAuthenticationResult Authenticate(std::string_view username, std::string_view password) const;
    Result<security::AccountRecord> CurrentAccount(const security::AccountRecord& actor) const;
    Result<security::AccountRecord> UpdatePassword(const security::AccountRecord& actor, std::string password);
    Result<security::TokenIssueResult> RotateToken(const security::AccountRecord& actor, const TokenRequest& request);
    Result<TokenStatus> Token(const security::AccountRecord& actor) const;
    Result<bool> RevokeToken(const security::AccountRecord& actor);

private:
    bool IsCurrent(const security::AccountRecord& actor) const;

    security::AccountRegistry& accounts_;
    security::TokenRegistry& tokens_;
    UnixNow unixNow_;
    TokenRevoked tokenRevoked_;
};
} // namespace binjad::portal
