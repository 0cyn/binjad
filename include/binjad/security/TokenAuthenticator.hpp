#pragma once

#include <cstdint>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binjad::security
{
enum class TokenRole
{
    Admin,
    User,
};

struct TokenRecord
{
    std::string id;
    std::string issuerAccountId;
    TokenRole role = TokenRole::User;
    std::string label;
    std::uint64_t createdAt = 0;
    std::optional<std::uint64_t> expiresAt;
};

class TokenAuthenticator
{
  public:
    using Records = std::unordered_map<std::string, TokenRecord>;

    TokenAuthenticator(std::string hmacKey, Records records = {});
    std::optional<TokenRecord> Authenticate(
        std::string_view bearerToken, std::uint64_t now) const;
    void ReplaceRecords(Records records);

    static bool IsTokenSyntax(std::string_view bearerToken);

  private:
    std::string hmacKey_;
    Records records_;
    mutable std::shared_mutex mutex_;
};
}
