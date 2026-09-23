#include "binjad/security/token_authenticator.hpp"

#include "binjad/security/crypto.hpp"

#include <algorithm>
#include <mutex>
#include <stdexcept>

namespace binjad::security
{
TokenAuthenticator::TokenAuthenticator(std::string hmacKey, Records records)
    : hmacKey_(std::move(hmacKey)), records_(std::move(records))
{
    if (hmacKey_.empty())
        throw std::invalid_argument("token HMAC key must not be empty");
}

std::optional<TokenRecord> TokenAuthenticator::Authenticate(
    std::string_view bearerToken, std::uint64_t now) const
{
    if (!IsTokenSyntax(bearerToken))
        return std::nullopt;
    const auto verifier = HmacSha256Hex(hmacKey_, bearerToken);
    std::shared_lock lock(mutex_);
    const auto record = records_.find(verifier);
    if (record == records_.end())
        return std::nullopt;
    if (record->second.expiresAt && now >= *record->second.expiresAt)
        return std::nullopt;
    return record->second;
}

void TokenAuthenticator::ReplaceRecords(Records records)
{
    std::unique_lock lock(mutex_);
    records_ = std::move(records);
}

bool TokenAuthenticator::IsTokenSyntax(std::string_view bearerToken)
{
    return bearerToken.size() == 64 &&
        std::all_of(bearerToken.begin(), bearerToken.end(), [](char character) {
            return (character >= '0' && character <= '9') ||
                (character >= 'a' && character <= 'f');
        });
}
}
