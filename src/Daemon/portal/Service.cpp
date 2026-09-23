#include "binjad/portal/service.hpp"

#include <algorithm>
#include <chrono>
#include <limits>
#include <utility>

namespace binjad::portal
{
namespace
{
std::uint64_t CurrentUnixSeconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}
}

Service::Service(Config config, security::AccountRegistry& accounts,
    security::TokenRegistry& tokens, security::BootstrapCredential& bootstrap, UnixNow unixNow)
    : config_(std::move(config)), accounts_(accounts), tokens_(tokens), bootstrap_(bootstrap),
      unixNow_(unixNow ? std::move(unixNow) : CurrentUnixSeconds)
{
}

void Service::SetTokenRevokedCallback(TokenRevoked callback)
{
    tokenRevoked_ = std::move(callback);
}

Result<security::AccountRecord> Service::CreateBootstrapAdministrator(
    std::string_view credential, std::string username, std::string password)
{
    if (const auto error = bootstrap_.Refresh(); !error.empty())
        return {{}, error};
    const auto authorized = bootstrap_.Begin(credential);
    if (!authorized.authorized)
        return {{}, authorized.error.empty() ? "invalid bootstrap credential" : authorized.error};
    auto created = accounts_.Create({std::move(username), std::move(password),
        security::PortalRole::Admin, unixNow_()});
    if (!created.record)
    {
        const auto restoreError = bootstrap_.Complete(false);
        if (!restoreError.empty())
            created.error += "; " + restoreError;
        return {{}, std::move(created.error)};
    }
    if (const auto error = bootstrap_.Complete(true); !error.empty())
        return {created.record, error};
    return {std::move(created.record), {}};
}

Result<bool> Service::BootstrapAvailable()
{
    if (const auto error = bootstrap_.Refresh(); !error.empty())
        return {{}, error};
    return {bootstrap_.Available(), {}};
}

security::AccountAuthenticationResult Service::Authenticate(
    std::string_view username, std::string_view password) const
{
    return accounts_.Authenticate(username, password);
}

Result<security::AccountRecord> Service::AuthenticateAdminBearer(
    std::string_view token) const
{
    const auto principal = tokens_.Authenticator().Authenticate(token, unixNow_());
    if (!principal || principal->role != security::TokenRole::Admin)
        return {{}, "admin bearer token required"};
    const auto account = Account(principal->issuerAccountId);
    if (!account || account->deletedAt)
        return {{}, "issuing portal account is unavailable"};
    return {*account, {}};
}

Result<security::AccountRecord> Service::UnauthenticatedAdministrator() const
{
    for (const auto& [id, account] : accounts_.Records())
    {
        (void)id;
        if (!account.deletedAt && account.role == security::PortalRole::Admin)
            return {account, {}};
    }
    return {{}, "no active portal administrator exists"};
}

Result<std::vector<security::AccountRecord>> Service::ListAccounts(
    const security::AccountRecord& actor) const
{
    if (actor.deletedAt)
        return {{}, "account is deleted"};
    std::vector<security::AccountRecord> result;
    if (actor.role == security::PortalRole::Admin)
    {
        for (const auto& [id, account] : accounts_.Records())
            result.push_back(account);
    }
    else if (const auto account = Account(actor.id); account && !account->deletedAt)
    {
        result.push_back(*account);
    }
    return {std::move(result), {}};
}

Result<security::AccountRecord> Service::CreateAccount(const security::AccountRecord& actor,
    std::string username, std::string password, security::PortalRole role)
{
    if (actor.deletedAt || actor.role != security::PortalRole::Admin)
        return {{}, "portal administrator required"};
    if (config_.EffectiveMode() == Mode::Local && role == security::PortalRole::SelfService)
        return {{}, "self-service accounts are disabled in local mode"};
    auto created = accounts_.Create(
        {std::move(username), std::move(password), role, unixNow_()});
    return {std::move(created.record), std::move(created.error)};
}

Result<security::AccountRecord> Service::UpdateAccount(const security::AccountRecord& actor,
    std::string_view accountId, const security::AccountUpdateRequest& update)
{
    if (!CanManage(actor, accountId))
        return {{}, "account not found"};
    if (actor.role != security::PortalRole::Admin && update.role)
        return {{}, "portal administrator required to change roles"};
    auto updated = accounts_.Update(accountId, update);
    return {std::move(updated.record), std::move(updated.error)};
}

Result<AccountDeletionResult> Service::DeleteAccount(const security::AccountRecord& actor,
    std::string_view accountId, bool revokeTokens)
{
    if (actor.deletedAt || actor.role != security::PortalRole::Admin)
        return {{}, "portal administrator required"};
    if (!Account(accountId))
        return {AccountDeletionResult{}, {}};
    bool deleted = false;
    if (const auto error = accounts_.Delete(accountId, unixNow_(), deleted); !error.empty())
        return {{}, error};
    std::size_t revoked = 0;
    if (revokeTokens)
    {
        const auto issuedTokens = tokens_.RecordsForIssuer(accountId);
        if (const auto error = tokens_.RevokeByIssuer(accountId, revoked); !error.empty())
            return {AccountDeletionResult{deleted, 0}, error};
        if (tokenRevoked_)
        {
            for (const auto& token : issuedTokens)
                tokenRevoked_(token.id);
        }
    }
    return {AccountDeletionResult{deleted, revoked}, {}};
}

Result<security::AccountRecord> Service::SetCollaborationBinding(
    const security::AccountRecord& actor, std::string_view accountId,
    std::string collaborationUsername, std::string accessToken)
{
    if (config_.EffectiveMode() != Mode::Collaboration)
        return {{}, "collaboration bindings are disabled in local mode"};
    if (!CanManage(actor, accountId))
        return {{}, "account not found"};
    if (const auto error = accounts_.SetCollaborationBinding(accountId,
        std::move(collaborationUsername), accessToken); !error.empty())
        return {{}, error};
    const auto updated = Account(accountId);
    return updated ? Result<security::AccountRecord>{*updated, {}}
                   : Result<security::AccountRecord>{{}, "account not found"};
}

Result<security::TokenIssueResult> Service::IssueToken(
    const security::AccountRecord& actor, const TokenRequest& request)
{
    if (actor.deletedAt)
        return {{}, "account is deleted"};
    if (request.label && request.label->empty())
        return {{}, "token label must not be empty when present"};

    security::TokenRole role = security::TokenRole::User;
    if (config_.EffectiveMode() == Mode::Local)
    {
        role = security::TokenRole::Admin;
    }
    else if (request.role)
    {
        if (*request.role == security::TokenRole::Admin &&
            actor.role != security::PortalRole::Admin)
            return {{}, "portal administrator required to issue an admin token"};
        role = *request.role;
    }

    const auto ttl = request.ttlSeconds.value_or(
        static_cast<std::uint64_t>(config_.authentication.defaultTokenTtl.count()));
    std::optional<std::uint64_t> expiresAt;
    const auto now = unixNow_();
    if (ttl == 0)
    {
        if (!config_.authentication.allowInfiniteTokens)
            return {{}, "infinite bearer tokens are disabled"};
    }
    else
    {
        if (ttl > std::numeric_limits<std::uint64_t>::max() - now)
            return {{}, "token expiry overflows Unix time"};
        expiresAt = now + ttl;
    }
    auto issued = tokens_.Issue({actor.id, role, request.label.value_or(""), now, expiresAt});
    if (!issued.token)
        return {{}, std::move(issued.error)};
    return {std::move(issued), {}};
}

Result<std::vector<security::TokenRecord>> Service::ListTokens(
    const security::AccountRecord& actor) const
{
    if (actor.deletedAt)
        return {{}, "account is deleted"};
    return {tokens_.RecordsForIssuer(actor.id), {}};
}

Result<bool> Service::RevokeToken(
    const security::AccountRecord& actor, std::string_view tokenId)
{
    if (actor.deletedAt)
        return {{}, "account is deleted"};
    const auto records = tokens_.RecordsForIssuer(actor.id);
    if (std::none_of(records.begin(), records.end(), [&](const auto& record) {
        return record.id == tokenId;
    }))
        return {false, {}};
    bool removed = false;
    if (const auto error = tokens_.Revoke(tokenId, removed); !error.empty())
        return {{}, error};
    if (removed && tokenRevoked_)
        tokenRevoked_(tokenId);
    return {removed, {}};
}

std::optional<security::AccountRecord> Service::Account(std::string_view accountId) const
{
    const auto records = accounts_.Records();
    const auto account = records.find(std::string(accountId));
    return account == records.end() ? std::nullopt : std::optional(account->second);
}

bool Service::CanManage(
    const security::AccountRecord& actor, std::string_view accountId) const
{
    if (actor.deletedAt)
        return false;
    return actor.role == security::PortalRole::Admin || actor.id == accountId;
}
}
