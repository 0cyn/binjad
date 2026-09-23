#include "binjad/security/account_registry.hpp"

#include "binjad/security/random.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <initializer_list>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::security
{
namespace
{
constexpr std::string_view kInitialRegistry = "{\n  \"version\": 1,\n  \"accounts\": {}\n}\n";
constexpr std::string_view kIntegrityCredential = "accounts-integrity";

using rapidjson::Document;
using rapidjson::Value;

bool IsLowerHex256(std::string_view value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
    });
}

bool ValidUsername(std::string_view username)
{
    return !username.empty() && username.size() <= 64 &&
        std::all_of(username.begin(), username.end(), [](char character) {
            return (character >= 'A' && character <= 'Z') ||
                (character >= 'a' && character <= 'z') ||
                (character >= '0' && character <= '9') ||
                character == '.' || character == '_' || character == '-';
        });
}

bool HasOnlyMembers(const Value& object, std::initializer_list<std::string_view> allowed,
    std::string_view path, std::string& error)
{
    std::unordered_set<std::string_view> seen;
    for (const auto& member : object.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (std::find(allowed.begin(), allowed.end(), name) == allowed.end())
        {
            error = std::string(path) + " contains unknown field '" + std::string(name) + "'";
            return false;
        }
        if (!seen.insert(name).second)
        {
            error = std::string(path) + " contains duplicate field '" + std::string(name) + "'";
            return false;
        }
    }
    return true;
}

bool RequiredString(const Value& object, const char* name, std::string_view path,
    std::string& output, std::string& error)
{
    const auto member = object.FindMember(name);
    if (member == object.MemberEnd() || !member->value.IsString())
    {
        error = std::string(path) + '.' + name + " must be a string";
        return false;
    }
    output.assign(member->value.GetString(), member->value.GetStringLength());
    return true;
}

bool RequiredUnsigned(const Value& object, const char* name, std::string_view path,
    std::uint64_t& output, std::string& error)
{
    const auto member = object.FindMember(name);
    if (member == object.MemberEnd() || !member->value.IsUint64())
    {
        error = std::string(path) + '.' + name + " must be an unsigned integer";
        return false;
    }
    output = member->value.GetUint64();
    return true;
}

std::optional<PortalRole> ParseRole(std::string_view role)
{
    if (role == "portal-admin")
        return PortalRole::Admin;
    if (role == "self-service")
        return PortalRole::SelfService;
    return std::nullopt;
}

std::string_view RoleName(PortalRole role)
{
    return role == PortalRole::Admin ? "portal-admin" : "self-service";
}

std::string PasswordCredential(std::string_view accountId)
{
    return "account-password-" + std::string(accountId);
}

std::string CollaborationCredential(std::string_view accountId)
{
    return "account-collaboration-" + std::string(accountId);
}

bool ParseRecord(std::string id, const Value& value, std::string_view path,
    AccountRecord& record, std::string& error)
{
    if (!value.IsObject())
    {
        error = std::string(path) + " must be an object";
        return false;
    }
    if (!HasOnlyMembers(value,
        {"username", "role", "created_at", "collaboration_username", "deleted_at"},
        path, error))
        return false;
    record.id = std::move(id);
    if (!RequiredString(value, "username", path, record.username, error) ||
        !ValidUsername(record.username))
    {
        if (error.empty())
            error = std::string(path) +
                ".username must be 1 through 64 ASCII letters, digits, '.', '_', or '-'";
        return false;
    }
    std::string role;
    if (!RequiredString(value, "role", path, role, error))
        return false;
    const auto parsedRole = ParseRole(role);
    if (!parsedRole)
    {
        error = std::string(path) + ".role must be 'portal-admin' or 'self-service'";
        return false;
    }
    record.role = *parsedRole;
    if (!RequiredUnsigned(value, "created_at", path, record.createdAt, error))
        return false;
    std::uint64_t deletedAt = 0;
    if (!RequiredUnsigned(value, "deleted_at", path, deletedAt, error))
        return false;
    if (deletedAt != 0)
    {
        if (deletedAt < record.createdAt)
        {
            error = std::string(path) + ".deleted_at must be zero or not precede created_at";
            return false;
        }
        record.deletedAt = deletedAt;
    }
    if (const auto collaboration = value.FindMember("collaboration_username");
        collaboration != value.MemberEnd())
    {
        if (!collaboration->value.IsString() || collaboration->value.GetStringLength() == 0)
        {
            error = std::string(path) + ".collaboration_username must be a non-empty string";
            return false;
        }
        record.collaborationUsername.emplace(
            collaboration->value.GetString(), collaboration->value.GetStringLength());
    }
    return true;
}
}

AccountRegistryParseResult ParseAccountRegistry(std::string_view json)
{
    Document document;
    try
    {
        document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
    }
    catch (const ParseException& exception)
    {
        return {{}, std::string("invalid account registry JSON at byte ") +
            std::to_string(exception.Offset()) + ": " +
            rapidjson::GetParseError_En(exception.Code())};
    }
    if (document.HasParseError())
    {
        return {{}, std::string("invalid account registry JSON at byte ") +
            std::to_string(document.GetErrorOffset()) + ": " +
            rapidjson::GetParseError_En(document.GetParseError())};
    }
    if (!document.IsObject())
        return {{}, "account registry root must be an object"};
    std::string error;
    if (!HasOnlyMembers(document, {"version", "accounts"}, "$", error))
        return {{}, std::move(error)};
    const auto version = document.FindMember("version");
    if (version == document.MemberEnd() || !version->value.IsUint() || version->value.GetUint() != 1)
        return {{}, "$.version must be the supported version 1"};
    const auto accounts = document.FindMember("accounts");
    if (accounts == document.MemberEnd() || !accounts->value.IsObject())
        return {{}, "$.accounts must be an object"};

    AccountRecords records;
    std::unordered_set<std::string> activeUsernames;
    for (const auto& member : accounts->value.GetObject())
    {
        std::string id(member.name.GetString(), member.name.GetStringLength());
        if (!IsLowerHex256(id))
            return {{}, "$.accounts keys must be 64 lowercase hexadecimal account IDs"};
        if (records.contains(id))
            return {{}, "account registry contains a duplicate account ID"};
        AccountRecord record;
        const auto path = "$.accounts." + id;
        if (!ParseRecord(id, member.value, path, record, error))
            return {{}, std::move(error)};
        if (!record.deletedAt && !activeUsernames.insert(record.username).second)
            return {{}, "account registry contains duplicate active username '" + record.username + "'"};
        records.emplace(std::move(id), std::move(record));
    }
    return {std::move(records), {}};
}

std::string SerializeAccountRegistry(const AccountRecords& records)
{
    std::vector<std::string_view> ids;
    ids.reserve(records.size());
    for (const auto& [id, record] : records)
        ids.push_back(id);
    std::sort(ids.begin(), ids.end());

    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
    writer.SetIndent(' ', 2);
    writer.StartObject();
    writer.Key("version");
    writer.Uint(1);
    writer.Key("accounts");
    writer.StartObject();
    for (const auto id : ids)
    {
        const auto& record = records.at(std::string(id));
        writer.Key(id.data(), static_cast<rapidjson::SizeType>(id.size()));
        writer.StartObject();
        writer.Key("username");
        writer.String(record.username.data(), static_cast<rapidjson::SizeType>(record.username.size()));
        writer.Key("role");
        const auto role = RoleName(record.role);
        writer.String(role.data(), static_cast<rapidjson::SizeType>(role.size()));
        writer.Key("created_at");
        writer.Uint64(record.createdAt);
        if (record.collaborationUsername)
        {
            writer.Key("collaboration_username");
            writer.String(record.collaborationUsername->data(),
                static_cast<rapidjson::SizeType>(record.collaborationUsername->size()));
        }
        writer.Key("deleted_at");
        writer.Uint64(record.deletedAt.value_or(0));
        writer.EndObject();
    }
    writer.EndObject();
    writer.EndObject();
    std::string output(buffer.GetString(), buffer.GetSize());
    output.push_back('\n');
    return output;
}

AccountRegistry::AccountRegistry(CredentialStore& credentials, std::filesystem::path path,
    Argon2Profile passwordProfile)
    : credentials_(credentials), file_(credentials, std::move(path), std::string(kIntegrityCredential)),
      passwordProfile_(passwordProfile)
{
}

std::string AccountRegistry::Load()
{
    std::lock_guard lock(mutex_);
    if (loaded_)
        return "account registry is already loaded";
    const auto loaded = file_.LoadOrCreate(kInitialRegistry, [](std::string_view contents) {
        const auto parsed = ParseAccountRegistry(contents);
        return parsed.records && parsed.records->empty();
    });
    if (!loaded.contents)
        return loaded.error;
    auto parsed = ParseAccountRegistry(*loaded.contents);
    if (!parsed.records)
        return parsed.error;
    records_ = std::move(*parsed.records);
    for (const auto& [id, record] : records_)
    {
        if (!record.deletedAt)
            continue;
        if (const auto error = credentials_.Remove(PasswordCredential(id)); !error.empty())
            return "cannot remove tombstoned account password: " + error;
        if (const auto error = credentials_.Remove(CollaborationCredential(id)); !error.empty())
            return "cannot remove tombstoned collaboration credential: " + error;
    }
    loaded_ = true;
    return {};
}

bool AccountRegistry::IsLoaded() const
{
    std::lock_guard lock(mutex_);
    return loaded_;
}

AccountRecords AccountRegistry::Records() const
{
    std::lock_guard lock(mutex_);
    return records_;
}

std::optional<AccountRecord> AccountRegistry::FindActive(std::string_view username) const
{
    std::lock_guard lock(mutex_);
    const auto account = std::find_if(records_.begin(), records_.end(), [&](const auto& entry) {
        return !entry.second.deletedAt && entry.second.username == username;
    });
    return account == records_.end() ? std::nullopt : std::optional(account->second);
}

AccountCreateResult AccountRegistry::Create(const AccountCreateRequest& request)
{
    std::lock_guard lock(mutex_);
    if (!loaded_)
        return {{}, "account registry is not loaded"};
    if (!ValidUsername(request.username))
        return {{}, "username must be 1 through 64 ASCII letters, digits, '.', '_', or '-'"};
    if (!IsValidPortalPassword(request.password))
        return {{}, "password must be valid UTF-8 from 9 through 1024 bytes"};
    if (std::any_of(records_.begin(), records_.end(), [&](const auto& entry) {
        return !entry.second.deletedAt && entry.second.username == request.username;
    }))
        return {{}, "an active account already uses that username"};

    const auto password = HashPassword(request.password, passwordProfile_);
    if (!password.encoded)
        return {{}, "cannot hash account password: " + password.error};
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        auto id = GenerateHex256();
        if (!id.value)
            return {{}, "cannot generate account ID: " + id.error};
        if (records_.contains(*id.value))
            continue;
        const auto credential = PasswordCredential(*id.value);
        if (const auto error = credentials_.Write(credential, *password.encoded); !error.empty())
            return {{}, "cannot store account password: " + error};

        AccountRecord record{*id.value, request.username, request.role, request.createdAt, {}, {}};
        auto updated = records_;
        updated.emplace(record.id, record);
        if (const auto error = file_.Replace(SerializeAccountRegistry(updated)); !error.empty())
        {
            credentials_.Remove(credential);
            return {{}, "cannot persist account registry: " + error};
        }
        records_ = std::move(updated);
        return {std::move(record), {}};
    }
    return {{}, "cannot generate a unique account ID"};
}

AccountAuthenticationResult AccountRegistry::Authenticate(
    std::string_view username, std::string_view password) const
{
    std::optional<AccountRecord> account;
    {
        std::lock_guard lock(mutex_);
        if (!loaded_)
            return {PasswordVerification::Error, {}, "account registry is not loaded"};
        const auto found = std::find_if(records_.begin(), records_.end(), [&](const auto& entry) {
            return !entry.second.deletedAt && entry.second.username == username;
        });
        if (found == records_.end())
            return {};
        account = found->second;
    }
    const auto credential = credentials_.Read(PasswordCredential(account->id));
    if (!credential.error.empty())
        return {PasswordVerification::Error, {}, "cannot read account password: " + credential.error};
    if (!credential.value)
        return {PasswordVerification::Error, {}, "account password is missing"};
    auto verification = VerifyPassword(password, *credential.value);
    return {verification.result,
        verification.result == PasswordVerification::Match ? account : std::nullopt,
        std::move(verification.error)};
}

AccountUpdateResult AccountRegistry::Update(
    std::string_view accountId, const AccountUpdateRequest& request)
{
    std::lock_guard lock(mutex_);
    if (!loaded_)
        return {{}, "account registry is not loaded"};
    const auto existing = records_.find(std::string(accountId));
    if (existing == records_.end() || existing->second.deletedAt)
        return {{}, "active account not found"};
    if (!request.role && !request.password)
        return {{}, "account update must change role or password"};
    if (request.role && existing->second.role == PortalRole::Admin &&
        *request.role != PortalRole::Admin && ActiveAdministratorCount() == 1)
        return {{}, "cannot demote the last active portal administrator"};
    if (request.password && !IsValidPortalPassword(*request.password))
        return {{}, "password must be valid UTF-8 from 9 through 1024 bytes"};

    std::optional<std::string> encodedPassword;
    std::optional<std::string> previousPassword;
    const auto credentialName = PasswordCredential(accountId);
    if (request.password)
    {
        const auto hashed = HashPassword(*request.password, passwordProfile_);
        if (!hashed.encoded)
            return {{}, "cannot hash account password: " + hashed.error};
        encodedPassword = std::move(*hashed.encoded);
        const auto previous = credentials_.Read(credentialName);
        if (!previous.error.empty())
            return {{}, "cannot read existing account password: " + previous.error};
        if (!previous.value)
            return {{}, "existing account password is missing"};
        previousPassword = std::move(*previous.value);
        if (const auto error = credentials_.Write(credentialName, *encodedPassword); !error.empty())
            return {{}, "cannot store updated account password: " + error};
    }

    auto updated = records_;
    if (request.role)
        updated.at(std::string(accountId)).role = *request.role;
    if (request.role)
    {
        if (const auto error = file_.Replace(SerializeAccountRegistry(updated)); !error.empty())
        {
            if (previousPassword)
                credentials_.Write(credentialName, *previousPassword);
            return {{}, "cannot persist account update: " + error};
        }
        records_ = std::move(updated);
    }
    return {records_.at(std::string(accountId)), {}};
}

std::string AccountRegistry::SetCollaborationBinding(std::string_view accountId,
    std::string collaborationUsername, std::string_view accessToken)
{
    std::lock_guard lock(mutex_);
    if (!loaded_)
        return "account registry is not loaded";
    const auto existing = records_.find(std::string(accountId));
    if (existing == records_.end() || existing->second.deletedAt)
        return "active account not found";
    if (collaborationUsername.empty())
        return "collaboration username must not be empty";
    if (accessToken.empty())
        return "collaboration access token must not be empty";

    const auto credentialName = CollaborationCredential(accountId);
    const auto previousCredential = credentials_.Read(credentialName);
    if (!previousCredential.error.empty())
        return "cannot read existing collaboration credential: " + previousCredential.error;
    if (const auto error = credentials_.Write(credentialName, accessToken); !error.empty())
        return "cannot store collaboration credential: " + error;

    auto updated = records_;
    updated.at(std::string(accountId)).collaborationUsername = std::move(collaborationUsername);
    if (const auto error = file_.Replace(SerializeAccountRegistry(updated)); !error.empty())
    {
        if (previousCredential.value)
            credentials_.Write(credentialName, *previousCredential.value);
        else
            credentials_.Remove(credentialName);
        return "cannot persist collaboration binding: " + error;
    }
    records_ = std::move(updated);
    return {};
}

CredentialReadResult AccountRegistry::CollaborationAccessToken(std::string_view accountId) const
{
    {
        std::lock_guard lock(mutex_);
        const auto account = records_.find(std::string(accountId));
        if (!loaded_ || account == records_.end() || account->second.deletedAt ||
            !account->second.collaborationUsername)
            return {};
    }
    return credentials_.Read(CollaborationCredential(accountId));
}

std::string AccountRegistry::Delete(
    std::string_view accountId, std::uint64_t deletedAt, bool& deleted)
{
    std::lock_guard lock(mutex_);
    deleted = false;
    if (!loaded_)
        return "account registry is not loaded";
    const auto existing = records_.find(std::string(accountId));
    if (existing == records_.end())
        return {};
    if (!existing->second.deletedAt)
    {
        if (existing->second.role == PortalRole::Admin && ActiveAdministratorCount() == 1)
            return "cannot delete the last active portal administrator";
        if (deletedAt < existing->second.createdAt)
            return "account deletion time must not precede creation time";
        auto updated = records_;
        updated.at(std::string(accountId)).deletedAt = deletedAt;
        if (const auto error = file_.Replace(SerializeAccountRegistry(updated)); !error.empty())
            return "cannot persist account tombstone: " + error;
        records_ = std::move(updated);
        deleted = true;
    }
    if (const auto error = credentials_.Remove(PasswordCredential(accountId)); !error.empty())
        return "account was tombstoned but its password could not be removed: " + error;
    if (const auto error = credentials_.Remove(CollaborationCredential(accountId)); !error.empty())
        return "account was tombstoned but its collaboration credential could not be removed: " + error;
    return {};
}

std::size_t AccountRegistry::ActiveAdministratorCount() const
{
    return static_cast<std::size_t>(std::count_if(records_.begin(), records_.end(),
        [](const auto& entry) {
            return !entry.second.deletedAt && entry.second.role == PortalRole::Admin;
        }));
}
}
