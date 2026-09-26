#include "binjad/security/AccountRegistry.hpp"

#include "binjad/security/Crypto.hpp"
#include "binjad/security/Random.hpp"
#include "binjad/security/TokenAuthenticator.hpp"
#include "binjad/security/TokenRegistry.hpp"
#include "PlatformRandom.hpp"

#include <argon2.h>
#include <rapidjsonwrapper.h>

#include <algorithm>
#include <initializer_list>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::security
{
namespace
{
constexpr std::string_view kInitialRegistry = "{\n  \"version\": 2,\n  \"accounts\": {}\n}\n";
constexpr std::string_view kIntegrityCredential = "accounts-integrity-v2";

using rapidjson::Document;
using rapidjson::Value;

bool IsLowerHex256(std::string_view value)
{
    return value.size() == 64
        && std::all_of(value.begin(), value.end(), [](char character)
            { return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f'); });
}

bool ValidUsername(std::string_view username)
{
    return !username.empty() && username.size() <= 64
        && std::all_of(username.begin(), username.end(),
            [](char character)
            {
                return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z')
                    || (character >= '0' && character <= '9') || character == '.' || character == '_'
                    || character == '-';
            });
}

bool HasOnlyMembers(
    const Value& object, std::initializer_list<std::string_view> allowed, std::string_view path, std::string& error)
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

bool RequiredString(
    const Value& object, const char* name, std::string_view path, std::string& output, std::string& error)
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

bool RequiredUnsigned(
    const Value& object, const char* name, std::string_view path, std::uint64_t& output, std::string& error)
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

std::string PasswordCredential(std::string_view accountId)
{
    return "account-password-v2-" + std::string(accountId);
}

bool ParseRecord(std::string id, const Value& value, std::string_view path, AccountRecord& record, std::string& error)
{
    if (!value.IsObject())
    {
        error = std::string(path) + " must be an object";
        return false;
    }
    if (!HasOnlyMembers(value, {"username", "created_at"}, path, error))
        return false;
    record.id = std::move(id);
    if (!RequiredString(value, "username", path, record.username, error) || !ValidUsername(record.username))
    {
        if (error.empty())
            error = std::string(path) + ".username must be 1 through 64 ASCII letters, digits, '.', '_', or '-'";
        return false;
    }
    if (!RequiredUnsigned(value, "created_at", path, record.createdAt, error))
        return false;
    return true;
}
} // namespace

AccountRegistryParseResult ParseAccountRegistry(std::string_view json)
{
    Document document;
    try
    {
        document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
    }
    catch (const ParseException& exception)
    {
        return {{},
            std::string("invalid account registry JSON at byte ") + std::to_string(exception.Offset()) + ": "
                + rapidjson::GetParseError_En(exception.Code())};
    }
    if (document.HasParseError())
    {
        return {{},
            std::string("invalid account registry JSON at byte ") + std::to_string(document.GetErrorOffset()) + ": "
                + rapidjson::GetParseError_En(document.GetParseError())};
    }
    if (!document.IsObject())
        return {{}, "account registry root must be an object"};
    std::string error;
    if (!HasOnlyMembers(document, {"version", "accounts"}, "$", error))
        return {{}, std::move(error)};
    const auto version = document.FindMember("version");
    if (version == document.MemberEnd() || !version->value.IsUint() || version->value.GetUint() != 2)
        return {{}, "$.version must be the supported version 2; reset the old authentication state"};
    const auto accounts = document.FindMember("accounts");
    if (accounts == document.MemberEnd() || !accounts->value.IsObject())
        return {{}, "$.accounts must be an object"};

    AccountRecords records;
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
        records.emplace(std::move(id), std::move(record));
    }
    if (records.size() > 1)
        return {{}, "account registry must contain at most one account"};
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
    writer.Uint(2);
    writer.Key("accounts");
    writer.StartObject();
    for (const auto id : ids)
    {
        const auto& record = records.at(std::string(id));
        writer.Key(id.data(), static_cast<rapidjson::SizeType>(id.size()));
        writer.StartObject();
        writer.Key("username");
        writer.String(record.username.data(), static_cast<rapidjson::SizeType>(record.username.size()));
        writer.Key("created_at");
        writer.Uint64(record.createdAt);
        writer.EndObject();
    }
    writer.EndObject();
    writer.EndObject();
    std::string output(buffer.GetString(), buffer.GetSize());
    output.push_back('\n');
    return output;
}

AccountRegistry::AccountRegistry(
    CredentialStore& credentials, std::filesystem::path path, Argon2Profile passwordProfile)
    : credentials_(credentials), file_(credentials, std::move(path), std::string(kIntegrityCredential)),
      passwordProfile_(passwordProfile)
{
}

std::string AccountRegistry::Load()
{
    std::lock_guard lock(mutex_);
    if (loaded_)
        return "account registry is already loaded";
    const auto loaded = file_.LoadOrCreate(kInitialRegistry,
        [](std::string_view contents)
        {
            const auto parsed = ParseAccountRegistry(contents);
            return parsed.records && parsed.records->empty();
        });
    if (!loaded.contents)
        return loaded.error == "existing private file has no integrity anchor"
            ? "existing account registry is incompatible; remove the account and token registry files to reset "
              "authentication"
            : loaded.error;
    auto parsed = ParseAccountRegistry(*loaded.contents);
    if (!parsed.records)
        return parsed.error;
    records_ = std::move(*parsed.records);
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
    const auto account = std::find_if(
        records_.begin(), records_.end(), [&](const auto& entry) { return entry.second.username == username; });
    return account == records_.end() ? std::nullopt : std::optional(account->second);
}

std::optional<AccountRecord> AccountRegistry::Account() const
{
    std::lock_guard lock(mutex_);
    return records_.empty() ? std::nullopt : std::optional(records_.begin()->second);
}

AccountCreateResult AccountRegistry::CreateInitial(const AccountCreateRequest& request)
{
    std::lock_guard lock(mutex_);
    if (!loaded_)
        return {{}, "account registry is not loaded"};
    if (!records_.empty())
        return {{}, "account is already configured"};
    if (!ValidUsername(request.username))
        return {{}, "username must be 1 through 64 ASCII letters, digits, '.', '_', or '-'"};
    if (!IsValidPortalPassword(request.password))
        return {{}, "password must be valid UTF-8 from 9 through 1024 bytes"};
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

        AccountRecord record{*id.value, request.username, request.createdAt};
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

AccountAuthenticationResult AccountRegistry::Authenticate(std::string_view username, std::string_view password) const
{
    std::optional<AccountRecord> account;
    {
        std::lock_guard lock(mutex_);
        if (!loaded_)
            return {PasswordVerification::Error, {}, "account registry is not loaded"};
        const auto found = std::find_if(
            records_.begin(), records_.end(), [&](const auto& entry) { return entry.second.username == username; });
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
    return {verification.result, verification.result == PasswordVerification::Match ? account : std::nullopt,
        std::move(verification.error)};
}

AccountUpdateResult AccountRegistry::UpdatePassword(std::string_view accountId, std::string password)
{
    std::lock_guard lock(mutex_);
    if (!loaded_)
        return {{}, "account registry is not loaded"};
    const auto existing = records_.find(std::string(accountId));
    if (existing == records_.end())
        return {{}, "account not found"};
    if (!IsValidPortalPassword(password))
        return {{}, "password must be valid UTF-8 from 9 through 1024 bytes"};

    const auto credentialName = PasswordCredential(accountId);
    const auto hashed = HashPassword(password, passwordProfile_);
    if (!hashed.encoded)
        return {{}, "cannot hash account password: " + hashed.error};
    if (const auto error = credentials_.Write(credentialName, *hashed.encoded); !error.empty())
        return {{}, "cannot store updated account password: " + error};
    return {records_.at(std::string(accountId)), {}};
}

namespace
{
std::string ArgonError(int code)
{
    const char* message = argon2_error_message(code);
    return message ? message : "unknown Argon2 error";
}

bool FitsArgonLength(std::size_t size)
{
    return size <= std::numeric_limits<std::uint32_t>::max();
}

bool ValidUtf8(std::string_view value)
{
    for (std::size_t offset = 0; offset < value.size();)
    {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::uint32_t codepoint = 0;
        std::size_t length = 1;
        if (first <= 0x7f)
            codepoint = first;
        else if (first >= 0xc2 && first <= 0xdf)
        {
            codepoint = first & 0x1f;
            length = 2;
        }
        else if (first >= 0xe0 && first <= 0xef)
        {
            codepoint = first & 0x0f;
            length = 3;
        }
        else if (first >= 0xf0 && first <= 0xf4)
        {
            codepoint = first & 0x07;
            length = 4;
        }
        else
            return false;
        if (offset + length > value.size())
            return false;
        for (std::size_t index = 1; index < length; ++index)
        {
            const auto continuation = static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xc0) != 0x80)
                return false;
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((length == 3 && codepoint < 0x800) || (length == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return false;
        offset += length;
    }
    return true;
}
} // namespace

PasswordHashResult HashPassword(std::string_view password, const Argon2Profile& profile)
{
    if (!FitsArgonLength(password.size()))
        return {{}, "password is too large for Argon2"};
    if (profile.saltBytes < ARGON2_MIN_SALT_LENGTH || profile.outputBytes < ARGON2_MIN_OUTLEN ||
        profile.memoryKib < ARGON2_MIN_MEMORY || profile.iterations < ARGON2_MIN_TIME ||
        profile.lanes < ARGON2_MIN_LANES)
        return {{}, "Argon2 profile is outside the supported minimums"};

    std::vector<unsigned char> salt(profile.saltBytes);
    if (const auto error = FillSecureRandom(salt); !error.empty())
        return {{}, "cannot generate password salt: " + error};
    const auto encodedLength = argon2_encodedlen(profile.iterations, profile.memoryKib,
        profile.lanes, profile.saltBytes, profile.outputBytes, Argon2_id);
    if (encodedLength == 0)
        return {{}, "cannot determine Argon2 encoded length"};
    std::string encoded(encodedLength, '\0');
    const auto status = argon2id_hash_encoded(profile.iterations, profile.memoryKib,
        profile.lanes, password.data(), password.size(), salt.data(), salt.size(),
        profile.outputBytes, encoded.data(), encoded.size());
    if (status != ARGON2_OK)
        return {{}, ArgonError(status)};
    encoded.resize(std::char_traits<char>::length(encoded.c_str()));
    return {std::move(encoded), {}};
}

PasswordVerifyResult VerifyPassword(std::string_view password, std::string_view encoded)
{
    if (!FitsArgonLength(password.size()) || encoded.find('\0') != std::string_view::npos)
        return {PasswordVerification::Error, "password verifier input is malformed"};
    const std::string terminated(encoded);
    const auto status = argon2id_verify(terminated.c_str(), password.data(), password.size());
    if (status == ARGON2_OK)
        return {PasswordVerification::Match, {}};
    if (status == ARGON2_VERIFY_MISMATCH)
        return {PasswordVerification::Mismatch, {}};
    return {PasswordVerification::Error, ArgonError(status)};
}

bool IsValidPortalPassword(std::string_view password)
{
    return password.size() >= 9 && password.size() <= 1024 && ValidUtf8(password);
}

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

namespace
{
constexpr std::string_view kInitialTokenRegistry = "{\n  \"version\": 2,\n  \"tokens\": {}\n}\n";
constexpr std::string_view kTokenIntegrityCredential = "tokens-integrity-v2";
constexpr std::string_view kHmacCredential = "tokens-hmac-key-v2";

bool ValidLabel(std::string_view label)
{
    if (label.empty() || label.size() > 256)
        return false;
    for (std::size_t offset = 0; offset < label.size();)
    {
        const auto first = static_cast<unsigned char>(label[offset]);
        std::uint32_t codepoint = 0;
        std::size_t length = 1;
        if (first <= 0x7f)
        {
            codepoint = first;
        }
        else if (first >= 0xc2 && first <= 0xdf)
        {
            codepoint = first & 0x1f;
            length = 2;
        }
        else if (first >= 0xe0 && first <= 0xef)
        {
            codepoint = first & 0x0f;
            length = 3;
        }
        else if (first >= 0xf0 && first <= 0xf4)
        {
            codepoint = first & 0x07;
            length = 4;
        }
        else
        {
            return false;
        }
        if (offset + length > label.size())
            return false;
        for (std::size_t index = 1; index < length; ++index)
        {
            const auto continuation = static_cast<unsigned char>(label[offset + index]);
            if ((continuation & 0xc0) != 0x80)
                return false;
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((length == 3 && codepoint < 0x800) || (length == 4 && codepoint < 0x10000)
            || (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return false;
        if (codepoint <= 0x1f || (codepoint >= 0x7f && codepoint <= 0x9f))
            return false;
        offset += length;
    }
    return true;
}

std::optional<TokenRole> ParseRole(std::string_view role)
{
    if (role == "admin")
        return TokenRole::Admin;
    if (role == "user")
        return TokenRole::User;
    return std::nullopt;
}

std::string_view RoleName(TokenRole role)
{
    return role == TokenRole::Admin ? "admin" : "user";
}

bool ParseTokenRecord(const Value& value, std::string_view path, TokenRecord& record, std::string& error)
{
    if (!value.IsObject())
    {
        error = std::string(path) + " must be an object";
        return false;
    }
    if (!HasOnlyMembers(value, {"id", "issuer_account_id", "role", "label", "created_at", "expires_at"}, path, error))
        return false;
    if (!RequiredString(value, "id", path, record.id, error) || !IsLowerHex256(record.id))
    {
        if (error.empty())
            error = std::string(path) + ".id must be 64 lowercase hexadecimal characters";
        return false;
    }
    if (!RequiredString(value, "issuer_account_id", path, record.issuerAccountId, error)
        || !IsLowerHex256(record.issuerAccountId))
    {
        if (error.empty())
            error = std::string(path) + ".issuer_account_id must be 64 lowercase hexadecimal characters";
        return false;
    }
    std::string role;
    if (!RequiredString(value, "role", path, role, error))
        return false;
    const auto parsedRole = ParseRole(role);
    if (!parsedRole)
    {
        error = std::string(path) + ".role must be 'admin' or 'user'";
        return false;
    }
    record.role = *parsedRole;
    if (const auto label = value.FindMember("label"); label != value.MemberEnd())
    {
        if (!label->value.IsString())
        {
            error = std::string(path) + ".label must be a string";
            return false;
        }
        record.label.assign(label->value.GetString(), label->value.GetStringLength());
        if (!ValidLabel(record.label))
        {
            error = std::string(path) + ".label must be control-free UTF-8 from 1 through 256 bytes";
            return false;
        }
    }
    std::uint64_t expiresAt = 0;
    if (!RequiredUnsigned(value, "created_at", path, record.createdAt, error)
        || !RequiredUnsigned(value, "expires_at", path, expiresAt, error))
        return false;
    if (expiresAt != 0)
    {
        if (expiresAt <= record.createdAt)
        {
            error = std::string(path) + ".expires_at must be zero or greater than created_at";
            return false;
        }
        record.expiresAt = expiresAt;
    }
    return true;
}
} // namespace

TokenRegistryParseResult ParseTokenRegistry(std::string_view json)
{
    Document document;
    try
    {
        document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
    }
    catch (const ParseException& exception)
    {
        return {{},
            std::string("invalid token registry JSON at byte ") + std::to_string(exception.Offset()) + ": "
                + rapidjson::GetParseError_En(exception.Code())};
    }
    if (document.HasParseError())
    {
        return {{},
            std::string("invalid token registry JSON at byte ") + std::to_string(document.GetErrorOffset()) + ": "
                + rapidjson::GetParseError_En(document.GetParseError())};
    }
    if (!document.IsObject())
        return {{}, "token registry root must be an object"};
    std::string error;
    if (!HasOnlyMembers(document, {"version", "tokens"}, "$", error))
        return {{}, std::move(error)};
    const auto version = document.FindMember("version");
    if (version == document.MemberEnd() || !version->value.IsUint() || version->value.GetUint() != 2)
        return {{}, "$.version must be the supported version 2; reset the old authentication state"};
    const auto tokens = document.FindMember("tokens");
    if (tokens == document.MemberEnd() || !tokens->value.IsObject())
        return {{}, "$.tokens must be an object"};

    TokenAuthenticator::Records records;
    std::unordered_set<std::string> tokenIds;
    std::unordered_set<std::string> issuerIds;
    for (const auto& member : tokens->value.GetObject())
    {
        const std::string verifier(member.name.GetString(), member.name.GetStringLength());
        if (!IsLowerHex256(verifier))
            return {{}, "$.tokens keys must be 64 lowercase hexadecimal HMAC verifiers"};
        if (records.contains(verifier))
            return {{}, "token registry contains a duplicate HMAC verifier"};
        TokenRecord record;
        const auto path = "$.tokens." + verifier;
        if (!ParseTokenRecord(member.value, path, record, error))
            return {{}, std::move(error)};
        if (!tokenIds.insert(record.id).second)
            return {{}, "token registry contains a duplicate internal token ID"};
        if (!issuerIds.insert(record.issuerAccountId).second)
            return {{}, "token registry contains more than one token for an account"};
        records.emplace(verifier, std::move(record));
    }
    return {std::move(records), {}};
}

std::string SerializeTokenRegistry(const TokenAuthenticator::Records& records)
{
    std::vector<std::string_view> verifiers;
    verifiers.reserve(records.size());
    for (const auto& [verifier, record] : records)
        verifiers.push_back(verifier);
    std::sort(verifiers.begin(), verifiers.end());

    rapidjson::StringBuffer buffer;
    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
    writer.SetIndent(' ', 2);
    writer.StartObject();
    writer.Key("version");
    writer.Uint(2);
    writer.Key("tokens");
    writer.StartObject();
    for (const auto verifier : verifiers)
    {
        const auto& record = records.at(std::string(verifier));
        writer.Key(verifier.data(), static_cast<rapidjson::SizeType>(verifier.size()));
        writer.StartObject();
        writer.Key("id");
        writer.String(record.id.data(), static_cast<rapidjson::SizeType>(record.id.size()));
        writer.Key("issuer_account_id");
        writer.String(record.issuerAccountId.data(), static_cast<rapidjson::SizeType>(record.issuerAccountId.size()));
        writer.Key("role");
        const auto role = RoleName(record.role);
        writer.String(role.data(), static_cast<rapidjson::SizeType>(role.size()));
        if (!record.label.empty())
        {
            writer.Key("label");
            writer.String(record.label.data(), static_cast<rapidjson::SizeType>(record.label.size()));
        }
        writer.Key("created_at");
        writer.Uint64(record.createdAt);
        writer.Key("expires_at");
        writer.Uint64(record.expiresAt.value_or(0));
        writer.EndObject();
    }
    writer.EndObject();
    writer.EndObject();
    std::string output(buffer.GetString(), buffer.GetSize());
    output.push_back('\n');
    return output;
}

TokenRegistry::TokenRegistry(CredentialStore& credentials, std::filesystem::path path)
    : credentials_(credentials), file_(credentials, std::move(path), std::string(kTokenIntegrityCredential))
{
}

std::string TokenRegistry::Load()
{
    std::lock_guard lock(mutex_);
    if (authenticator_)
        return "token registry is already loaded";
    const auto loaded = file_.LoadOrCreate(kInitialTokenRegistry,
        [](std::string_view contents)
        {
            const auto parsed = ParseTokenRegistry(contents);
            return parsed.records && parsed.records->empty();
        });
    if (!loaded.contents)
        return loaded.error == "existing private file has no integrity anchor"
            ? "existing token registry is incompatible; remove the account and token registry files to reset "
              "authentication"
            : loaded.error;
    auto parsed = ParseTokenRegistry(*loaded.contents);
    if (!parsed.records)
        return parsed.error;

    auto key = credentials_.Read(kHmacCredential);
    if (!key.error.empty())
        return "cannot read token HMAC key: " + key.error;
    if (!key.value)
    {
        if (!parsed.records->empty())
            return "token records exist but the token HMAC key is missing";
        auto generated = GenerateHex256();
        if (!generated.value)
            return "cannot generate token HMAC key: " + generated.error;
        if (const auto error = credentials_.Write(kHmacCredential, *generated.value); !error.empty())
            return "cannot store token HMAC key: " + error;
        key.value = std::move(generated.value);
    }
    if (!IsLowerHex256(*key.value))
        return "token HMAC key is malformed";

    hmacKey_ = std::move(*key.value);
    records_ = std::move(*parsed.records);
    authenticator_ = std::make_unique<TokenAuthenticator>(hmacKey_, records_);
    return {};
}

bool TokenRegistry::IsLoaded() const
{
    std::lock_guard lock(mutex_);
    return authenticator_ != nullptr;
}

const TokenAuthenticator& TokenRegistry::Authenticator() const
{
    std::lock_guard lock(mutex_);
    if (!authenticator_)
        throw std::logic_error("token registry is not loaded");
    return *authenticator_;
}

TokenAuthenticator::Records TokenRegistry::Records() const
{
    std::lock_guard lock(mutex_);
    return records_;
}

std::vector<TokenRecord> TokenRegistry::RecordsForIssuer(std::string_view issuerAccountId) const
{
    std::lock_guard lock(mutex_);
    std::vector<TokenRecord> result;
    for (const auto& [verifier, record] : records_)
    {
        if (record.issuerAccountId == issuerAccountId)
            result.push_back(record);
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right)
        { return left.createdAt < right.createdAt || (left.createdAt == right.createdAt && left.id < right.id); });
    return result;
}

TokenIssueResult TokenRegistry::ReplaceForIssuer(const TokenIssueRequest& request)
{
    std::lock_guard lock(mutex_);
    if (!authenticator_)
        return {{}, {}, {}, "token registry is not loaded"};
    if (!IsLowerHex256(request.issuerAccountId))
        return {{}, {}, {}, "issuer account ID must be 64 lowercase hexadecimal characters"};
    if (!request.label.empty() && !ValidLabel(request.label))
        return {{}, {}, {}, "token label must be control-free UTF-8 from 1 through 256 bytes"};
    if (request.expiresAt && *request.expiresAt <= request.createdAt)
        return {{}, {}, {}, "token expiry must be greater than its creation time"};

    for (int attempt = 0; attempt < 100; ++attempt)
    {
        auto token = GenerateHex256();
        if (!token.value)
            return {{}, {}, {}, "cannot generate bearer token: " + token.error};
        auto id = GenerateHex256();
        if (!id.value)
            return {{}, {}, {}, "cannot generate internal token ID: " + id.error};
        const auto verifier = HmacSha256Hex(hmacKey_, *token.value);
        const bool idExists = std::any_of(
            records_.begin(), records_.end(), [&](const auto& entry) { return entry.second.id == *id.value; });
        if (records_.contains(verifier) || idExists)
            continue;

        TokenRecord record{
            *id.value, request.issuerAccountId, request.role, request.label, request.createdAt, request.expiresAt};
        auto updated = records_;
        std::vector<TokenRecord> replaced;
        for (auto existing = updated.begin(); existing != updated.end();)
        {
            if (existing->second.issuerAccountId != request.issuerAccountId)
            {
                ++existing;
                continue;
            }
            replaced.push_back(existing->second);
            existing = updated.erase(existing);
        }
        updated.emplace(verifier, record);
        if (const auto error = file_.Replace(SerializeTokenRegistry(updated)); !error.empty())
            return {{}, {}, {}, "cannot persist token registry: " + error};
        records_ = std::move(updated);
        authenticator_->ReplaceRecords(records_);
        return {std::move(token.value), std::move(record), std::move(replaced), {}};
    }
    return {{}, {}, {}, "cannot generate a unique bearer token and internal ID"};
}

std::string TokenRegistry::Revoke(std::string_view tokenId, bool& removed)
{
    std::lock_guard lock(mutex_);
    removed = false;
    if (!authenticator_)
        return "token registry is not loaded";
    auto updated = records_;
    const auto record =
        std::find_if(updated.begin(), updated.end(), [&](const auto& entry) { return entry.second.id == tokenId; });
    if (record == updated.end())
        return {};
    updated.erase(record);
    if (const auto error = file_.Replace(SerializeTokenRegistry(updated)); !error.empty())
        return "cannot persist token registry: " + error;
    records_ = std::move(updated);
    authenticator_->ReplaceRecords(records_);
    removed = true;
    return {};
}

std::string TokenRegistry::RevokeByIssuer(std::string_view issuerAccountId, std::size_t& removed)
{
    std::lock_guard lock(mutex_);
    removed = 0;
    if (!authenticator_)
        return "token registry is not loaded";
    auto updated = records_;
    for (auto record = updated.begin(); record != updated.end();)
    {
        if (record->second.issuerAccountId != issuerAccountId)
        {
            ++record;
            continue;
        }
        record = updated.erase(record);
        ++removed;
    }
    if (removed == 0)
        return {};
    if (const auto error = file_.Replace(SerializeTokenRegistry(updated)); !error.empty())
    {
        removed = 0;
        return "cannot persist token registry: " + error;
    }
    records_ = std::move(updated);
    authenticator_->ReplaceRecords(records_);
    return {};
}
} // namespace binjad::security
