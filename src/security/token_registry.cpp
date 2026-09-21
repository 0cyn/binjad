#include "binjad/security/token_registry.hpp"

#include "binjad/security/crypto.hpp"
#include "binjad/security/random.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <initializer_list>
#include <stdexcept>
#include <unordered_set>
#include <utility>
#include <vector>

namespace binjad::security
{
namespace
{
constexpr std::string_view kInitialRegistry = "{\n  \"version\": 1,\n  \"tokens\": {}\n}\n";
constexpr std::string_view kIntegrityCredential = "tokens-integrity";
constexpr std::string_view kHmacCredential = "tokens-hmac-key";

using rapidjson::Document;
using rapidjson::Value;

bool IsLowerHex256(std::string_view value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
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
        if ((length == 3 && codepoint < 0x800) || (length == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
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

bool ParseRecord(const Value& value, std::string_view path, TokenRecord& record, std::string& error)
{
    if (!value.IsObject())
    {
        error = std::string(path) + " must be an object";
        return false;
    }
    if (!HasOnlyMembers(value,
        {"id", "issuer_account_id", "role", "label", "created_at", "expires_at"}, path, error))
        return false;
    if (!RequiredString(value, "id", path, record.id, error) || !IsLowerHex256(record.id))
    {
        if (error.empty())
            error = std::string(path) + ".id must be 64 lowercase hexadecimal characters";
        return false;
    }
    if (!RequiredString(value, "issuer_account_id", path, record.issuerAccountId, error) ||
        !IsLowerHex256(record.issuerAccountId))
    {
        if (error.empty())
            error = std::string(path) +
                ".issuer_account_id must be 64 lowercase hexadecimal characters";
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
    if (!RequiredUnsigned(value, "created_at", path, record.createdAt, error) ||
        !RequiredUnsigned(value, "expires_at", path, expiresAt, error))
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
}

TokenRegistryParseResult ParseTokenRegistry(std::string_view json)
{
    Document document;
    try
    {
        document.Parse<rapidjson::kParseValidateEncodingFlag>(json.data(), json.size());
    }
    catch (const ParseException& exception)
    {
        return {{}, std::string("invalid token registry JSON at byte ") +
            std::to_string(exception.Offset()) + ": " +
            rapidjson::GetParseError_En(exception.Code())};
    }
    if (document.HasParseError())
    {
        return {{}, std::string("invalid token registry JSON at byte ") +
            std::to_string(document.GetErrorOffset()) + ": " +
            rapidjson::GetParseError_En(document.GetParseError())};
    }
    if (!document.IsObject())
        return {{}, "token registry root must be an object"};
    std::string error;
    if (!HasOnlyMembers(document, {"version", "tokens"}, "$", error))
        return {{}, std::move(error)};
    const auto version = document.FindMember("version");
    if (version == document.MemberEnd() || !version->value.IsUint() || version->value.GetUint() != 1)
        return {{}, "$.version must be the supported version 1"};
    const auto tokens = document.FindMember("tokens");
    if (tokens == document.MemberEnd() || !tokens->value.IsObject())
        return {{}, "$.tokens must be an object"};

    TokenAuthenticator::Records records;
    std::unordered_set<std::string> tokenIds;
    for (const auto& member : tokens->value.GetObject())
    {
        const std::string verifier(member.name.GetString(), member.name.GetStringLength());
        if (!IsLowerHex256(verifier))
            return {{}, "$.tokens keys must be 64 lowercase hexadecimal HMAC verifiers"};
        if (records.contains(verifier))
            return {{}, "token registry contains a duplicate HMAC verifier"};
        TokenRecord record;
        const auto path = "$.tokens." + verifier;
        if (!ParseRecord(member.value, path, record, error))
            return {{}, std::move(error)};
        if (!tokenIds.insert(record.id).second)
            return {{}, "token registry contains a duplicate internal token ID"};
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
    writer.Uint(1);
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
        writer.String(record.issuerAccountId.data(),
            static_cast<rapidjson::SizeType>(record.issuerAccountId.size()));
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
    : credentials_(credentials), file_(credentials, std::move(path), std::string(kIntegrityCredential))
{
}

std::string TokenRegistry::Load()
{
    std::lock_guard lock(mutex_);
    if (authenticator_)
        return "token registry is already loaded";
    const auto loaded = file_.LoadOrCreate(kInitialRegistry, [](std::string_view contents) {
        const auto parsed = ParseTokenRegistry(contents);
        return parsed.records && parsed.records->empty();
    });
    if (!loaded.contents)
        return loaded.error;
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
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.createdAt < right.createdAt ||
            (left.createdAt == right.createdAt && left.id < right.id);
    });
    return result;
}

TokenIssueResult TokenRegistry::Issue(const TokenIssueRequest& request)
{
    std::lock_guard lock(mutex_);
    if (!authenticator_)
        return {{}, {}, "token registry is not loaded"};
    if (!IsLowerHex256(request.issuerAccountId))
        return {{}, {}, "issuer account ID must be 64 lowercase hexadecimal characters"};
    if (!request.label.empty() && !ValidLabel(request.label))
        return {{}, {}, "token label must be control-free UTF-8 from 1 through 256 bytes"};
    if (request.expiresAt && *request.expiresAt <= request.createdAt)
        return {{}, {}, "token expiry must be greater than its creation time"};

    for (int attempt = 0; attempt < 100; ++attempt)
    {
        auto token = GenerateHex256();
        if (!token.value)
            return {{}, {}, "cannot generate bearer token: " + token.error};
        auto id = GenerateHex256();
        if (!id.value)
            return {{}, {}, "cannot generate internal token ID: " + id.error};
        const auto verifier = HmacSha256Hex(hmacKey_, *token.value);
        const bool idExists = std::any_of(records_.begin(), records_.end(), [&](const auto& entry) {
            return entry.second.id == *id.value;
        });
        if (records_.contains(verifier) || idExists)
            continue;

        TokenRecord record{*id.value, request.issuerAccountId, request.role,
            request.label, request.createdAt, request.expiresAt};
        auto updated = records_;
        updated.emplace(verifier, record);
        if (const auto error = file_.Replace(SerializeTokenRegistry(updated)); !error.empty())
            return {{}, {}, "cannot persist token registry: " + error};
        records_ = std::move(updated);
        authenticator_->ReplaceRecords(records_);
        return {std::move(token.value), std::move(record), {}};
    }
    return {{}, {}, "cannot generate a unique bearer token and internal ID"};
}

std::string TokenRegistry::Revoke(std::string_view tokenId, bool& removed)
{
    std::lock_guard lock(mutex_);
    removed = false;
    if (!authenticator_)
        return "token registry is not loaded";
    auto updated = records_;
    const auto record = std::find_if(updated.begin(), updated.end(), [&](const auto& entry) {
        return entry.second.id == tokenId;
    });
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

std::string TokenRegistry::RevokeByIssuer(
    std::string_view issuerAccountId, std::size_t& removed)
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
}
