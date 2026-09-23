#include "binjad/security/credential_vault.hpp"

#include <rapidjsonwrapper.h>

#include <set>

namespace binjad::security
{
CredentialVaultParseResult ParseCredentialVault(std::string_view contents)
{
    rapidjson::Document document;
    document.Parse(contents.data(), contents.size());
    if (document.HasParseError() || !document.IsObject())
        return {{}, "credential vault must be a JSON object"};

    std::set<std::string_view> fields;
    for (const auto& member : document.GetObject())
    {
        const std::string_view name(member.name.GetString(), member.name.GetStringLength());
        if (name != "version" && name != "values")
            return {{}, "credential vault contains unknown field '" + std::string(name) + "'"};
        if (!fields.insert(name).second)
            return {{}, "credential vault contains duplicate field '" + std::string(name) + "'"};
    }
    const auto version = document.FindMember("version");
    const auto values = document.FindMember("values");
    if (version == document.MemberEnd() || !version->value.IsUint() ||
        version->value.GetUint() != 1)
        return {{}, "credential vault version must be 1"};
    if (values == document.MemberEnd() || !values->value.IsObject())
        return {{}, "credential vault values must be an object"};

    CredentialVaultValues result;
    for (const auto& member : values->value.GetObject())
    {
        const std::string key(member.name.GetString(), member.name.GetStringLength());
        if (key.empty())
            return {{}, "credential vault key must not be empty"};
        if (!member.value.IsString())
            return {{}, "credential vault value for '" + key + "' must be a string"};
        if (!result.emplace(key, std::string(member.value.GetString(),
                member.value.GetStringLength())).second)
            return {{}, "credential vault contains duplicate key '" + key + "'"};
    }
    return {std::move(result), {}};
}

std::string SerializeCredentialVault(const CredentialVaultValues& values)
{
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    writer.StartObject();
    writer.Key("version"); writer.Uint(1);
    writer.Key("values"); writer.StartObject();
    for (const auto& [key, value] : values)
    {
        writer.Key(key.data(), static_cast<rapidjson::SizeType>(key.size()));
        writer.String(value.data(), static_cast<rapidjson::SizeType>(value.size()));
    }
    writer.EndObject(); writer.EndObject();
    return {buffer.GetString(), buffer.GetSize()};
}
}
