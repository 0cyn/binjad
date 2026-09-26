#include "binjad/security/TokenRegistry.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <unordered_map>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace
{
class MemoryCredentialStore final : public binjad::security::CredentialStore
{
public:
    binjad::security::CredentialReadResult Read(std::string_view key) override
    {
        const auto value = values.find(std::string(key));
        return value == values.end() ? binjad::security::CredentialReadResult{}
                                     : binjad::security::CredentialReadResult{value->second, {}};
    }

    std::string Write(std::string_view key, std::string_view value) override
    {
        values[std::string(key)] = value;
        return {};
    }

    std::string Remove(std::string_view key) override
    {
        values.erase(std::string(key));
        return {};
    }

    std::unordered_map<std::string, std::string> values;
};

#if !defined(_WIN32)
class TemporaryDirectory
{
public:
    explicit TemporaryDirectory(std::string_view name)
        : path(std::filesystem::temp_directory_path() / (std::string(name) + '-' + std::to_string(::getpid())))
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    ~TemporaryDirectory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    std::filesystem::path path;
};
#endif
} // namespace

TEST(TokenRegistryTest, ParsesStrictVersionedRecordsAndInfiniteExpiry)
{
    const std::string verifier(64, 'a');
    const std::string tokenId(64, 'b');
    const std::string accountId(64, 'c');
    const auto json = std::string(R"({"version":2,"tokens":{")") + verifier + R"(":{"id":")" + tokenId
        + R"(","issuer_account_id":")" + accountId
        + R"(","role":"admin","label":"release","created_at":10,"expires_at":0}}})";
    const auto parsed = binjad::security::ParseTokenRegistry(json);
    ASSERT_TRUE(parsed.records.has_value()) << parsed.error;
    ASSERT_EQ(parsed.records->size(), 1U);
    EXPECT_FALSE(parsed.records->at(verifier).expiresAt.has_value());

    const auto unknown = binjad::security::ParseTokenRegistry(R"({"version":2,"tokens":{},"unexpected":true})");
    EXPECT_FALSE(unknown.records.has_value());
    EXPECT_NE(unknown.error.find("unknown field"), std::string::npos);
}

#if !defined(_WIN32)
TEST(TokenRegistryTest, CreatesIssuesAuthenticatesReloadsAndRevokes)
{
    TemporaryDirectory temporary("binjad-token-registry");
    const auto path = temporary.path / "tokens.json";
    MemoryCredentialStore credentials;
    binjad::security::TokenRegistry registry(credentials, path);
    ASSERT_TRUE(registry.Load().empty());
    EXPECT_TRUE(registry.IsLoaded());

    const auto issued =
        registry.ReplaceForIssuer({std::string(64, 'c'), binjad::security::TokenRole::Admin, "release", 10, 100});
    ASSERT_TRUE(issued.token.has_value()) << issued.error;
    ASSERT_TRUE(issued.record.has_value());
    EXPECT_TRUE(registry.Authenticator().Authenticate(*issued.token, 99).has_value());
    EXPECT_FALSE(registry.Authenticator().Authenticate(*issued.token, 100).has_value());

    binjad::security::TokenRegistry reopened(credentials, path);
    ASSERT_TRUE(reopened.Load().empty());
    EXPECT_TRUE(reopened.Authenticator().Authenticate(*issued.token, 99).has_value());

    bool removed = false;
    EXPECT_TRUE(reopened.Revoke(issued.record->id, removed).empty());
    EXPECT_TRUE(removed);
    EXPECT_FALSE(reopened.Authenticator().Authenticate(*issued.token, 99).has_value());
}

TEST(TokenRegistryTest, RefusesRecordsWithoutOriginalHmacKey)
{
    TemporaryDirectory temporary("binjad-token-key");
    const auto path = temporary.path / "tokens.json";
    MemoryCredentialStore credentials;
    binjad::security::TokenRegistry registry(credentials, path);
    ASSERT_TRUE(registry.Load().empty());
    ASSERT_TRUE(registry.ReplaceForIssuer({std::string(64, 'c'), binjad::security::TokenRole::User, {}, 10, 100})
            .token.has_value());
    credentials.values.erase("tokens-hmac-key-v2");

    binjad::security::TokenRegistry reopened(credentials, path);
    EXPECT_NE(reopened.Load().find("HMAC key is missing"), std::string::npos);
}

TEST(TokenRegistryTest, ValidatesLabelsBeforePersistence)
{
    TemporaryDirectory temporary("binjad-token-label");
    MemoryCredentialStore credentials;
    binjad::security::TokenRegistry registry(credentials, temporary.path / "tokens.json");
    ASSERT_TRUE(registry.Load().empty());
    const auto invalid =
        registry.ReplaceForIssuer({std::string(64, 'c'), binjad::security::TokenRole::User, "line\nbreak", 10, 100});
    EXPECT_FALSE(invalid.token.has_value());
    EXPECT_NE(invalid.error.find("control-free"), std::string::npos);
    const auto invalidUtf8 = registry.ReplaceForIssuer(
        {std::string(64, 'c'), binjad::security::TokenRole::User, std::string("invalid\xff", 8), 10, 100});
    EXPECT_FALSE(invalidUtf8.token.has_value());
    EXPECT_TRUE(registry.Records().empty());
}

TEST(TokenRegistryTest, ReplacesOneTokenPerIssuer)
{
    TemporaryDirectory temporary("binjad-token-issuer");
    MemoryCredentialStore credentials;
    binjad::security::TokenRegistry registry(credentials, temporary.path / "tokens.json");
    ASSERT_TRUE(registry.Load().empty());
    const std::string firstIssuer(64, 'c');
    const std::string secondIssuer(64, 'd');
    const auto first =
        registry.ReplaceForIssuer({firstIssuer, binjad::security::TokenRole::User, "first", 10, 100}).token;
    ASSERT_TRUE(first);
    const auto replacement =
        registry.ReplaceForIssuer({firstIssuer, binjad::security::TokenRole::User, "second", 11, 100});
    ASSERT_TRUE(replacement.token);
    ASSERT_EQ(replacement.replaced.size(), 1U);
    ASSERT_TRUE(registry.ReplaceForIssuer({secondIssuer, binjad::security::TokenRole::User, "other", 12, 100}).token);
    EXPECT_EQ(registry.RecordsForIssuer(firstIssuer).size(), 1U);
    EXPECT_FALSE(registry.Authenticator().Authenticate(*first, 50));
    EXPECT_TRUE(registry.Authenticator().Authenticate(*replacement.token, 50));
    std::size_t removed = 0;
    ASSERT_TRUE(registry.RevokeByIssuer(firstIssuer, removed).empty());
    EXPECT_EQ(removed, 1U);
    EXPECT_TRUE(registry.RecordsForIssuer(firstIssuer).empty());
    EXPECT_EQ(registry.Records().size(), 1U);
}
#endif
