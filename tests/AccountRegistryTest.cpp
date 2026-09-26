#include "binjad/security/AccountRegistry.hpp"

#include <gtest/gtest.h>

#include <filesystem>
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
    TemporaryDirectory()
        : path(std::filesystem::temp_directory_path() / ("binjad-account-registry-" + std::to_string(::getpid())))
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

TEST(AccountRegistryTest, ParsesOneVersionTwoAccount)
{
    const std::string activeId(64, 'a');
    const auto json =
        std::string(R"({"version":2,"accounts":{")") + activeId + R"(":{"username":"operator","created_at":10}}})";
    const auto parsed = binjad::security::ParseAccountRegistry(json);
    ASSERT_TRUE(parsed.records.has_value()) << parsed.error;
    EXPECT_EQ(parsed.records->at(activeId).username, "operator");
}

TEST(AccountRegistryTest, RejectsLegacyMultipleAndUnknownFields)
{
    const std::string first(64, 'a');
    const std::string second(64, 'b');
    EXPECT_FALSE(binjad::security::ParseAccountRegistry(R"({"version":1,"accounts":{}})").records.has_value());
    const auto multiple = std::string(R"({"version":2,"accounts":{")") + first
        + R"(":{"username":"first","created_at":1},")" + second + R"(":{"username":"second","created_at":2}}})";
    EXPECT_FALSE(binjad::security::ParseAccountRegistry(multiple).records.has_value());
    EXPECT_FALSE(
        binjad::security::ParseAccountRegistry(R"({"version":2,"accounts":{},"extra":true})").records.has_value());
}

#if !defined(_WIN32)
TEST(AccountRegistryTest, CreatesAnchoredEmptyRegistryAndFindsExactUsername)
{
    TemporaryDirectory temporary;
    MemoryCredentialStore credentials;
    binjad::security::AccountRegistry registry(credentials, temporary.path / "accounts.json");
    ASSERT_TRUE(registry.Load().empty());
    EXPECT_TRUE(registry.IsLoaded());
    EXPECT_TRUE(registry.Records().empty());
    EXPECT_FALSE(registry.FindActive("operator").has_value());
}

TEST(AccountRegistryTest, CreatesAuthenticatesAndRejectsSecondAccount)
{
    TemporaryDirectory temporary;
    MemoryCredentialStore credentials;
    constexpr binjad::security::Argon2Profile testProfile{32, 1, 1, 16, 32};
    binjad::security::AccountRegistry registry(credentials, temporary.path / "accounts.json", testProfile);
    ASSERT_TRUE(registry.Load().empty());

    const auto created = registry.CreateInitial({"Operator", "ninebytes", 10});
    ASSERT_TRUE(created.record.has_value()) << created.error;
    EXPECT_EQ(registry.Authenticate("Operator", "ninebytes").result, binjad::security::PasswordVerification::Match);
    EXPECT_EQ(registry.Authenticate("operator", "ninebytes").result, binjad::security::PasswordVerification::Mismatch);
    EXPECT_EQ(registry.Authenticate("Operator", "incorrect").result, binjad::security::PasswordVerification::Mismatch);

    const auto second = registry.CreateInitial({"Second", "otherpass", 11});
    EXPECT_FALSE(second.record.has_value());
    EXPECT_NE(second.error.find("already configured"), std::string::npos);
    ASSERT_TRUE(registry.Account().has_value());
    EXPECT_EQ(registry.Account()->id, created.record->id);
}

TEST(AccountRegistryTest, UpdatesPassword)
{
    TemporaryDirectory temporary;
    MemoryCredentialStore credentials;
    constexpr binjad::security::Argon2Profile testProfile{32, 1, 1, 16, 32};
    binjad::security::AccountRegistry registry(credentials, temporary.path / "accounts.json", testProfile);
    ASSERT_TRUE(registry.Load().empty());
    const auto created = registry.CreateInitial({"Admin", "oldsecret", 10});
    ASSERT_TRUE(created.record.has_value());

    const auto password = registry.UpdatePassword(created.record->id, "newsecret");
    ASSERT_TRUE(password.record.has_value()) << password.error;
    EXPECT_EQ(registry.Authenticate("Admin", "newsecret").result, binjad::security::PasswordVerification::Match);
    EXPECT_EQ(registry.Authenticate("Admin", "oldsecret").result, binjad::security::PasswordVerification::Mismatch);
}
#endif
