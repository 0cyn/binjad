#include "binjad/security/account_registry.hpp"

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
        return value == values.end()
            ? binjad::security::CredentialReadResult{}
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
        : path(std::filesystem::temp_directory_path() /
            ("binjad-account-registry-" + std::to_string(::getpid())))
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
}

TEST(AccountRegistryTest, ParsesActiveAndReusableTombstonedUsernames)
{
    const std::string activeId(64, 'a');
    const std::string deletedId(64, 'b');
    const auto json = std::string(R"({"version":1,"accounts":{")") + activeId +
        R"(":{"username":"operator","role":"portal-admin","created_at":10,"deleted_at":0},")" +
        deletedId + R"(":{"username":"operator","role":"self-service","created_at":1,)"
        R"("collaboration_username":"alice","deleted_at":9}}})";
    const auto parsed = binjad::security::ParseAccountRegistry(json);
    ASSERT_TRUE(parsed.records.has_value()) << parsed.error;
    EXPECT_FALSE(parsed.records->at(activeId).deletedAt.has_value());
    EXPECT_EQ(parsed.records->at(deletedId).collaborationUsername, "alice");
}

TEST(AccountRegistryTest, RejectsDuplicateActiveUsernameAndUnknownFields)
{
    const std::string first(64, 'a');
    const std::string second(64, 'b');
    const auto duplicate = std::string(R"({"version":1,"accounts":{")") + first +
        R"(":{"username":"same","role":"portal-admin","created_at":1,"deleted_at":0},")" +
        second + R"(":{"username":"same","role":"portal-admin","created_at":2,"deleted_at":0}}})";
    EXPECT_FALSE(binjad::security::ParseAccountRegistry(duplicate).records.has_value());
    EXPECT_FALSE(binjad::security::ParseAccountRegistry(
        R"({"version":1,"accounts":{},"extra":true})").records.has_value());
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

TEST(AccountRegistryTest, CreatesAuthenticatesBindsDeletesAndReusesUsername)
{
    TemporaryDirectory temporary;
    MemoryCredentialStore credentials;
    constexpr binjad::security::Argon2Profile testProfile{32, 1, 1, 16, 32};
    binjad::security::AccountRegistry registry(
        credentials, temporary.path / "accounts.json", testProfile);
    ASSERT_TRUE(registry.Load().empty());

    const auto created = registry.Create(
        {"Operator", "ninebytes", binjad::security::PortalRole::Admin, 10});
    ASSERT_TRUE(created.record.has_value()) << created.error;
    EXPECT_EQ(registry.Authenticate("Operator", "ninebytes").result,
        binjad::security::PasswordVerification::Match);
    EXPECT_EQ(registry.Authenticate("operator", "ninebytes").result,
        binjad::security::PasswordVerification::Mismatch);
    EXPECT_EQ(registry.Authenticate("Operator", "incorrect").result,
        binjad::security::PasswordVerification::Mismatch);

    ASSERT_TRUE(registry.SetCollaborationBinding(
        created.record->id, "alice", "collaboration-secret").empty());
    const auto accessToken = registry.CollaborationAccessToken(created.record->id);
    ASSERT_TRUE(accessToken.value.has_value());
    EXPECT_EQ(*accessToken.value, "collaboration-secret");

    const auto secondAdmin = registry.Create(
        {"Second", "otherpass", binjad::security::PortalRole::Admin, 11});
    ASSERT_TRUE(secondAdmin.record.has_value()) << secondAdmin.error;
    bool deleted = false;
    ASSERT_TRUE(registry.Delete(created.record->id, 20, deleted).empty());
    EXPECT_TRUE(deleted);
    EXPECT_EQ(registry.Authenticate("Operator", "ninebytes").result,
        binjad::security::PasswordVerification::Mismatch);
    EXPECT_FALSE(registry.CollaborationAccessToken(created.record->id).value.has_value());

    const auto reused = registry.Create(
        {"Operator", "newsecret", binjad::security::PortalRole::SelfService, 30});
    ASSERT_TRUE(reused.record.has_value()) << reused.error;
    EXPECT_NE(reused.record->id, created.record->id);
}

TEST(AccountRegistryTest, UpdatesPasswordAndPreventsLastAdministratorLockout)
{
    TemporaryDirectory temporary;
    MemoryCredentialStore credentials;
    constexpr binjad::security::Argon2Profile testProfile{32, 1, 1, 16, 32};
    binjad::security::AccountRegistry registry(
        credentials, temporary.path / "accounts.json", testProfile);
    ASSERT_TRUE(registry.Load().empty());
    const auto created = registry.Create(
        {"Admin", "oldsecret", binjad::security::PortalRole::Admin, 10});
    ASSERT_TRUE(created.record.has_value());

    const auto password = registry.Update(created.record->id,
        {{}, std::string("newsecret")});
    ASSERT_TRUE(password.record.has_value()) << password.error;
    EXPECT_EQ(registry.Authenticate("Admin", "newsecret").result,
        binjad::security::PasswordVerification::Match);
    EXPECT_FALSE(registry.Update(created.record->id,
        {binjad::security::PortalRole::SelfService, {}}).record.has_value());
    bool deleted = false;
    EXPECT_NE(registry.Delete(created.record->id, 20, deleted).find("last active"),
        std::string::npos);
    EXPECT_FALSE(deleted);
}
#endif
