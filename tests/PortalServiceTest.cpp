#include "binjad/portal/service.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <unordered_map>
#include <vector>

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
struct Fixture
{
    explicit Fixture(binjad::Mode mode = binjad::Mode::Local)
        : path(std::filesystem::temp_directory_path() /
            ("binjad-portal-service-" + std::to_string(::getpid()))),
          config(MakeConfig(mode)),
          accounts(credentials, path / "accounts.json", {32, 1, 1, 16, 32}),
          tokens(credentials, path / "tokens.json"), bootstrap(credentials),
          service(config, accounts, tokens, bootstrap, [this] { return now; })
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        EXPECT_TRUE(accounts.Load().empty());
        EXPECT_TRUE(tokens.Load().empty());
        EXPECT_TRUE(bootstrap.Load().empty());
    }

    static binjad::Config MakeConfig(binjad::Mode mode)
    {
        binjad::Config config;
        config.mode = mode;
        if (mode == binjad::Mode::Collaboration)
            config.collaboration.remote = binjad::CollaborationRemoteConfig{
                "test", "https://collaboration.example"};
        return config;
    }

    ~Fixture()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    MemoryCredentialStore credentials;
    std::filesystem::path path;
    binjad::Config config;
    binjad::security::AccountRegistry accounts;
    binjad::security::TokenRegistry tokens;
    binjad::security::BootstrapCredential bootstrap;
    std::uint64_t now = 100;
    binjad::portal::Service service;
};
#endif
}

#if !defined(_WIN32)
TEST(PortalServiceTest, BootstrapCreatesOnlyAdministratorAndConsumesCredential)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    const auto created = fixture.service.CreateBootstrapAdministrator(
        *credential.credential, "Admin", "ninebytes");
    ASSERT_TRUE(created.value.has_value()) << created.error;
    EXPECT_EQ(created.value->role, binjad::security::PortalRole::Admin);
    EXPECT_FALSE(fixture.bootstrap.Available());
    EXPECT_FALSE(fixture.service.CreateBootstrapAdministrator(
        *credential.credential, "Other", "ninebytes").value.has_value());
}

TEST(PortalServiceTest, EnforcesAccountScopeAndLastAdminRule)
{
    Fixture fixture(binjad::Mode::Collaboration);
    auto credential = fixture.bootstrap.Mint();
    auto admin = fixture.service.CreateBootstrapAdministrator(
        *credential.credential, "Admin", "ninebytes");
    ASSERT_TRUE(admin.value);
    const auto user = fixture.service.CreateAccount(*admin.value,
        "User", "usersecret", binjad::security::PortalRole::SelfService);
    ASSERT_TRUE(user.value) << user.error;
    EXPECT_FALSE(fixture.service.CreateAccount(*user.value,
        "Other", "otherpass", binjad::security::PortalRole::SelfService).value);
    EXPECT_FALSE(fixture.service.UpdateAccount(*user.value, admin.value->id,
        {{}, std::string("changedpass")}).value);
    EXPECT_FALSE(fixture.service.UpdateAccount(*admin.value, admin.value->id,
        {binjad::security::PortalRole::SelfService, {}}).value);
}

TEST(PortalServiceTest, AppliesModeRoleAndExpiryPoliciesToTokenIssuance)
{
    Fixture fixture;
    auto credential = fixture.bootstrap.Mint();
    auto admin = fixture.service.CreateBootstrapAdministrator(
        *credential.credential, "Admin", "ninebytes");
    ASSERT_TRUE(admin.value);
    const auto local = fixture.service.IssueToken(*admin.value,
        {std::string("local"), binjad::security::TokenRole::User, {}});
    ASSERT_TRUE(local.value && local.value->record);
    EXPECT_EQ(local.value->record->role, binjad::security::TokenRole::Admin);
    EXPECT_EQ(local.value->record->expiresAt, 100 + 604800);
    EXPECT_FALSE(fixture.service.IssueToken(*admin.value,
        {{}, {}, 0}).value.has_value());
}

TEST(PortalServiceTest, DeletesAccountWithSelectedTokenDisposition)
{
    Fixture fixture;
    auto credential = fixture.bootstrap.Mint();
    auto firstAdmin = fixture.service.CreateBootstrapAdministrator(
        *credential.credential, "Admin", "ninebytes");
    ASSERT_TRUE(firstAdmin.value);
    auto secondAdmin = fixture.service.CreateAccount(*firstAdmin.value,
        "Second", "otherpass", binjad::security::PortalRole::Admin);
    ASSERT_TRUE(secondAdmin.value);
    const auto issued = fixture.service.IssueToken(*secondAdmin.value, {});
    ASSERT_TRUE(issued.value && issued.value->record);
    std::vector<std::string> revoked;
    fixture.service.SetTokenRevokedCallback(
        [&](std::string_view tokenId) { revoked.emplace_back(tokenId); });
    const auto deleted = fixture.service.DeleteAccount(
        *firstAdmin.value, secondAdmin.value->id, true);
    ASSERT_TRUE(deleted.value) << deleted.error;
    EXPECT_TRUE(deleted.value->deleted);
    EXPECT_EQ(deleted.value->revokedTokens, 1U);
    EXPECT_EQ(revoked, (std::vector<std::string>{issued.value->record->id}));
    EXPECT_TRUE(fixture.tokens.RecordsForIssuer(secondAdmin.value->id).empty());
}
#endif
