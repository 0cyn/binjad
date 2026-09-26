#include "binjad/portal/Service.hpp"

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
struct Fixture
{
    Fixture()
        : path(std::filesystem::temp_directory_path() / ("binjad-portal-service-" + std::to_string(::getpid()))),
          accounts(credentials, path / "accounts.json", {32, 1, 1, 16, 32}), tokens(credentials, path / "tokens.json"),
          service(accounts, tokens, [this] { return now; })
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        EXPECT_TRUE(accounts.Load().empty());
        EXPECT_TRUE(tokens.Load().empty());
    }

    ~Fixture()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    MemoryCredentialStore credentials;
    std::filesystem::path path;
    binjad::security::AccountRegistry accounts;
    binjad::security::TokenRegistry tokens;
    std::uint64_t now = 100;
    binjad::portal::Service service;
};
#endif
} // namespace

#if !defined(_WIN32)
TEST(PortalServiceTest, CreatesExactlyOneInitialAccount)
{
    Fixture fixture;
    ASSERT_TRUE(fixture.service.SetupRequired().value.value_or(false));
    const auto created = fixture.service.CreateInitialAccount("Admin", "ninebytes");
    ASSERT_TRUE(created.value.has_value()) << created.error;
    EXPECT_FALSE(fixture.service.SetupRequired().value.value_or(true));
    EXPECT_FALSE(fixture.service.CreateInitialAccount("Other", "otherpass").value.has_value());
    EXPECT_EQ(fixture.service.Authenticate("Admin", "ninebytes").result, binjad::security::PasswordVerification::Match);
}

TEST(PortalServiceTest, ChangesOnlyTheCurrentAccountPassword)
{
    Fixture fixture;
    const auto account = fixture.service.CreateInitialAccount("Admin", "ninebytes");
    ASSERT_TRUE(account.value);
    const auto updated = fixture.service.UpdatePassword(*account.value, "newsecret");
    ASSERT_TRUE(updated.value) << updated.error;
    EXPECT_EQ(fixture.service.Authenticate("Admin", "newsecret").result, binjad::security::PasswordVerification::Match);
    EXPECT_EQ(
        fixture.service.Authenticate("Admin", "ninebytes").result, binjad::security::PasswordVerification::Mismatch);
}

TEST(PortalServiceTest, AtomicallyRotatesTheSingleToken)
{
    Fixture fixture;
    const auto account = fixture.service.CreateInitialAccount("Admin", "ninebytes");
    ASSERT_TRUE(account.value);
    const auto first = fixture.service.RotateToken(*account.value, {60});
    ASSERT_TRUE(first.value && first.value->token && first.value->record) << first.error;
    EXPECT_EQ(first.value->record->expiresAt, 160U);

    std::vector<std::string> revoked;
    fixture.service.SetTokenRevokedCallback([&](std::string_view tokenId) { revoked.emplace_back(tokenId); });
    const auto second = fixture.service.RotateToken(*account.value, {0});
    ASSERT_TRUE(second.value && second.value->token && second.value->record) << second.error;
    EXPECT_FALSE(second.value->record->expiresAt.has_value());
    EXPECT_EQ(fixture.tokens.RecordsForIssuer(account.value->id).size(), 1U);
    EXPECT_FALSE(fixture.tokens.Authenticator().Authenticate(*first.value->token, 100));
    EXPECT_TRUE(fixture.tokens.Authenticator().Authenticate(*second.value->token, 100));
    EXPECT_EQ(revoked, (std::vector<std::string>{first.value->record->id}));
}
#endif
