#include "binjad/security/bootstrap_credential.hpp"

#include <gtest/gtest.h>

#include <string>
#include <unordered_map>

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
}

TEST(BootstrapCredentialTest, RemintInvalidatesPreviousCredential)
{
    MemoryCredentialStore credentials;
    binjad::security::BootstrapCredential bootstrap(credentials);
    ASSERT_TRUE(bootstrap.Load().empty());
    const auto first = bootstrap.Mint();
    const auto second = bootstrap.Mint();
    ASSERT_TRUE(first.credential && second.credential);
    EXPECT_NE(*first.credential, *second.credential);
    EXPECT_FALSE(bootstrap.Begin(*first.credential).authorized);
    EXPECT_TRUE(bootstrap.Begin(*second.credential).authorized);
}

TEST(BootstrapCredentialTest, FailedActionRestoresCredentialAndSuccessConsumesIt)
{
    MemoryCredentialStore credentials;
    binjad::security::BootstrapCredential bootstrap(credentials);
    ASSERT_TRUE(bootstrap.Load().empty());
    const auto minted = bootstrap.Mint();
    ASSERT_TRUE(minted.credential);
    ASSERT_TRUE(bootstrap.Begin(*minted.credential).authorized);
    EXPECT_FALSE(bootstrap.Begin(*minted.credential).authorized);
    ASSERT_TRUE(bootstrap.Complete(false).empty());
    ASSERT_TRUE(bootstrap.Begin(*minted.credential).authorized);
    ASSERT_TRUE(bootstrap.Complete(true).empty());
    EXPECT_FALSE(bootstrap.Available());
    EXPECT_FALSE(bootstrap.Begin(*minted.credential).authorized);
}

TEST(BootstrapCredentialTest, InterruptedPendingCredentialIsConsumedOnReload)
{
    MemoryCredentialStore credentials;
    binjad::security::BootstrapCredential first(credentials);
    ASSERT_TRUE(first.Load().empty());
    const auto minted = first.Mint();
    ASSERT_TRUE(minted.credential);
    ASSERT_TRUE(first.Begin(*minted.credential).authorized);

    binjad::security::BootstrapCredential restarted(credentials);
    ASSERT_TRUE(restarted.Load().empty());
    EXPECT_FALSE(restarted.Available());
    EXPECT_FALSE(restarted.Begin(*minted.credential).authorized);
    EXPECT_TRUE(credentials.values.empty());
}

TEST(BootstrapCredentialTest, RunningDaemonObservesExternalRemint)
{
    MemoryCredentialStore credentials;
    binjad::security::BootstrapCredential daemon(credentials);
    ASSERT_TRUE(daemon.Load().empty());
    EXPECT_FALSE(daemon.Available());

    binjad::security::BootstrapCredential command(credentials);
    ASSERT_TRUE(command.Load().empty());
    const auto minted = command.Mint();
    ASSERT_TRUE(minted.credential);
    ASSERT_TRUE(daemon.Refresh().empty());
    EXPECT_TRUE(daemon.Available());
    EXPECT_TRUE(daemon.Begin(*minted.credential).authorized);
}
