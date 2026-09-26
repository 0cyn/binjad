#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/Crypto.hpp"
#include "binjad/security/CredentialVault.hpp"
#include "binjad/security/IntegrityFile.hpp"
#include "binjad/security/Password.hpp"
#include "binjad/security/Random.hpp"
#include "binjad/security/TokenAuthenticator.hpp"
#include "binjad/platform/Paths.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <unordered_map>

#if !defined(_WIN32)
#include <sys/stat.h>
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
        if (value == values.end())
            return {};
        return {value->second, {}};
    }

    std::string Write(std::string_view key, std::string_view value) override
    {
        ++writes;
        if (failWrite && writes == *failWrite)
            return "injected failure";
        values[std::string(key)] = value;
        return {};
    }

    std::string Remove(std::string_view key) override
    {
        values.erase(std::string(key));
        return {};
    }

    std::unordered_map<std::string, std::string> values;
    std::optional<std::size_t> failWrite;
    std::size_t writes = 0;
};

#if !defined(_WIN32)
class TemporaryDirectory
{
  public:
    explicit TemporaryDirectory(std::string_view name)
        : path(std::filesystem::temp_directory_path() /
            (std::string(name) + '-' + std::to_string(::getpid())))
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

TEST(SecurityTest, RoundTripsStrictVersionedCredentialVault)
{
    const binjad::security::CredentialVaultValues values{
        {"anchor", "1\ncurrent\npending"},
        {"password", "$argon2id$value"},
    };
    const auto serialized = binjad::security::SerializeCredentialVault(values);
    const auto parsed = binjad::security::ParseCredentialVault(serialized);
    ASSERT_TRUE(parsed.values) << parsed.error;
    EXPECT_EQ(*parsed.values, values);

    EXPECT_FALSE(binjad::security::ParseCredentialVault(
        R"({"version":1,"values":{},"unexpected":true})").values);
    EXPECT_FALSE(binjad::security::ParseCredentialVault(
        R"({"version":2,"values":{}})").values);
    EXPECT_FALSE(binjad::security::ParseCredentialVault(
        R"({"version":1,"values":{"key":1}})").values);
}

TEST(SecurityTest, ComputesKnownSha256AndHmacValues)
{
    EXPECT_EQ(binjad::security::Sha256Hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(binjad::security::HmacSha256Hex(
        "key", "The quick brown fox jumps over the lazy dog"),
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

TEST(SecurityTest, ComparesValuesWithoutLengthShortCircuit)
{
    EXPECT_TRUE(binjad::security::ConstantTimeEqual("same", "same"));
    EXPECT_FALSE(binjad::security::ConstantTimeEqual("same", "different"));
    EXPECT_FALSE(binjad::security::ConstantTimeEqual("same", "samo"));
}

TEST(SecurityTest, ComputesNormalizedLegacyCredentialNamespace)
{
    const auto first = binjad::security::CredentialNamespace("relative/../config.json");
    const auto second = binjad::security::CredentialNamespace("config.json");
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), 64U);
}

TEST(SecurityTest, GeneratesConfiguredTokenAndSessionIdentifierFormats)
{
    const auto token = binjad::security::GenerateHex256();
    ASSERT_TRUE(token.value.has_value()) << token.error;
    EXPECT_TRUE(binjad::security::TokenAuthenticator::IsTokenSyntax(*token.value));

    const auto session = binjad::security::GenerateBase64Url256();
    ASSERT_TRUE(session.value.has_value()) << session.error;
    ASSERT_EQ(session.value->size(), 43U);
    EXPECT_TRUE(std::all_of(session.value->begin(), session.value->end(), [](char character) {
        return (character >= 'A' && character <= 'Z') ||
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '-' || character == '_';
    }));
}

TEST(SecurityTest, AuthenticatesHmacVerifierAndEnforcesExpiry)
{
    const std::string token(64, 'a');
    constexpr std::string_view key = "test HMAC key";
    binjad::security::TokenRecord record{
        std::string(64, 'b'), std::string(64, 'c'),
        binjad::security::TokenRole::Admin, "test", 10, 100};
    binjad::security::TokenAuthenticator authenticator(std::string(key),
        {{binjad::security::HmacSha256Hex(key, token), record}});

    const auto authenticated = authenticator.Authenticate(token, 99);
    ASSERT_TRUE(authenticated.has_value());
    EXPECT_EQ(authenticated->id, record.id);
    EXPECT_FALSE(authenticator.Authenticate(token, 100).has_value());
    EXPECT_FALSE(authenticator.Authenticate(std::string(64, 'A'), 99).has_value());
    EXPECT_FALSE(authenticator.Authenticate("short", 99).has_value());
}

TEST(SecurityTest, HashesAndVerifiesArgon2idPhcStrings)
{
    constexpr binjad::security::Argon2Profile testProfile{32, 1, 1, 16, 32};
    const auto hash = binjad::security::HashPassword("correct horse", testProfile);
    ASSERT_TRUE(hash.encoded.has_value()) << hash.error;
    EXPECT_EQ(hash.encoded->find("$argon2id$v=19$m=32,t=1,p=1$"), 0U);
    EXPECT_EQ(binjad::security::VerifyPassword("correct horse", *hash.encoded).result,
        binjad::security::PasswordVerification::Match);
    EXPECT_EQ(binjad::security::VerifyPassword("wrong horse", *hash.encoded).result,
        binjad::security::PasswordVerification::Mismatch);
    EXPECT_EQ(binjad::security::VerifyPassword("password", "not-a-phc-string").result,
        binjad::security::PasswordVerification::Error);
    EXPECT_EQ(binjad::security::kPortalPasswordProfile.memoryKib, 256U * 1024);
    EXPECT_EQ(binjad::security::kPortalPasswordProfile.iterations, 3U);
    EXPECT_FALSE(binjad::security::IsValidPortalPassword("short"));
    EXPECT_TRUE(binjad::security::IsValidPortalPassword("ninebytes"));
    EXPECT_FALSE(binjad::security::IsValidPortalPassword(std::string("invalid\xff", 8)));
}

#if !defined(_WIN32)
TEST(SecurityTest, CreatesAndAnchorsPrivateFile)
{
    TemporaryDirectory temporary("binjad-integrity-create");
    MemoryCredentialStore credentials;
    binjad::security::IntegrityFile file(
        credentials, temporary.path / "tokens.json", "tokens-integrity");

    const auto result = file.LoadOrCreate("{\"version\":1}\n", {});
    ASSERT_TRUE(result.contents.has_value()) << result.error;
    EXPECT_TRUE(result.created);
    EXPECT_EQ(*result.contents, "{\"version\":1}\n");
    EXPECT_TRUE(credentials.values.contains("tokens-integrity"));
}

TEST(SecurityTest, RejectsUnanchoredAndTamperedFiles)
{
    TemporaryDirectory temporary("binjad-integrity-tamper");
    const auto path = temporary.path / "tokens.json";
    MemoryCredentialStore credentials;
    binjad::security::IntegrityFile original(credentials, path, "tokens-integrity");
    const auto loaded = original.LoadOrCreate("{}\n", {});
    ASSERT_TRUE(loaded.contents.has_value()) << loaded.error;

    {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(stream);
        stream << "{\"tampered\":true}\n";
    }
    binjad::security::IntegrityFile reopened(credentials, path, "tokens-integrity");
    const auto result = reopened.LoadOrCreate("{}\n", {});
    EXPECT_FALSE(result.contents.has_value());
    EXPECT_NE(result.error.find("does not match"), std::string::npos);

    MemoryCredentialStore noAnchor;
    binjad::security::IntegrityFile unanchored(noAnchor, path, "tokens-integrity");
    const auto missing = unanchored.LoadOrCreate("{}\n", [](std::string_view) { return false; });
    EXPECT_FALSE(missing.contents.has_value());
    EXPECT_NE(missing.error.find("no integrity anchor"), std::string::npos);
}

TEST(SecurityTest, RecoversInstalledPendingSnapshot)
{
    TemporaryDirectory temporary("binjad-integrity-recovery");
    const auto path = temporary.path / "tokens.json";
    MemoryCredentialStore credentials;
    binjad::security::IntegrityFile original(credentials, path, "tokens-integrity");
    const auto loaded = original.LoadOrCreate("old\n", {});
    ASSERT_TRUE(loaded.contents.has_value()) << loaded.error;
    credentials.failWrite = credentials.writes + 2;
    EXPECT_NE(original.Replace("new\n").find("cannot finalize"), std::string::npos);
    credentials.failWrite.reset();

    binjad::security::IntegrityFile reopened(credentials, path, "tokens-integrity");
    const auto recovered = reopened.LoadOrCreate("unused\n", {});
    ASSERT_TRUE(recovered.contents.has_value());
    EXPECT_EQ(*recovered.contents, "new\n");
}

TEST(SecurityTest, RejectsInsecurePrivateFilePermissions)
{
    TemporaryDirectory temporary("binjad-integrity-mode");
    const auto path = temporary.path / "tokens.json";
    MemoryCredentialStore credentials;
    binjad::security::IntegrityFile original(credentials, path, "tokens-integrity");
    const auto loaded = original.LoadOrCreate("{}\n", {});
    ASSERT_TRUE(loaded.contents.has_value()) << loaded.error;
    ASSERT_EQ(::chmod(path.c_str(), 0644), 0);

    binjad::security::IntegrityFile reopened(credentials, path, "tokens-integrity");
    const auto result = reopened.LoadOrCreate("{}\n", {});
    EXPECT_FALSE(result.contents.has_value());
    EXPECT_NE(result.error.find("group or other"), std::string::npos);
}

TEST(SecurityTest, CopiesSymlinkedRegularFileIntoPrivateWorkingStorage)
{
    TemporaryDirectory temporary("binjad-private-copy");
    const auto source = temporary.path / "source.bin";
    const auto link = temporary.path / "link.bin";
    const auto destination = temporary.path / "private" / "copy.bin";
    ASSERT_TRUE(std::filesystem::create_directories(temporary.path));
    {
        std::ofstream stream(source, std::ios::binary);
        ASSERT_TRUE(stream);
        stream << "private copy contents";
    }
    ASSERT_EQ(::symlink(source.c_str(), link.c_str()), 0);
    const auto copied = binjad::platform::CopyRegularFilePrivate(link, destination);
    ASSERT_TRUE(copied.bytesCopied.has_value()) << copied.error;
    EXPECT_EQ(*copied.bytesCopied, 21U);
    const auto contents = binjad::platform::ReadPrivateFile(destination);
    ASSERT_TRUE(contents.contents.has_value()) << contents.error;
    EXPECT_EQ(*contents.contents, "private copy contents");
    struct stat metadata{};
    ASSERT_EQ(::stat(destination.c_str(), &metadata), 0);
    EXPECT_EQ(metadata.st_mode & 0777, 0600);
}

TEST(SecurityTest, AtomicallyInstallsWithoutOverwritingUnrelatedDestination)
{
    TemporaryDirectory temporary("binjad-atomic-install");
    const auto source = temporary.path / "source.bndb";
    const auto destination = temporary.path / "destination.bndb";
    ASSERT_TRUE(binjad::platform::CreatePrivateFileIfAbsent(source, "first").created);
    auto installed = binjad::platform::InstallRegularFileAtomically(
        source, destination, false);
    ASSERT_TRUE(installed.installed) << installed.error;
    EXPECT_FALSE(binjad::platform::InstallRegularFileAtomically(
        source, destination, false).installed);
    ASSERT_TRUE(binjad::platform::ReplacePrivateFile(source, "second").installed);
    installed = binjad::platform::InstallRegularFileAtomically(source, destination, true);
    ASSERT_TRUE(installed.installed) << installed.error;
    const auto contents = binjad::platform::ReadPrivateFile(destination);
    ASSERT_TRUE(contents.contents);
    EXPECT_EQ(*contents.contents, "second");
}
#endif
