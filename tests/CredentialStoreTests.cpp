#include "binjad/Config.hpp"
#include "binjad/platform/Paths.hpp"
#include "binjad/security/AccountRegistry.hpp"
#include "binjad/security/CredentialStore.hpp"
#include "binjad/security/CredentialVault.hpp"
#include "binjad/security/TokenRegistry.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace {
	class TemporaryDirectory
	{
	public:
		TemporaryDirectory()
		{
			std::string pattern =
				(std::filesystem::canonical(std::filesystem::temp_directory_path()) / "binjad-credentials-XXXXXX")
					.string();
			if (!::mkdtemp(pattern.data()))
				throw std::runtime_error("mkdtemp failed: " + std::string(std::strerror(errno)));
			path_ = std::move(pattern);
		}

		~TemporaryDirectory()
		{
			std::error_code error;
			std::filesystem::remove_all(path_, error);
		}

		const std::filesystem::path& Path() const { return path_; }

	private:
		std::filesystem::path path_;
	};

	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}

	void TestParsing()
	{
		const auto valid =
			binjad::security::ParseCredentialVault(R"json({"version":1,"values":{"alpha":"one","beta":"two"}})json");
		Require(valid.values.has_value(), "valid vault did not parse");
		Require(valid.values->at("alpha") == "one", "valid vault value changed");

		Require(!binjad::security::ParseCredentialVault(R"json({"version":1,"version":1,"values":{}})json").values,
			"duplicate vault field was accepted");
		Require(!binjad::security::ParseCredentialVault(R"json({"version":1,"values":{},"extra":true})json").values,
			"unknown vault field was accepted");
		Require(!binjad::security::ParseCredentialVault("not-json").values, "malformed vault was accepted");
	}

	void TestLifecycleAndLock()
	{
		TemporaryDirectory directory;
		const auto config = directory.Path() / "config.json";
		const auto vault = binjad::security::FileCredentialStorePath(config);
		{
			auto store = binjad::security::CreateCredentialStore(config);
			const auto missing = store->Read("alpha");
			Require(missing.error.empty() && !missing.value, "missing credential read failed");
			Require(store->Write("alpha", "one").empty(), "credential write failed");
			const auto value = store->Read("alpha");
			Require(value.value && *value.value == "one", "credential read did not return written value");

			bool rejectedSecondStore = false;
			try
			{
				auto second = binjad::security::CreateCredentialStore(config);
				(void)second;
			}
			catch (const std::runtime_error&)
			{
				rejectedSecondStore = true;
			}
			Require(rejectedSecondStore, "second credential-store owner was not rejected");
			Require(store->Remove("alpha").empty(), "credential removal failed");
		}

		struct stat metadata {};
		Require(::lstat(vault.c_str(), &metadata) == 0, "credential vault was not created");
		Require(S_ISREG(metadata.st_mode), "credential vault is not a regular file");
		Require((metadata.st_mode & 0777) == 0600, "credential vault mode is not 0600");
		Require(metadata.st_nlink == 1, "credential vault has an unexpected hard link");

		auto reopened = binjad::security::CreateCredentialStore(config);
		const auto missing = reopened->Read("alpha");
		Require(missing.error.empty() && !missing.value, "removed credential reappeared after reload");
	}

	void TestAuthenticationPersistence()
	{
		TemporaryDirectory directory;
		const auto config = directory.Path() / "service.json";
		const auto accountsPath = directory.Path() / "accounts.json";
		const auto tokensPath = directory.Path() / "tokens.json";
		const std::string password = "correct horse battery staple";
		std::string bearer;
		std::string accountId;

		{
			auto store = binjad::security::CreateCredentialStore(config);
			binjad::security::TokenRegistry tokens(*store, tokensPath);
			binjad::security::AccountRegistry accounts(
				*store, accountsPath, binjad::security::Argon2Profile {32, 1, 1, 8, 16});
			Require(tokens.Load().empty(), "initial token-registry load failed");
			Require(accounts.Load().empty(), "initial account-registry load failed");
			const auto account = accounts.CreateInitial({"parallels", password, 100});
			Require(account.record.has_value(), "account creation failed");
			accountId = account.record->id;
			const auto issued =
				tokens.ReplaceForIssuer({accountId, binjad::security::TokenRole::Admin, "test", 101, std::nullopt});
			Require(issued.token.has_value(), "token creation failed");
			bearer = *issued.token;

			const auto vault = binjad::platform::ReadPrivateFile(binjad::security::FileCredentialStorePath(config));
			Require(vault.contents.has_value(), "credential vault could not be read");
			Require(
				vault.contents->find(password) == std::string::npos, "credential vault contains plaintext password");
			Require(
				vault.contents->find(bearer) == std::string::npos, "credential vault contains plaintext bearer token");
			Require(vault.contents->find("$argon2id$") != std::string::npos,
				"credential vault does not contain an Argon2id verifier");
		}

		{
			auto store = binjad::security::CreateCredentialStore(config);
			binjad::security::TokenRegistry tokens(*store, tokensPath);
			binjad::security::AccountRegistry accounts(
				*store, accountsPath, binjad::security::Argon2Profile {32, 1, 1, 8, 16});
			Require(tokens.Load().empty(), "reloaded token registry failed integrity validation");
			Require(accounts.Load().empty(), "reloaded account registry failed integrity validation");
			const auto authentication = accounts.Authenticate("parallels", password);
			Require(authentication.result == binjad::security::PasswordVerification::Match,
				"reloaded password verifier did not authenticate");
			Require(tokens.Authenticator().Authenticate(bearer, 102).has_value(),
				"reloaded token verifier did not authenticate");
		}
	}

	void TestFileValidation()
	{
		{
			TemporaryDirectory directory;
			const auto real = directory.Path() / "real";
			const auto alias = directory.Path() / "alias";
			std::filesystem::create_directory(real);
			Require(::chmod(real.c_str(), 0700) == 0, "could not secure symlinked credential directory");
			Require(::symlink(real.c_str(), alias.c_str()) == 0, "could not create credential-directory symlink");
			bool rejected = false;
			try
			{
				auto store = binjad::security::CreateCredentialStore(alias / "config.json");
				(void)store;
			}
			catch (const std::runtime_error&)
			{
				rejected = true;
			}
			Require(rejected, "symlinked credential directory was accepted");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "permissions.json";
			const auto vault = binjad::security::FileCredentialStorePath(config);
			Require(binjad::platform::CreatePrivateFileIfAbsent(vault, binjad::security::SerializeCredentialVault({}))
						.error.empty(),
				"could not create permission-test vault");
			Require(::chmod(vault.c_str(), 0644) == 0, "could not weaken permission-test vault");
			auto store = binjad::security::CreateCredentialStore(config);
			Require(!store->Read("test").error.empty(), "group-readable credential vault was accepted");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "hardlink.json";
			const auto vault = binjad::security::FileCredentialStorePath(config);
			Require(binjad::platform::CreatePrivateFileIfAbsent(vault, binjad::security::SerializeCredentialVault({}))
						.error.empty(),
				"could not create hard-link-test vault");
			Require(::link(vault.c_str(), (directory.Path() / "second-link").c_str()) == 0,
				"could not hard-link test vault");
			auto store = binjad::security::CreateCredentialStore(config);
			Require(!store->Read("test").error.empty(), "hard-linked credential vault was accepted");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "symlink.json";
			const auto vault = binjad::security::FileCredentialStorePath(config);
			const auto target = directory.Path() / "target.json";
			Require(binjad::platform::CreatePrivateFileIfAbsent(target, binjad::security::SerializeCredentialVault({}))
						.error.empty(),
				"could not create symlink-test target");
			Require(::symlink(target.c_str(), vault.c_str()) == 0, "could not create credential-vault symlink");
			auto store = binjad::security::CreateCredentialStore(config);
			Require(!store->Read("test").error.empty(), "credential-vault symlink was accepted");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "oversized.json";
			const auto vault = binjad::security::FileCredentialStorePath(config);
			Require(binjad::platform::CreatePrivateFileIfAbsent(vault, std::string(1024 * 1024 + 1, 'x')).error.empty(),
				"could not create oversized test vault");
			auto store = binjad::security::CreateCredentialStore(config);
			Require(store->Read("test").error.find("1 MiB") != std::string::npos,
				"oversized credential vault was not rejected before parsing");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "changed.json";
			const auto vault = binjad::security::FileCredentialStorePath(config);
			auto store = binjad::security::CreateCredentialStore(config);
			Require(store->Write("alpha", "one").empty(), "could not initialize change-detection vault");
			binjad::security::CredentialVaultValues changed {{"alpha", "two"}};
			const auto replacement =
				binjad::platform::ReplacePrivateFile(vault, binjad::security::SerializeCredentialVault(changed));
			Require(replacement.installed && replacement.error.empty(), "could not replace change-detection vault");
			Require(!store->Write("beta", "three").empty(), "credential-vault replacement was not detected");
		}

		{
			TemporaryDirectory directory;
			const auto insecure = directory.Path() / "insecure";
			std::filesystem::create_directory(insecure);
			Require(::chmod(insecure.c_str(), 0777) == 0, "could not weaken credential directory");
			bool rejected = false;
			try
			{
				auto store = binjad::security::CreateCredentialStore(insecure / "config.json");
				(void)store;
			}
			catch (const std::runtime_error&)
			{
				rejected = true;
			}
			Require(rejected, "group-writable credential directory was accepted");
		}

		{
			TemporaryDirectory directory;
			const auto config = directory.Path() / "config.json";
			Require(binjad::platform::CreatePrivateFileIfAbsent(config, binjad::DefaultConfigJson()).error.empty(),
				"could not create permission-test configuration");
			Require(::chmod(config.c_str(), 0644) == 0, "could not weaken permission-test configuration");
			const auto loaded = binjad::LoadConfig(config);
			Require(!loaded.config && !loaded.errors.empty(), "group-readable startup configuration was accepted");
		}
	}
}  // namespace

int main()
{
	try
	{
		TestParsing();
		TestLifecycleAndLock();
		TestAuthenticationPersistence();
		TestFileValidation();
		std::cout << "credential store tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "credential store test failed: " << exception.what() << '\n';
		return 1;
	}
}
