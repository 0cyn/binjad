#include "binjad/portal/api.hpp"
#include "binjad/http/portal_routes.hpp"
#include "binjad/platform/paths.hpp"

#include <rapidjsonwrapper.h>
#include <gtest/gtest.h>

#include <filesystem>
#include <future>
#include <memory>
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

std::string Base64(std::string_view value)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    for (std::size_t offset = 0; offset < value.size(); offset += 3)
    {
        std::uint32_t bytes = static_cast<unsigned char>(value[offset]) << 16;
        if (offset + 1 < value.size())
            bytes |= static_cast<unsigned char>(value[offset + 1]) << 8;
        if (offset + 2 < value.size())
            bytes |= static_cast<unsigned char>(value[offset + 2]);
        output.push_back(alphabet[(bytes >> 18) & 0x3f]);
        output.push_back(alphabet[(bytes >> 12) & 0x3f]);
        output.push_back(offset + 1 < value.size() ? alphabet[(bytes >> 6) & 0x3f] : '=');
        output.push_back(offset + 2 < value.size() ? alphabet[bytes & 0x3f] : '=');
    }
    return output;
}

#if !defined(_WIN32)
struct Fixture
{
    explicit Fixture(bool unauthenticated = false)
        : path(std::filesystem::temp_directory_path() /
            ("binjad-portal-api-" + std::to_string(::getpid()))),
          config(MakeConfig(unauthenticated)),
          accounts(credentials, path / "accounts.json", {32, 1, 1, 16, 32}),
          tokens(credentials, path / "tokens.json"), bootstrap(credentials),
          service(config, accounts, tokens, bootstrap, [] { return 100; }),
          api(config, service, path / "config.json")
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        EXPECT_TRUE(accounts.Load().empty());
        EXPECT_TRUE(tokens.Load().empty());
        EXPECT_TRUE(bootstrap.Load().empty());
    }

    static binjad::Config MakeConfig(bool unauthenticated)
    {
        binjad::Config config;
        config.http.allowedOrigins = {"http://127.0.0.1:8712"};
        config.http.veryDangerousUnauthenticatedPortal = unauthenticated;
        return config;
    }
    ~Fixture()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    std::string Authorization() const
    {
        return "Basic " + Base64("Admin:ninebytes");
    }

    MemoryCredentialStore credentials;
    std::filesystem::path path;
    binjad::Config config;
    binjad::security::AccountRegistry accounts;
    binjad::security::TokenRegistry tokens;
    binjad::security::BootstrapCredential bootstrap;
    binjad::portal::Service service;
    binjad::portal::Api api;
};
#endif
}

#if !defined(_WIN32)
TEST(PortalApiTest, ExposesBootstrapStateAndCreatesAdministrator)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    auto status = fixture.api.Handle(
        {binjad::http::Method::Get, "/portal/api/bootstrap"});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find("true"), std::string::npos);
    auto created = fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"});
    EXPECT_EQ(created.status, 201);
    EXPECT_NE(created.body.find("portal-admin"), std::string::npos);
    status = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/bootstrap"});
    EXPECT_NE(status.body.find("false"), std::string::npos);
}

TEST(PortalApiTest, AuthenticatesAccountCrudAndTokenIssuance)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    const auto authorization = fixture.Authorization();
    const auto accounts = fixture.api.Handle(
        {binjad::http::Method::Get, "/portal/api/accounts", {}, authorization});
    EXPECT_EQ(accounts.status, 200);
    EXPECT_NE(accounts.body.find("Admin"), std::string::npos);
    const auto issued = fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/tokens", {}, authorization,
        R"({"label":"automation","ttl_seconds":60})"});
    EXPECT_EQ(issued.status, 201);
    EXPECT_NE(issued.body.find(R"("token":")"), std::string::npos);
    EXPECT_NE(issued.body.find(R"("expires_at":160)"), std::string::npos);
}

TEST(PortalApiTest, RejectsBadOriginCredentialsAndOversizedBodies)
{
    Fixture fixture;
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/accounts", "https://evil.example"}).status, 403);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/accounts"}).status, 401);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(binjad::portal::Api::kMaxBodyBytes + 1, 'x')}).status, 413);
}

TEST(PortalApiTest, ServesMinimalBrowserPage)
{
    Fixture fixture;
    const auto page = fixture.api.Page();
    EXPECT_EQ(page.status, 200);
    EXPECT_EQ(page.contentType, "text/html; charset=utf-8");
    EXPECT_NE(page.body.find("<title>binjad</title>"), std::string::npos);
    EXPECT_NE(page.body.find("control room"), std::string::npos);
    EXPECT_NE(page.body.find("Issue bearer token"), std::string::npos);
    EXPECT_NE(page.body.find("Daemon configuration"), std::string::npos);
    EXPECT_NE(page.body.find("Local project catalog"), std::string::npos);
    EXPECT_NE(page.body.find("Context View"), std::string::npos);
    EXPECT_NE(page.body.find("Tool Calls"), std::string::npos);
    EXPECT_NE(page.body.find("Enabled Tools"), std::string::npos);
    EXPECT_EQ(page.body.find(">Plugins<"), std::string::npos);
    EXPECT_NE(page.body.find("Exact MCP wire context"), std::string::npos);
    EXPECT_NE(page.body.find("/portal/app.css"), std::string::npos);
    EXPECT_EQ(page.body.find("onclick="), std::string::npos);
    const auto css = fixture.api.Asset("app.css");
    EXPECT_EQ(css.status, 200);
    EXPECT_EQ(css.contentType, "text/css; charset=utf-8");
    EXPECT_NE(css.body.find("--accent"), std::string::npos);
    const auto javascript = fixture.api.Asset("app.js");
    EXPECT_EQ(javascript.status, 200);
    EXPECT_EQ(javascript.contentType, "text/javascript; charset=utf-8");
    EXPECT_NE(javascript.body.find("loadConfiguration"), std::string::npos);
    EXPECT_NE(javascript.body.find("renderEnabledToolLists"), std::string::npos);
    EXPECT_NE(javascript.body.find("Core Workflow"), std::string::npos);
    EXPECT_EQ(fixture.api.Asset("secret.txt").status, 404);
}

TEST(PortalApiTest, ServesAuthenticatedMcpContextAndToolDocumentation)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    fixture.api.SetMcpDocumentationProviders(
        [](auto version, auto role, std::string_view client) {
            return std::string(R"({"protocolVersion":")") +
                std::string(binjad::mcp::ToString(version)) +
                R"(","role":")" +
                (role == binjad::security::TokenRole::Admin ? "admin" : "user") +
                R"(","client":")" + std::string(client) + R"("})";
        },
        [](auto version, auto role) {
            return std::string(R"({"protocolVersion":")") +
                std::string(binjad::mcp::ToString(version)) +
                R"(","role":")" +
                (role == binjad::security::TokenRole::Admin ? "admin" : "user") + R"("})";
        });
    const auto authorization = fixture.Authorization();
    const auto context = fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/mcp/context", {}, authorization,
        R"({"protocol":"2026-07-28","role":"user","client":"local_binjad"})"});
    EXPECT_EQ(context.status, 200);
    EXPECT_NE(context.body.find(R"("client":"local_binjad")"), std::string::npos);
    const auto tools = fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/mcp/tools", {}, authorization,
        R"({"protocol":"2025-03-26","role":"admin"})"});
    EXPECT_EQ(tools.status, 200);
    EXPECT_NE(tools.body.find("2025-03-26"), std::string::npos);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/mcp/context", {}, authorization,
        R"({"protocol":"not-a-version","role":"admin","client":"binjad"})"}).status, 400);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/mcp/context", {}, authorization,
        R"({"protocol":"2026-07-28","role":"admin","client":"bad name"})"}).status, 400);
}

TEST(PortalApiTest, PersistsValidatedConfigurationAndReportsRuntimeStatus)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    const auto configPath = fixture.path / "config.json";
    ASSERT_TRUE(binjad::platform::CreatePrivateFileIfAbsent(
        configPath, binjad::DefaultConfigJson()).created);
    fixture.api.SetRuntimeStatusProvider([] {
        return binjad::portal::RuntimeStatus{2, 3, 4, 5, 12, 9, 6, 2, 1};
    });
    fixture.api.SetProjectListCallback([] {
        return std::vector<binjad::portal::ProjectSummary>{
            {"ProjectRef", "Example", "Local fixture"}};
    });
    const auto authorization = fixture.Authorization();

    const auto status = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/status", {}, authorization});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find(R"("worker_budget":9)"), std::string::npos);
    const auto projects = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/projects", {}, authorization});
    EXPECT_EQ(projects.status, 200);
    EXPECT_NE(projects.body.find("Local fixture"), std::string::npos);
    const auto invalid = fixture.api.Handle({binjad::http::Method::Put,
        "/portal/api/config", {}, authorization,
        R"({"cpu":{"percentage":0},"jobs":{"cancellation_grace_seconds":0}})"});
    EXPECT_EQ(invalid.status, 400);
    EXPECT_NE(invalid.body.find("$.cpu.percentage"), std::string::npos);
    EXPECT_NE(invalid.body.find("$.jobs.cancellation_grace_seconds"), std::string::npos);

    const auto updated = fixture.api.Handle({binjad::http::Method::Put,
        "/portal/api/config", {}, authorization,
        R"({"mode":"local","cpu":{"percentage":55}})"});
    EXPECT_EQ(updated.status, 200);
    EXPECT_NE(updated.body.find(R"("restart_required":true)"), std::string::npos);
    const auto loaded = binjad::LoadConfig(configPath);
    ASSERT_TRUE(loaded.config);
    EXPECT_EQ(loaded.config->mode, binjad::Mode::Local);
    EXPECT_EQ(loaded.config->cpu.percentage, 55);
    const auto configuration = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/config", {}, authorization});
    EXPECT_EQ(configuration.status, 200);
    EXPECT_NE(configuration.body.find(R"("percentage":55)"), std::string::npos);
}

TEST(PortalApiTest, AcceptsIssuedAdminBearerForPanelAdministration)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    const auto issued = fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/tokens", {}, fixture.Authorization(), R"({"label":"panel"})"});
    ASSERT_EQ(issued.status, 201);
    rapidjson::Document document;
    document.Parse(issued.body.data(), issued.body.size());
    ASSERT_FALSE(document.HasParseError());
    const std::string token = document["result"]["token"].GetString();
    const auto bearer = "Bearer " + token;
    const auto status = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/status", {}, bearer});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find("Admin"), std::string::npos);
    const auto accounts = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/accounts", {}, bearer});
    EXPECT_EQ(accounts.status, 200);
}

TEST(PortalApiTest, DangerousFlagExplicitlyBypassesPortalAuthentication)
{
    Fixture fixture(true);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/status"}).status, 401);
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    const auto status = fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/status"});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find("Admin"), std::string::npos);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Get,
        "/portal/api/accounts"}).status, 200);
}

TEST(PortalApiTest, DrogonAdapterServesPageAndDispatchesApi)
{
    Fixture fixture;
    auto api = std::shared_ptr<binjad::portal::Api>(&fixture.api, [](auto*) {});
    binjad::http::PortalRoutes routes(fixture.config, std::move(api));
    auto pageRequest = drogon::HttpRequest::newHttpRequest();
    pageRequest->setMethod(drogon::Get);
    drogon::HttpResponsePtr page;
    routes.HandlePage(pageRequest, {}, [&](const auto& response) { page = response; });
    ASSERT_TRUE(page);
    EXPECT_EQ(page->getStatusCode(), drogon::k200OK);

    auto assetRequest = drogon::HttpRequest::newHttpRequest();
    assetRequest->setMethod(drogon::Get);
    assetRequest->setPath("/portal/app.js");
    drogon::HttpResponsePtr asset;
    routes.HandleAsset(assetRequest, {}, [&](const auto& response) { asset = response; });
    ASSERT_TRUE(asset);
    EXPECT_EQ(asset->getStatusCode(), drogon::k200OK);
    EXPECT_EQ(asset->contentTypeString(), "text/javascript; charset=utf-8");

    auto apiRequest = drogon::HttpRequest::newHttpRequest();
    apiRequest->setMethod(drogon::Get);
    apiRequest->setPath("/portal/api/accounts");
    std::promise<drogon::HttpResponsePtr> completion;
    auto result = completion.get_future();
    routes.HandleApi(apiRequest, {},
        [&](const auto& response) { completion.set_value(response); });
    const auto response = result.get();
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k401Unauthorized);
}

TEST(PortalApiTest, DeletesLocalProjectOnlyWithAdminConfirmation)
{
    Fixture fixture;
    const auto credential = fixture.bootstrap.Mint();
    ASSERT_TRUE(credential.credential);
    ASSERT_EQ(fixture.api.Handle({binjad::http::Method::Post,
        "/portal/api/bootstrap", {}, {},
        std::string(R"({"credential":")") + *credential.credential +
            R"(","username":"Admin","password":"ninebytes"})"}).status, 201);
    int deletions = 0;
    fixture.api.SetProjectDeleteCallback([&](std::string_view project) {
        ++deletions;
        if (project == "BusyProject")
            return binjad::portal::Result<bool>{{}, "project has open analysis handles"};
        if (project != "ProjectRef")
            return binjad::portal::Result<bool>{{}, "project not found"};
        return binjad::portal::Result<bool>{true, {}};
    });
    const auto authorization = fixture.Authorization();
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Delete,
        "/portal/api/projects/ProjectRef", {}, authorization,
        R"({"delete":false})"}).status, 400);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Delete,
        "/portal/api/projects/BusyProject", {}, authorization,
        R"({"delete":true})"}).status, 409);
    const auto deleted = fixture.api.Handle({binjad::http::Method::Delete,
        "/portal/api/projects/ProjectRef", {}, authorization,
        R"({"delete":true})"});
    EXPECT_EQ(deleted.status, 200);
    EXPECT_NE(deleted.body.find(R"("deleted":true)"), std::string::npos);
    EXPECT_EQ(deletions, 2);
}
#endif
