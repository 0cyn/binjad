#include "binjad/portal/Api.hpp"
#include "binjad/http/PortalRoutes.hpp"
#include "binjad/platform/Paths.hpp"

#include <rapidjsonwrapper.h>
#include <gtest/gtest.h>

#include <algorithm>
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

std::string Base64(std::string_view value)
{
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
    Fixture()
        : path(std::filesystem::temp_directory_path() / ("binjad-portal-api-" + std::to_string(::getpid()))),
          config(MakeConfig(path / "config.json")),
          accounts(credentials, path / "accounts.json", {32, 1, 1, 16, 32}), tokens(credentials, path / "tokens.json"),
          service(accounts, tokens, [] { return 100; }), api(config, service, path / "config.json")
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        EXPECT_TRUE(accounts.Load().empty());
        EXPECT_TRUE(tokens.Load().empty());
    }

    static binjad::Config MakeConfig(const std::filesystem::path& path)
    {
        auto parsed = binjad::ParseConfig(binjad::DefaultConfigJson(), path);
        return std::move(*parsed.config);
    }

    ~Fixture()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    std::string Authorization() const { return "Basic " + Base64("Admin:ninebytes"); }

    void Setup()
    {
        ASSERT_EQ(api.Handle({binjad::http::Method::Post, "/portal/api/setup", {}, {},
                                 R"({"username":"Admin","password":"ninebytes"})"})
                      .status,
            201);
    }

    MemoryCredentialStore credentials;
    std::filesystem::path path;
    binjad::Config config;
    binjad::security::AccountRegistry accounts;
    binjad::security::TokenRegistry tokens;
    binjad::portal::Service service;
    binjad::portal::Api api;
};
#endif
} // namespace

#if !defined(_WIN32)
TEST(PortalApiTest, ExposesFirstRunSetupAndCreatesOneAccount)
{
    Fixture fixture;
    auto status = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/setup"});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find("true"), std::string::npos);
    fixture.Setup();
    status = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/setup"});
    EXPECT_NE(status.body.find("false"), std::string::npos);
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Post, "/portal/api/setup", {}, {},
                      R"({"username":"Other","password":"otherpass"})"})
                  .status,
        409);
}

TEST(PortalApiTest, ManagesPasswordAndSingleTokenWithBasicAuthentication)
{
    Fixture fixture;
    fixture.Setup();
    const auto authorization = fixture.Authorization();
    const auto account = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/account", {}, authorization});
    EXPECT_EQ(account.status, 200);
    EXPECT_NE(account.body.find("Admin"), std::string::npos);

    const auto issued = fixture.api.Handle(
        {binjad::http::Method::Post, "/portal/api/token", {}, authorization, R"({"ttl_seconds":60})"});
    EXPECT_EQ(issued.status, 201);
    EXPECT_NE(issued.body.find(R"("token":")"), std::string::npos);
    EXPECT_NE(issued.body.find(R"("expires_at":160)"), std::string::npos);
    const auto rotated = fixture.api.Handle(
        {binjad::http::Method::Post, "/portal/api/token", {}, authorization, R"({"ttl_seconds":0})"});
    EXPECT_EQ(rotated.status, 201);
    EXPECT_NE(rotated.body.find(R"("expires_at":0)"), std::string::npos);
    EXPECT_EQ(fixture.tokens.Records().size(), 1U);

    const auto changed = fixture.api.Handle(
        {binjad::http::Method::Patch, "/portal/api/account", {}, authorization, R"({"password":"newsecret"})"});
    EXPECT_EQ(changed.status, 200);
    EXPECT_EQ(fixture.api.Handle({binjad::http::Method::Get, "/portal/api/status", {}, authorization}).status, 401);
    const auto updatedAuthorization = "Basic " + Base64("Admin:newsecret");
    EXPECT_EQ(
        fixture.api.Handle({binjad::http::Method::Get, "/portal/api/status", {}, updatedAuthorization}).status, 200);
}

TEST(PortalApiTest, RejectsBadOriginCredentialsBearerAndOversizedBodies)
{
    Fixture fixture;
    fixture.Setup();
    EXPECT_EQ(
        fixture.api.Handle({binjad::http::Method::Get, "/portal/api/account", "https://evil.example"}).status, 403);
    const auto missing = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/account"});
    EXPECT_EQ(missing.status, 401);
    EXPECT_EQ(std::find_if(missing.headers.begin(), missing.headers.end(),
                  [](const auto& header) { return header.first == "WWW-Authenticate"; }),
        missing.headers.end());
    EXPECT_EQ(
        fixture.api.Handle({binjad::http::Method::Get, "/portal/api/account", {}, "Bearer deadbeef"}).status, 401);
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Post, "/portal/api/setup", {}, {},
                      std::string(binjad::portal::Api::kMaxBodyBytes + 1, 'x')})
                  .status,
        413);
}

TEST(PortalApiTest, ServesSingleAccountBrowserPage)
{
    Fixture fixture;
    const auto page = fixture.api.Page();
    EXPECT_EQ(page.status, 200);
    EXPECT_NE(page.body.find(R"(<div class="brand">binja'd</div>)"), std::string::npos);
    EXPECT_EQ(page.body.find("control room"), std::string::npos);
    EXPECT_NE(page.body.find(R"(<form id="login-form">)"), std::string::npos);
    EXPECT_NE(page.body.find(R"(<button class="primary" type="submit">Log in</button>)"), std::string::npos);
    EXPECT_NE(page.body.find("Create the account"), std::string::npos);
    EXPECT_NE(page.body.find("Create or rotate MCP token"), std::string::npos);
    EXPECT_NE(page.body.find("Change password"), std::string::npos);
    EXPECT_EQ(page.body.find("Bootstrap credential"), std::string::npos);
    EXPECT_EQ(page.body.find("Create account</h2>"), std::string::npos);
    EXPECT_EQ(page.body.find("Daemon configuration"), std::string::npos);
    EXPECT_NE(page.body.find("Reload from disk"), std::string::npos);
    EXPECT_NE(page.body.find("Updates immediately on change"), std::string::npos);
    EXPECT_NE(page.body.find("This is what a model sees as formatted by opencode"), std::string::npos);
    EXPECT_EQ(page.body.find("Exact MCP wire context"), std::string::npos);
    EXPECT_NE(page.body.find("Local project catalog"), std::string::npos);
    EXPECT_NE(page.body.find("cfg-project-registration"), std::string::npos);
    EXPECT_EQ(page.body.find("onclick="), std::string::npos);
    EXPECT_EQ(fixture.api.Asset("app.css").status, 200);
    EXPECT_EQ(fixture.api.Asset("app.js").status, 200);
    EXPECT_EQ(fixture.api.Asset("binjad.png").status, 200);
    EXPECT_EQ(fixture.api.Asset("secret.txt").status, 404);
}

TEST(PortalApiTest, ServesAdminMcpDocumentationWithoutRoleSelection)
{
    Fixture fixture;
    fixture.Setup();
    fixture.api.SetMcpDocumentationProviders(
        [](auto version, auto role, std::string_view client)
        {
            EXPECT_EQ(role, binjad::security::TokenRole::Admin);
            return std::string(R"({"protocolVersion":")") + std::string(binjad::mcp::ToString(version))
                + R"(","client":")" + std::string(client) + R"("})";
        },
        [](auto version, auto role)
        {
            EXPECT_EQ(role, binjad::security::TokenRole::Admin);
            return std::string(R"({"protocolVersion":")") + std::string(binjad::mcp::ToString(version)) + R"("})";
        });
    const auto context = fixture.api.Handle({binjad::http::Method::Post, "/portal/api/mcp/context", {},
        fixture.Authorization(), R"({"protocol":"2026-07-28","client":"local_binjad"})"});
    EXPECT_EQ(context.status, 200);
    EXPECT_NE(context.body.find("local_binjad"), std::string::npos);
    const auto tools = fixture.api.Handle({binjad::http::Method::Post, "/portal/api/mcp/tools", {},
        fixture.Authorization(), R"({"protocol":"2025-03-26"})"});
    EXPECT_EQ(tools.status, 200);
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Post, "/portal/api/mcp/tools", {}, fixture.Authorization(),
                      R"({"protocol":"2025-03-26","role":"user"})"})
                  .status,
        400);
}

TEST(PortalApiTest, PersistsValidatedConfigurationAndReportsRuntimeStatus)
{
    Fixture fixture;
    fixture.Setup();
    const auto configPath = fixture.path / "config.json";
    ASSERT_TRUE(binjad::platform::CreatePrivateFileIfAbsent(configPath, binjad::DefaultConfigJson()).created);
    fixture.api.SetRuntimeStatusProvider([] { return binjad::portal::RuntimeStatus{2, 3, 4, 5, 12, 9, 6, 2, 1}; });
    fixture.api.SetProjectListCallback(
        [] { return std::vector<binjad::portal::ProjectSummary>{{"ProjectRef", "Example", "Local fixture"}}; });
    const auto authorization = fixture.Authorization();
    const auto status = fixture.api.Handle({binjad::http::Method::Get, "/portal/api/status", {}, authorization});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find(R"("mode":"local")"), std::string::npos);
    EXPECT_NE(status.body.find(R"("worker_budget":9)"), std::string::npos);
    EXPECT_NE(status.body.find("Local fixture"), std::string::npos);
    EXPECT_NE(status.body.find(R"("token":null)"), std::string::npos);
    EXPECT_NE(status.body.find(R"("function_analysis":true)"), std::string::npos);
    EXPECT_EQ(
        fixture.api
            .Handle({binjad::http::Method::Put, "/portal/api/config", {}, authorization, R"({"cpu":{"percentage":0}})"})
            .status,
        400);
    const auto updated = fixture.api.Handle(
        {binjad::http::Method::Put, "/portal/api/config", {}, authorization, R"({"cpu":{"percentage":55}})"});
    EXPECT_EQ(updated.status, 200);
    const auto loaded = binjad::LoadConfig(configPath);
    ASSERT_TRUE(loaded.config);
    EXPECT_EQ(loaded.config->cpu.percentage, 55);
}

TEST(PortalApiTest, HotAppliesAndPersistsToolPackChangesWithoutRequiringRestart)
{
    Fixture fixture;
    fixture.Setup();
    const auto configPath = fixture.path / "config.json";
    ASSERT_TRUE(binjad::platform::CreatePrivateFileIfAbsent(configPath, binjad::DefaultConfigJson()).created);
    std::optional<binjad::ToolConfig> applied;
    fixture.api.SetToolConfigCallback([&](const auto& tools) { applied = tools; });

    const auto updated = fixture.api.Handle({binjad::http::Method::Patch, "/portal/api/tools", {},
        fixture.Authorization(), R"({"function_analysis":false,"header_parsing":false,"url_generation":false})"});
    EXPECT_EQ(updated.status, 200);
    EXPECT_NE(updated.body.find(R"("function_analysis":false)"), std::string::npos);
    EXPECT_NE(updated.body.find(R"("restart_required":false)"), std::string::npos);
    ASSERT_TRUE(applied);
    EXPECT_FALSE(applied->functionAnalysis);
    EXPECT_FALSE(applied->headerParsing);
    EXPECT_FALSE(applied->urlGeneration);

    const auto loaded = binjad::LoadConfig(configPath);
    ASSERT_TRUE(loaded.config);
    EXPECT_FALSE(loaded.config->tools.functionAnalysis);
    EXPECT_FALSE(loaded.config->tools.headerParsing);
    EXPECT_FALSE(loaded.config->tools.urlGeneration);
    const auto status = fixture.api.Handle(
        {binjad::http::Method::Get, "/portal/api/tools", {}, fixture.Authorization()});
    EXPECT_EQ(status.status, 200);
    EXPECT_NE(status.body.find(R"("function_analysis":false)"), std::string::npos);
    EXPECT_NE(status.body.find(R"("url_generation":false)"), std::string::npos);

    const auto saved = fixture.api.Handle({binjad::http::Method::Put, "/portal/api/config", {},
        fixture.Authorization(), R"({"tools":{"function_analysis":true}})"});
    EXPECT_EQ(saved.status, 200);
    EXPECT_NE(saved.body.find(R"("restart_required":false)"), std::string::npos);
    ASSERT_TRUE(applied);
    EXPECT_TRUE(applied->functionAnalysis);
}

TEST(PortalApiTest, CreatesProjectsThroughThePortalCallback)
{
    Fixture fixture;
    fixture.Setup();
    fixture.api.SetProjectCreateCallback(
        [](std::string name, std::optional<std::string> path, std::string description)
        {
            EXPECT_EQ(name, "Example");
            EXPECT_EQ(path, "nested/example.bnpr");
            EXPECT_EQ(description, "Portal project");
            return binjad::portal::Result<binjad::portal::ProjectSummary>{
                binjad::portal::ProjectSummary{"ProjectRef", std::move(name), std::move(description)}, {}};
        });
    const auto created = fixture.api.Handle({binjad::http::Method::Post, "/portal/api/projects", {},
        fixture.Authorization(),
        R"({"name":"Example","path":"nested/example.bnpr","description":"Portal project"})"});
    EXPECT_EQ(created.status, 201);
    EXPECT_NE(created.body.find(R"("project":"ProjectRef")"), std::string::npos);
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

    auto apiRequest = drogon::HttpRequest::newHttpRequest();
    apiRequest->setMethod(drogon::Get);
    apiRequest->setPath("/portal/api/account");
    std::promise<drogon::HttpResponsePtr> completion;
    auto result = completion.get_future();
    routes.HandleApi(apiRequest, {}, [&](const auto& response) { completion.set_value(response); });
    EXPECT_EQ(result.get()->getStatusCode(), drogon::k401Unauthorized);
}

TEST(PortalApiTest, DeletesLocalProjectOnlyWithConfirmation)
{
    Fixture fixture;
    fixture.Setup();
    int deletions = 0;
    fixture.api.SetProjectDeleteCallback(
        [&](std::string_view project)
        {
            ++deletions;
            if (project == "BusyProject")
                return binjad::portal::Result<bool>{{}, "project has open analysis handles"};
            return project == "ProjectRef" ? binjad::portal::Result<bool>{true, {}}
                                           : binjad::portal::Result<bool>{{}, "project not found"};
        });
    const auto authorization = fixture.Authorization();
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Delete, "/portal/api/projects/ProjectRef", {}, authorization,
                      R"({"delete":false})"})
                  .status,
        400);
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Delete, "/portal/api/projects/BusyProject", {}, authorization,
                      R"({"delete":true})"})
                  .status,
        409);
    EXPECT_EQ(fixture.api
                  .Handle({binjad::http::Method::Delete, "/portal/api/projects/ProjectRef", {}, authorization,
                      R"({"delete":true})"})
                  .status,
        200);
    EXPECT_EQ(deletions, 2);
}
#endif
