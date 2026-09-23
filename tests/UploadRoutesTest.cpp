#include "binjad/http/upload_routes.hpp"

#include "binjad/platform/paths.hpp"
#include "binjad/security/crypto.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <unistd.h>

namespace
{
class FakeRequestStream final : public drogon::RequestStream
{
  public:
    void setStreamReader(drogon::RequestStreamReaderPtr value) override
    {
        reader = std::move(value);
    }
    drogon::RequestStreamReaderPtr reader;
};

struct Fixture
{
    Fixture()
        : path(std::filesystem::temp_directory_path() /
              ("binjad-upload-route-" + std::to_string(getpid()))),
          config(MakeConfig(path)),
          token(64, 'a'), authenticator(std::string(key),
              {{binjad::security::HmacSha256Hex(key, token),
                  {std::string(64, 'b'), std::string(64, 'c'),
                      binjad::security::TokenRole::Admin, "test", 1, {}}}}),
          sessions(references, std::chrono::minutes(30)), projects(references),
          uploads(config, references, sessions, projects)
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
        project = {{}, "native", "/private/Test.bnpr", "Test", {}};
        EXPECT_TRUE(projects.Upsert(project).empty());
        now = binjad::session::AnalysisSessionRegistry::Clock::now();
        session = sessions.Create(std::string(64, 'b'), 1, now);
        EXPECT_TRUE(session.session);
    }

    static binjad::Config MakeConfig(const std::filesystem::path& path)
    {
        binjad::Config config;
        config.http.publicBaseUrl = "http://127.0.0.1:8712";
        config.storage.spoolPath = path / "spool";
        config.uploads.maxBytes = 1024;
        return config;
    }
    ~Fixture()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }

    binjad::upload::UploadIssueResult Issue(std::string filename)
    {
        return uploads.Issue(std::string(64, 'b'), session.session->reference,
            project.reference, std::move(filename), 1, now);
    }

    static constexpr std::string_view key = "upload route key";
    std::filesystem::path path;
    binjad::Config config;
    std::string token;
    binjad::security::TokenAuthenticator authenticator;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions;
    binjad::project::LocalProjectRegistry projects;
    binjad::upload::UploadRegistry uploads;
    binjad::project::LocalProjectRecord project;
    binjad::session::AnalysisSessionCreateResult session;
    binjad::session::AnalysisSessionRegistry::Clock::time_point now;
};

drogon::HttpRequestPtr Request(drogon::HttpMethod method,
    std::string path, std::string_view token, std::string body = {})
{
    auto request = drogon::HttpRequest::newHttpRequest();
    request->setMethod(method);
    request->setPath(std::move(path));
    if (!token.empty())
        request->addHeader("Authorization", "Bearer " + std::string(token));
    request->setBody(std::move(body));
    return request;
}

std::string UrlPath(const std::string& url)
{
    const auto scheme = url.find("://");
    return url.substr(url.find('/', scheme + 3));
}
}

TEST(UploadRoutesTest, AcceptsCapabilityOnlyRawPutAndConsumesCapability)
{
    Fixture fixture;
    const auto issued = fixture.Issue("raw.bin");
    ASSERT_TRUE(issued.upload);
    binjad::http::UploadRoutes routes(fixture.config, fixture.authenticator, fixture.uploads);
    auto request = Request(drogon::Put, UrlPath(issued.url), {}, "payload");
    drogon::HttpResponsePtr response;
    routes.Handle(request, {}, [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k201Created);
    EXPECT_TRUE(fixture.uploads.FindCompleted(std::string(64, 'b'),
        fixture.session.session->reference, issued.upload->id, {}));
    drogon::HttpResponsePtr retried;
    routes.Handle(request, {}, [&](const auto& value) { retried = value; });
    ASSERT_TRUE(retried);
    EXPECT_EQ(retried->getStatusCode(), drogon::k404NotFound);
}

TEST(UploadRoutesTest, OptionallyRequiresIssuingBearerToken)
{
    Fixture fixture;
    fixture.config.uploads.requireBearerAuthentication = true;
    const auto issued = fixture.Issue("authenticated.bin");
    ASSERT_TRUE(issued.upload);
    binjad::http::UploadRoutes routes(fixture.config, fixture.authenticator, fixture.uploads);

    drogon::HttpResponsePtr rejected;
    routes.Handle(Request(drogon::Put, UrlPath(issued.url), {}, "payload"), {},
        [&](const auto& value) { rejected = value; });
    ASSERT_TRUE(rejected);
    EXPECT_EQ(rejected->getStatusCode(), drogon::k401Unauthorized);

    drogon::HttpResponsePtr accepted;
    routes.Handle(Request(drogon::Put, UrlPath(issued.url), fixture.token, "payload"), {},
        [&](const auto& value) { accepted = value; });
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->getStatusCode(), drogon::k201Created);
}

TEST(UploadRoutesTest, ConfiguresDrogonStorageBeneathPrivateSpool)
{
    Fixture fixture;
    const auto expected = fixture.config.storage.spoolPath / "drogon-uploads";
    ASSERT_TRUE(binjad::http::ConfigureDrogonUploadStorage(
        drogon::app(), fixture.config).empty());
    EXPECT_EQ(std::filesystem::path(drogon::app().getUploadPath()), expected);
    EXPECT_TRUE(std::filesystem::is_directory(expected));
    const auto permissions = std::filesystem::status(expected).permissions();
    EXPECT_EQ(permissions & (std::filesystem::perms::group_all |
        std::filesystem::perms::others_all), std::filesystem::perms::none);
}

TEST(UploadRoutesTest, StreamsSingleMultipartFileAcrossChunks)
{
    Fixture fixture;
    const auto issued = fixture.Issue("multipart.bin");
    ASSERT_TRUE(issued.upload);
    binjad::http::UploadRoutes routes(fixture.config, fixture.authenticator, fixture.uploads);
    auto request = Request(drogon::Post, UrlPath(issued.url), {});
    request->addHeader("Content-Type", "multipart/form-data; boundary=test-boundary");
    auto stream = std::make_shared<FakeRequestStream>();
    drogon::HttpResponsePtr response;
    routes.Handle(request, stream, [&](const auto& value) { response = value; });
    ASSERT_TRUE(stream->reader);
    const std::string first = "--test-boundary\r\nContent-Disposition: form-data; "
        "name=\"file\"; filename=\"ignored\"\r\n\r\nab";
    const std::string second = "cd\r\n--test-boundary--\r\n";
    stream->reader->onStreamData(first.data(), first.size());
    stream->reader->onStreamData(second.data(), second.size());
    stream->reader->onStreamFinish({});
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k201Created);
    const auto payload = fixture.uploads.PreparePayload(std::string(64, 'b'),
        fixture.session.session->reference, issued.upload->id, {});
    ASSERT_TRUE(payload.first) << payload.second;
    const auto contents = binjad::platform::ReadPrivateFile(payload.first->path);
    ASSERT_TRUE(contents.contents);
    EXPECT_EQ(*contents.contents, "abcd");
}
