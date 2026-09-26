#include "binjad/http/DrogonRoutes.hpp"

#include "binjad/security/Crypto.hpp"

#include <gtest/gtest.h>
#include <trantor/net/AsyncStream.h>

#include <future>
#include <memory>

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

struct FakeAsyncOutput
{
    std::string data;
    std::promise<void> closed;
    bool didClose = false;
    bool acceptSends = true;
};

class FakeAsyncStream final : public trantor::AsyncStream
{
  public:
    explicit FakeAsyncStream(std::shared_ptr<FakeAsyncOutput> output)
        : output_(std::move(output))
    {
    }

    bool send(const char* data, std::size_t length) override
    {
        output_->data.append(data, length);
        return output_->acceptSends;
    }

    void close() override
    {
        if (!output_->didClose)
        {
            output_->didClose = true;
            output_->closed.set_value();
        }
    }

  private:
    std::shared_ptr<FakeAsyncOutput> output_;
};

struct Fixture
{
    Fixture()
        : token(64, 'a'), authenticator(std::string(key),
            {{binjad::security::HmacSha256Hex(key, token),
                {std::string(64, 'b'), std::string(64, 'c'),
                    binjad::security::TokenRole::Admin, "test", 1, {}}}})
    {
        config.http.allowedOrigins = {"http://127.0.0.1:8712"};
        config.http.mcpMaxBodyBytes = 16;
    }

    static constexpr std::string_view key = "test key";
    std::string token;
    binjad::Config config;
    binjad::security::TokenAuthenticator authenticator;
};

drogon::HttpRequestPtr Request(
    drogon::HttpMethod method, std::string_view token, std::string body = {})
{
    auto request = drogon::HttpRequest::newHttpRequest();
    request->setMethod(method);
    if (!token.empty())
        request->addHeader("Authorization", "Bearer " + std::string(token));
    if (!body.empty())
        request->setBody(std::move(body));
    return request;
}
}

TEST(DrogonRoutesTest, ConvertsMinimalHealthResponse)
{
    Fixture fixture;
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [](auto, auto) {});
    drogon::HttpResponsePtr response;
    routes.HandleHealth(Request(drogon::Get, {}), {},
        [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k200OK);
    EXPECT_EQ(response->body(), R"({"status":"ok"})");
}

TEST(DrogonRoutesTest, RejectsBeforeCallingDispatcher)
{
    Fixture fixture;
    bool called = false;
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [&](auto, auto) { called = true; });
    drogon::HttpResponsePtr response;
    routes.HandleMcp(Request(drogon::Post, {}), {},
        [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k401Unauthorized);
    EXPECT_FALSE(called);
}

TEST(DrogonRoutesTest, StreamsBoundedPostBodyToDispatcher)
{
    Fixture fixture;
    std::optional<binjad::http::AdmittedMcpRequest> admitted;
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [&](auto request, auto callback) {
            admitted = std::move(request);
            callback(drogon::HttpResponse::newHttpResponse());
        });
    auto stream = std::make_shared<FakeRequestStream>();
    std::promise<drogon::HttpResponsePtr> completion;
    auto response = completion.get_future();
    routes.HandleMcp(Request(drogon::Post, fixture.token), stream,
        [&](const auto& value) { completion.set_value(value); });
    ASSERT_TRUE(stream->reader);
    stream->reader->onStreamData("12345678", 8);
    stream->reader->onStreamData("abcdefgh", 8);
    stream->reader->onStreamFinish({});
    const auto completed = response.get();
    ASSERT_TRUE(admitted.has_value());
    EXPECT_EQ(admitted->body, "12345678abcdefgh");
    EXPECT_TRUE(completed);
}

TEST(DrogonRoutesTest, DiscardsChunkedBodyBeyondMcpLimit)
{
    Fixture fixture;
    bool called = false;
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [&](auto, auto) { called = true; });
    auto stream = std::make_shared<FakeRequestStream>();
    drogon::HttpResponsePtr response;
    routes.HandleMcp(Request(drogon::Post, fixture.token), stream,
        [&](const auto& value) { response = value; });
    ASSERT_TRUE(stream->reader);
    stream->reader->onStreamData("123456789", 9);
    stream->reader->onStreamData("abcdefghi", 9);
    stream->reader->onStreamFinish({});
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k413RequestEntityTooLarge);
    EXPECT_FALSE(called);
}

TEST(DrogonRoutesTest, StreamsAttachedAnalysisProgressAndFinalResponseAsSse)
{
    Fixture fixture;
    fixture.config.http.mcpMaxBodyBytes = 4096;
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [](auto request, auto callback) {
            request.attachedJob("TestJob", [] {});
            binjad::session::JobRecord job;
            job.reference = "TestJob";
            job.progress = binjad::session::JobProgress{
                1, 2, "analysis", 3, 4, "working"};
            request.progress(job);
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setBody(R"({"jsonrpc":"2.0","id":1,"result":{}})");
            callback(response);
        });
    auto request = Request(drogon::Post, fixture.token,
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bn_analysis_update_and_wait","arguments":{"binaryView":"TestView"}}})");
    request->addHeader("Accept", "application/json, text/event-stream");
    drogon::HttpResponsePtr response;
    routes.HandleMcp(request, {}, [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->contentTypeString(), "text/event-stream");
    ASSERT_TRUE(response->asyncStreamCallback());

    auto output = std::make_shared<FakeAsyncOutput>();
    auto closed = output->closed.get_future();
    response->asyncStreamCallback()(std::make_unique<drogon::ResponseStream>(
        std::make_unique<FakeAsyncStream>(output)));
    ASSERT_EQ(closed.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    EXPECT_NE(output->data.find("notifications/progress"), std::string::npos);
    EXPECT_NE(output->data.find(R"("job":"TestJob")"), std::string::npos);
    EXPECT_NE(output->data.find(R"("phase":"analysis")"), std::string::npos);
    EXPECT_NE(output->data.find(R"("id":1)"), std::string::npos);
}

TEST(DrogonRoutesTest, KeepsImportOnlyUploadCommitAsJson)
{
    Fixture fixture;
    fixture.config.http.mcpMaxBodyBytes = 4096;
    std::promise<drogon::HttpResponsePtr> completion;
    auto completed = completion.get_future();
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [](auto, auto callback) {
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setContentTypeString("application/json");
            response->setBody(R"({"jsonrpc":"2.0","id":1,"result":{}})");
            callback(response);
        });
    auto request = Request(drogon::Post, fixture.token,
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bn_upload_commit","arguments":{"id":"Upload","open":false,"analyze":false}}})");
    request->addHeader("Accept", "application/json, text/event-stream");
    routes.HandleMcp(request, {}, [&](const auto& value) { completion.set_value(value); });
    const auto response = completed.get();
    ASSERT_TRUE(response);
    EXPECT_EQ(response->contentTypeString(), "application/json");
    EXPECT_FALSE(response->asyncStreamCallback());
}

TEST(DrogonRoutesTest, StreamsLongProjectJobsAsSse)
{
    for (const auto* tool : {"bn_local_project_directory_import", "bn_local_project_relocate"})
    {
        Fixture fixture;
        fixture.config.http.mcpMaxBodyBytes = 4096;
        binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
            [](auto, auto callback) { callback(drogon::HttpResponse::newHttpResponse()); });
        auto request = Request(drogon::Post, fixture.token,
            std::string(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":")")
                + tool + R"(","arguments":{}}})");
        request->addHeader("Accept", "application/json, text/event-stream");
        drogon::HttpResponsePtr response;
        routes.HandleMcp(request, {}, [&](const auto& value) { response = value; });
        ASSERT_TRUE(response) << tool;
        EXPECT_EQ(response->contentTypeString(), "text/event-stream") << tool;
        EXPECT_TRUE(response->asyncStreamCallback()) << tool;
    }
}

TEST(DrogonRoutesTest, CancelsAttachedJobWhenSseSendDetectsDisconnect)
{
    Fixture fixture;
    fixture.config.http.mcpMaxBodyBytes = 4096;
    std::promise<void> cancellation;
    auto cancelled = cancellation.get_future();
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [&](auto request, auto callback) {
            request.attachedJob("TestJob", [&] { cancellation.set_value(); });
            binjad::session::JobRecord job;
            job.reference = "TestJob";
            job.progress = binjad::session::JobProgress{1, 2, "analysis", 1, 2, {}};
            request.progress(job);
            auto response = drogon::HttpResponse::newHttpResponse();
            response->setBody("{}");
            callback(response);
        });
    auto request = Request(drogon::Post, fixture.token,
        R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"bn_analysis_update_and_wait","arguments":{"binaryView":"TestView"}}})");
    request->addHeader("Accept", "text/event-stream");
    drogon::HttpResponsePtr response;
    routes.HandleMcp(request, {}, [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    auto output = std::make_shared<FakeAsyncOutput>();
    output->acceptSends = false;
    response->asyncStreamCallback()(std::make_unique<drogon::ResponseStream>(
        std::make_unique<FakeAsyncStream>(output)));
    EXPECT_EQ(cancelled.wait_for(std::chrono::seconds(1)), std::future_status::ready);
}

TEST(DrogonRoutesTest, StreamsModernSubscriptionNotificationsUntilDisconnect)
{
    Fixture fixture;
    fixture.config.http.mcpMaxBodyBytes = 4096;
    std::function<void(std::string_view)> notify;
    std::promise<void> attached;
    auto didAttach = attached.get_future();
    std::promise<void> cancellation;
    auto cancelled = cancellation.get_future();
    binjad::http::DrogonRoutes routes(fixture.config, fixture.authenticator,
        [&](auto request, auto) {
            notify = request.notification;
            request.attachedSubscription([&] { cancellation.set_value(); });
            attached.set_value();
        });
    auto request = Request(drogon::Post, fixture.token,
        R"({"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{}})");
    request->addHeader("Accept", "text/event-stream");
    drogon::HttpResponsePtr response;
    routes.HandleMcp(request, {}, [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->contentTypeString(), "text/event-stream");
    ASSERT_TRUE(response->asyncStreamCallback());

    auto output = std::make_shared<FakeAsyncOutput>();
    response->asyncStreamCallback()(std::make_unique<drogon::ResponseStream>(
        std::make_unique<FakeAsyncStream>(output)));
    ASSERT_EQ(didAttach.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    ASSERT_TRUE(notify);
    notify(R"({"jsonrpc":"2.0","method":"notifications/resources/list_changed"})");
    EXPECT_NE(output->data.find("notifications/resources/list_changed"), std::string::npos);

    output->acceptSends = false;
    notify(R"({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})");
    EXPECT_EQ(cancelled.wait_for(std::chrono::seconds(1)), std::future_status::ready);
    notify = {};
}
