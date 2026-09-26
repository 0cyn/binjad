#include "binjad/http/McpDispatcher.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace
{
using namespace std::chrono_literals;

binjad::security::TokenRecord Principal()
{
    return {std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
}

binjad::http::AdmittedMcpRequest LegacyRequest(std::string body)
{
    return {binjad::http::Method::Post, Principal(), {}, {}, {}, {}, std::move(body)};
}

std::string ResponseHeader(const drogon::HttpResponsePtr& response, std::string_view name)
{
    return response->getHeader(std::string(name));
}
}

TEST(McpDispatcherTest, InitializesLegacySessionAndHandlesPing)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0", [=] { return now; }, [] { return 10; });
    auto initialize = LegacyRequest(R"({
        "jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2025-06-18","capabilities":{},
            "clientInfo":{"name":"test","version":"1"}
        }
    })");
    drogon::HttpResponsePtr initialized;
    dispatcher.Handle(std::move(initialize), [&](const auto& response) { initialized = response; });
    ASSERT_TRUE(initialized);
    EXPECT_EQ(initialized->getStatusCode(), drogon::k200OK);
    const auto sessionId = ResponseHeader(initialized, "mcp-session-id");
    ASSERT_EQ(sessionId.size(), 43U);
    EXPECT_EQ(sessions.Size(), 1U);

    auto ping = LegacyRequest(R"({"jsonrpc":"2.0","id":2,"method":"ping"})");
    ping.sessionId = sessionId;
    ping.transportHeaders.protocolVersion = "2025-06-18";
    drogon::HttpResponsePtr pong;
    dispatcher.Handle(std::move(ping), [&](const auto& response) { pong = response; });
    ASSERT_TRUE(pong);
    EXPECT_EQ(pong->getStatusCode(), drogon::k200OK);
    EXPECT_NE(std::string(pong->body()).find(R"("id":2)"), std::string::npos);
}

TEST(McpDispatcherTest, DiscoversModernServerAndRejectsForeignSession)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0", [=] { return now; }, [] { return 10; });
    const auto foreign = sessions.Create(std::string(64, 'c'), 1, now);
    ASSERT_TRUE(foreign.session.has_value());

    const auto meta = std::string(R"("_meta":{
        "io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientCapabilities":{}
    })");
    binjad::http::AdmittedMcpRequest discovery{
        binjad::http::Method::Post, Principal(),
        {"2026-07-28", "server/discover", {}}, {}, {}, {},
        std::string(R"({"jsonrpc":"2.0","id":3,"method":"server/discover","params":{)") +
            meta + "}}"};
    drogon::HttpResponsePtr discovered;
    dispatcher.Handle(std::move(discovery), [&](const auto& response) { discovered = response; });
    ASSERT_TRUE(discovered);
    EXPECT_EQ(discovered->getStatusCode(), drogon::k200OK);
    EXPECT_EQ(ResponseHeader(discovered, "cache-control"), "private, max-age=60");

    binjad::http::AdmittedMcpRequest foreignLookup{
        binjad::http::Method::Post, Principal(),
        {"2026-07-28", "tools/list", {}}, {}, {}, {},
        std::string(R"({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{)") +
            R"("_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",)"
            R"("io.modelcontextprotocol/clientCapabilities":{},)"
            R"("me.cynder.binjad/analysisSession":")" + foreign.session->reference + "\"}}}"};
    drogon::HttpResponsePtr rejected;
    dispatcher.Handle(std::move(foreignLookup), [&](const auto& response) { rejected = response; });
    ASSERT_TRUE(rejected);
    EXPECT_EQ(rejected->getStatusCode(), drogon::k404NotFound);
    EXPECT_NE(std::string(rejected->body()).find("session not found"), std::string::npos);
}

TEST(McpDispatcherTest, LegacyDeleteDetachesWithoutClosingAnalysisSession)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    const auto created = sessions.Create(std::string(64, 'a'), 1, now,
        binjad::mcp::ProtocolVersion::V2025_03_26);
    ASSERT_TRUE(created.session && created.session->legacyTransportId);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0", [=] { return now; }, [] { return 10; });
    binjad::http::AdmittedMcpRequest request{
        binjad::http::Method::Delete, Principal(), {},
        created.session->legacyTransportId, {}, {}, {}};
    drogon::HttpResponsePtr response;
    dispatcher.Handle(std::move(request), [&](const auto& value) { response = value; });
    ASSERT_TRUE(response);
    EXPECT_EQ(response->getStatusCode(), drogon::k204NoContent);
    EXPECT_EQ(sessions.Size(), 1U);
}

TEST(McpDispatcherTest, LegacySubscriptionsPublishOnAttachedGetStream)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    const auto created = sessions.Create(std::string(64, 'a'), 1, now,
        binjad::mcp::ProtocolVersion::V2025_06_18);
    ASSERT_TRUE(created.session && created.session->legacyTransportId);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0",
        [=] { return now; }, [] { return 10; });

    auto subscribe = LegacyRequest(R"({"jsonrpc":"2.0","id":1,"method":"resources/subscribe","params":{"uri":"binjad://jobs"}})");
    subscribe.sessionId = created.session->legacyTransportId;
    subscribe.transportHeaders.protocolVersion = "2025-06-18";
    drogon::HttpResponsePtr subscribed;
    dispatcher.Handle(std::move(subscribe),
        [&](const auto& response) { subscribed = response; });
    ASSERT_TRUE(subscribed);
    EXPECT_EQ(subscribed->getStatusCode(), drogon::k200OK);

    std::vector<std::string> notifications;
    std::function<void()> detach;
    binjad::http::AdmittedMcpRequest listen;
    listen.method = binjad::http::Method::Get;
    listen.principal = Principal();
    listen.sessionId = created.session->legacyTransportId;
    listen.accept = "text/event-stream";
    listen.notification = [&](std::string_view value) {
        notifications.emplace_back(value);
    };
    listen.attachedSubscription = [&](std::function<void()> value) {
        detach = std::move(value);
    };
    bool completed = false;
    dispatcher.Handle(std::move(listen), [&](const auto&) { completed = true; });
    EXPECT_FALSE(completed);
    ASSERT_TRUE(detach);
    EXPECT_EQ(sessions.Find(created.session->reference, Principal().id, now)->retainers, 1U);

    dispatcher.Subscriptions()->PublishResource(Principal().id, "binjad://jobs");
    ASSERT_EQ(notifications.size(), 1U);
    EXPECT_NE(notifications[0].find("notifications/resources/updated"), std::string::npos);
    detach();
    EXPECT_EQ(dispatcher.Subscriptions()->ListenerCount(), 0U);
    EXPECT_EQ(sessions.Find(created.session->reference, Principal().id, now)->retainers, 0U);
}

TEST(McpDispatcherTest, ModernListenAcknowledgesAndFiltersNotifications)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point(1h);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0",
        [=] { return now; }, [] { return 10; });
    binjad::http::AdmittedMcpRequest listen;
    listen.method = binjad::http::Method::Post;
    listen.principal = Principal();
    listen.transportHeaders = {"2026-07-28", "subscriptions/listen", {}};
    listen.accept = "text/event-stream";
    listen.body = R"({"jsonrpc":"2.0","id":7,"method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":false,"resourcesListChanged":true,"resourceSubscriptions":["binjad://jobs"]}}})";
    std::vector<std::string> notifications;
    std::function<void()> detach;
    listen.notification = [&](std::string_view value) {
        notifications.emplace_back(value);
    };
    listen.attachedSubscription = [&](std::function<void()> value) {
        detach = std::move(value);
    };
    bool completed = false;
    dispatcher.Handle(std::move(listen), [&](const auto&) { completed = true; });
    EXPECT_FALSE(completed);
    ASSERT_TRUE(detach);
    ASSERT_EQ(notifications.size(), 1U);
    EXPECT_NE(notifications[0].find("notifications/subscriptions/acknowledged"),
        std::string::npos);

    dispatcher.Subscriptions()->PublishToolsListChanged();
    dispatcher.Subscriptions()->PublishResourcesListChanged();
    dispatcher.Subscriptions()->PublishResource(Principal().id, "binjad://jobs");
    ASSERT_EQ(notifications.size(), 3U);
    EXPECT_NE(notifications[1].find("notifications/resources/list_changed"),
        std::string::npos);
    EXPECT_NE(notifications[2].find("notifications/resources/updated"),
        std::string::npos);
    detach();
}

TEST(McpDispatcherTest, HotToolConfigurationPublishesListChange)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::http::McpDispatcher dispatcher(sessions, "0.1.0");
    binjad::mcp::SubscriptionFilter filter;
    filter.toolsListChanged = true;
    std::vector<std::string> notifications;
    dispatcher.Subscriptions()->ListenModern(Principal().id, filter,
        [&](std::string_view notification) { notifications.emplace_back(notification); });

    binjad::ToolConfig tools;
    tools.functionAnalysis = false;
    dispatcher.SetToolConfig(tools);

    ASSERT_EQ(notifications.size(), 1U);
    EXPECT_NE(notifications.front().find("notifications/tools/list_changed"), std::string::npos);
    EXPECT_EQ(dispatcher.ContextDocumentation(binjad::mcp::ProtocolVersion::V2026_07_28,
                  binjad::security::TokenRole::Admin, "binjad")
                  .find("bn_function_il"),
        std::string::npos);
}
