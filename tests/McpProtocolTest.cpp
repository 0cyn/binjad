#include "binjad/mcp/Protocol.hpp"

#include <gtest/gtest.h>

#include <string>

namespace
{
using binjad::mcp::ProtocolVersion;
using binjad::mcp::TransportHeaders;

constexpr auto kModernMeta = R"("_meta":{
    "io.modelcontextprotocol/protocolVersion":"2026-07-28",
    "io.modelcontextprotocol/clientCapabilities":{}
})";
}

TEST(McpProtocolTest, ValidatesModernDiscovery)
{
    const std::string body = std::string(R"({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{)") +
        kModernMeta + "}}";
    const auto result = binjad::mcp::ValidateRequest(body,
        TransportHeaders{"2026-07-28", "server/discover", std::nullopt});
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->version, ProtocolVersion::V2026_07_28);
    EXPECT_EQ(result.request->method, "server/discover");
}

TEST(McpProtocolTest, ExtractsModernAnalysisSessionMetadata)
{
    const std::string body = R"({
        "jsonrpc":"2.0","id":1,"method":"tools/list","params":{
            "_meta":{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientCapabilities":{},
                "me.cynder.binjad/analysisSession":"AmberCobaltMarbleFalcon"
            }
        }
    })";
    const auto result = binjad::mcp::ValidateRequest(body,
        TransportHeaders{"2026-07-28", "tools/list", std::nullopt});
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->analysisSession, "AmberCobaltMarbleFalcon");
}

TEST(McpProtocolTest, RejectsModernHeaderMismatch)
{
    const std::string body = std::string(R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{)") +
        kModernMeta + R"(,"name":"bn_compute_status","arguments":{}}})";
    const auto result = binjad::mcp::ValidateRequest(body,
        TransportHeaders{"2026-07-28", "tools/call", "wrong"});
    ASSERT_TRUE(result.error.has_value());
    EXPECT_EQ(result.error->code, -32020);
    EXPECT_EQ(result.error->httpStatus, 400);
}

TEST(McpProtocolTest, DecodesBase64NameHeader)
{
    const std::string body = std::string(R"({"jsonrpc":"2.0","id":"call","method":"tools/call","params":{)") +
        kModernMeta + R"(,"name":"bn_compute_status","arguments":{}}})";
    const auto result = binjad::mcp::ValidateRequest(body,
        TransportHeaders{"2026-07-28", "tools/call", "=?base64?Ym5fY29tcHV0ZV9zdGF0dXM=?="});
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->name, "bn_compute_status");
}

TEST(McpProtocolTest, NegotiatesOldestLegacyFallback)
{
    constexpr auto body = R"({
        "jsonrpc":"2.0","id":7,"method":"initialize",
        "params":{
            "protocolVersion":"1900-01-01",
            "capabilities":{},
            "clientInfo":{"name":"test","version":"1"}
        }
    })";
    const auto result = binjad::mcp::ValidateRequest(body, {});
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->version, ProtocolVersion::V2025_03_26);
}

TEST(McpProtocolTest, ValidatesLegacyResourceSubscription)
{
    constexpr auto body = R"({
        "jsonrpc":"2.0","id":2,"method":"resources/subscribe",
        "params":{"uri":"binjad://files/AmberCobaltMarbleFalcon"}
    })";
    const auto result = binjad::mcp::ValidateRequest(body, {}, ProtocolVersion::V2025_03_26);
    ASSERT_TRUE(result.request.has_value());
    EXPECT_EQ(result.request->uri, "binjad://files/AmberCobaltMarbleFalcon");
}

TEST(McpProtocolTest, ValidatesModernSubscriptionFilter)
{
    const std::string body = std::string(R"({"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{)") +
        kModernMeta + R"(,"notifications":{
            "toolsListChanged":true,
            "resourcesListChanged":true,
            "resourceSubscriptions":["binjad://jobs"]
        }}})";
    const auto result = binjad::mcp::ValidateRequest(body,
        TransportHeaders{"2026-07-28", "subscriptions/listen", std::nullopt});
    ASSERT_TRUE(result.request.has_value());
    ASSERT_TRUE(result.request->subscription.has_value());
    EXPECT_TRUE(result.request->subscription->toolsListChanged);
    EXPECT_EQ(result.request->subscription->resourceSubscriptions,
        (std::vector<std::string>{"binjad://jobs"}));
}

TEST(McpProtocolTest, BuildsModernDiscoveryMetadata)
{
    const auto response = binjad::mcp::BuildDiscoveryResponse(std::uint64_t{4}, "0.1.0");
    EXPECT_NE(response.find(R"("cacheScope":"private")"), std::string::npos);
    EXPECT_NE(response.find(R"("ttlMs":60000)"), std::string::npos);
    EXPECT_NE(response.find(R"("resources":{"subscribe":true,"listChanged":true})"),
        std::string::npos);
    EXPECT_NE(response.find("binary_view_open -> analyze"), std::string::npos);
    EXPECT_NE(response.find("Four-word references are opaque handles"), std::string::npos);
    EXPECT_NE(response.find("do not interpret or discuss their words"), std::string::npos);
    EXPECT_NE(response.find("binjad://docs"), std::string::npos);
}

TEST(McpProtocolTest, FramesSseDataAndKeepAlive)
{
    EXPECT_EQ(binjad::mcp::EncodeSseEvent("{\"ok\":true}"),
        "data: {\"ok\":true}\r\n\r\n");
    EXPECT_EQ(binjad::mcp::EncodeSseKeepAlive(), ":\r\n\r\n");
}

TEST(McpProtocolTest, BuildsSubscriptionNotifications)
{
    EXPECT_EQ(binjad::mcp::BuildToolsListChangedNotification(),
        R"({"jsonrpc":"2.0","method":"notifications/tools/list_changed"})");
    EXPECT_EQ(binjad::mcp::BuildResourcesListChangedNotification(),
        R"({"jsonrpc":"2.0","method":"notifications/resources/list_changed"})");
    EXPECT_EQ(binjad::mcp::BuildResourceUpdatedNotification("binjad://jobs"),
        R"({"jsonrpc":"2.0","method":"notifications/resources/updated","params":{"uri":"binjad://jobs"}})");
}
