#include "binjad/http/McpAdmission.hpp"

#include "binjad/security/Crypto.hpp"

#include <gtest/gtest.h>

#include <string>

namespace
{
struct Fixture
{
    Fixture()
        : token(64, 'a'), authenticator(std::string(key),
            {{binjad::security::HmacSha256Hex(key, token),
                {std::string(64, 'b'), std::string(64, 'c'),
                    binjad::security::TokenRole::Admin, "test", 1, 100}}}), policy(config, authenticator)
    {
    }

    static constexpr std::string_view key = "test key";
    std::string token;
    binjad::HttpConfig config{
        "http://127.0.0.1:8712", "/mcp", "/uploads", "/portal", "/healthz",
        {"http://127.0.0.1:8712"}, 32};
    binjad::security::TokenAuthenticator authenticator;
    binjad::http::McpAdmissionPolicy policy;
};

std::string Header(const binjad::http::ImmediateResponse& response, std::string_view name)
{
    for (const auto& [candidate, value] : response.headers)
    {
        if (candidate == name)
            return value;
    }
    return {};
}
}

TEST(HttpAdmissionTest, ReturnsMinimalPublicHealthResponse)
{
    const auto response = binjad::http::HealthResponse();
    EXPECT_EQ(response.status, 200);
    EXPECT_EQ(response.body, R"({"status":"ok"})");
    EXPECT_EQ(Header(response, "Cache-Control"), "no-store");
}

TEST(HttpAdmissionTest, RejectsOriginBeforeAuthentication)
{
    Fixture fixture;
    const auto result = fixture.policy.Evaluate(
        {binjad::http::Method::Post, "https://evil.example", std::nullopt, std::nullopt}, 2);
    ASSERT_TRUE(result.response.has_value());
    EXPECT_EQ(result.response->status, 403);
}

TEST(HttpAdmissionTest, UsesOneUnauthorizedResponseForBearerFailures)
{
    Fixture fixture;
    const auto missing = fixture.policy.Evaluate({binjad::http::Method::Post}, 2);
    const auto malformed = fixture.policy.Evaluate(
        {binjad::http::Method::Post, std::nullopt, "Basic nope", std::nullopt}, 2);
    const auto unknown = fixture.policy.Evaluate(
        {binjad::http::Method::Post, std::nullopt,
            "Bearer " + std::string(64, 'd'), std::nullopt}, 2);
    ASSERT_TRUE(missing.response && malformed.response && unknown.response);
    EXPECT_EQ(missing.response->status, 401);
    EXPECT_EQ(missing.response->body, malformed.response->body);
    EXPECT_EQ(malformed.response->body, unknown.response->body);
    EXPECT_EQ(Header(*unknown.response, "WWW-Authenticate"), "Bearer");
}

TEST(HttpAdmissionTest, AuthenticatesBeforeEnforcingBodyLimit)
{
    Fixture fixture;
    const auto unauthorized = fixture.policy.Evaluate(
        {binjad::http::Method::Post, std::nullopt, std::nullopt, 33}, 2);
    ASSERT_TRUE(unauthorized.response.has_value());
    EXPECT_EQ(unauthorized.response->status, 401);

    const auto oversized = fixture.policy.Evaluate(
        {binjad::http::Method::Post, std::nullopt, "Bearer " + fixture.token, 33}, 2);
    ASSERT_TRUE(oversized.response.has_value());
    EXPECT_EQ(oversized.response->status, 413);
}

TEST(HttpAdmissionTest, AllowsAuthenticatedSupportedMethods)
{
    Fixture fixture;
    for (const auto method : {binjad::http::Method::Post,
             binjad::http::Method::Get, binjad::http::Method::Delete})
    {
        const auto result = fixture.policy.Evaluate(
            {method, std::nullopt, "bearer " + fixture.token, 32}, 2);
        ASSERT_TRUE(result.principal.has_value());
        EXPECT_FALSE(result.response.has_value());
    }
}

TEST(HttpAdmissionTest, AllowsPreflightOnlyForConfiguredOrigin)
{
    Fixture fixture;
    const auto result = fixture.policy.Evaluate(
        {binjad::http::Method::Options, "http://127.0.0.1:8712"}, 2);
    ASSERT_TRUE(result.response.has_value());
    EXPECT_EQ(result.response->status, 204);
    EXPECT_EQ(Header(*result.response, "Access-Control-Allow-Origin"),
        "http://127.0.0.1:8712");
    EXPECT_NE(Header(*result.response, "Access-Control-Allow-Headers").find("Authorization"),
        std::string::npos);
}
