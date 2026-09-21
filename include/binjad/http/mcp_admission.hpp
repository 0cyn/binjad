#pragma once

#include "binjad/config.hpp"
#include "binjad/security/token_authenticator.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace binjad::http
{
enum class Method
{
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Other,
};

struct McpRequestHead
{
    Method method = Method::Other;
    std::optional<std::string> origin;
    std::optional<std::string> authorization;
    std::optional<std::uint64_t> contentLength;
};

struct ImmediateResponse
{
    int status = 0;
    std::string contentType;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
};

struct McpAdmissionResult
{
    std::optional<security::TokenRecord> principal;
    std::optional<ImmediateResponse> response;
    std::optional<std::string> allowedOrigin;
};

class McpAdmissionPolicy
{
  public:
    McpAdmissionPolicy(HttpConfig config, const security::TokenAuthenticator& authenticator);
    McpAdmissionResult Evaluate(const McpRequestHead& request, std::uint64_t now) const;

  private:
    bool IsAllowedOrigin(std::string_view origin) const;
    static std::optional<std::string_view> BearerToken(std::string_view authorization);

    HttpConfig config_;
    const security::TokenAuthenticator& authenticator_;
};

ImmediateResponse HealthResponse();
}
