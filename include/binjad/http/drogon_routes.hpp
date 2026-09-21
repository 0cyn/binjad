#pragma once

#include "binjad/config.hpp"
#include "binjad/http/mcp_admission.hpp"
#include "binjad/mcp/protocol.hpp"
#include "binjad/security/token_authenticator.hpp"
#include "binjad/session/job_registry.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpRequest.h>
#include <drogon/HttpResponse.h>
#include <drogon/RequestStream.h>

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace binjad::http
{
class AttachedSseState;

struct AdmittedMcpRequest
{
    Method method = Method::Other;
    security::TokenRecord principal;
    mcp::TransportHeaders transportHeaders;
    std::optional<std::string> sessionId;
    std::optional<std::string> lastEventId;
    std::string accept;
    std::string body;
    std::function<void(const session::JobRecord&)> progress;
    std::function<void(std::string_view, std::function<void()>)> attachedJob;
    std::function<void(std::string_view)> notification;
    std::function<void(std::function<void()>)> attachedSubscription;
};

using DrogonResponseCallback = std::function<void(const drogon::HttpResponsePtr&)>;
using McpRequestHandler =
    std::function<void(AdmittedMcpRequest, DrogonResponseCallback)>;

class DrogonRoutes : public std::enable_shared_from_this<DrogonRoutes>
{
  public:
    DrogonRoutes(Config config, const security::TokenAuthenticator& authenticator,
        McpRequestHandler handler);

    void Register(drogon::HttpAppFramework& app);
    void HandleHealth(const drogon::HttpRequestPtr& request,
        drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const;
    void HandleMcp(const drogon::HttpRequestPtr& request,
        drogon::RequestStreamPtr stream, DrogonResponseCallback callback) const;

  private:
    void TrackConnection(const trantor::TcpConnectionPtr& connection,
        const std::shared_ptr<AttachedSseState>& stream) const;
    void ForgetConnection(const trantor::TcpConnection* connection,
        const AttachedSseState* stream) const;
    void ConnectionChanged(const trantor::TcpConnectionPtr& connection) const;

    Config config_;
    McpAdmissionPolicy admission_;
    McpRequestHandler handler_;
    mutable std::mutex connectionsMutex_;
    mutable std::unordered_map<const trantor::TcpConnection*,
        std::vector<std::weak_ptr<AttachedSseState>>> connections_;
};

std::shared_ptr<DrogonRoutes> RegisterDrogonRoutes(drogon::HttpAppFramework& app,
    Config config, const security::TokenAuthenticator& authenticator, McpRequestHandler handler);
}
