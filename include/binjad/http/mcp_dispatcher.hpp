#pragma once

#include "binjad/http/drogon_routes.hpp"
#include "binjad/mcp/foundation.hpp"
#include "binjad/session/analysis_session_registry.hpp"
#include "binjad/session/subscription_registry.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace binjad::http
{
class McpDispatcher
{
  public:
    using SteadyNow = std::function<session::AnalysisSessionRegistry::Clock::time_point()>;
    using UnixNow = std::function<std::uint64_t()>;

    McpDispatcher(session::AnalysisSessionRegistry& sessions, std::string serverVersion,
        SteadyNow steadyNow = {}, UnixNow unixNow = {});
    McpDispatcher(session::AnalysisSessionRegistry& sessions, std::string serverVersion,
        Config config, SteadyNow steadyNow = {}, UnixNow unixNow = {});
    McpDispatcher(session::AnalysisSessionRegistry& sessions, std::string serverVersion,
        Config config, session::OpenItemRegistry* openItems,
        overseer::FileChildCoordinator* fileCoordinator,
        session::JobRegistry* jobs,
        project::LocalProjectRegistry* projects = nullptr,
        overseer::ProjectChildCoordinator* projectCoordinator = nullptr,
        overseer::AnalysisScheduler* scheduler = nullptr,
        upload::UploadRegistry* uploads = nullptr,
        project::CollaborationProjectRegistry* collaborationProjects = nullptr,
        overseer::CollaborationChildManager* collaborationManager = nullptr,
        SteadyNow steadyNow = {}, UnixNow unixNow = {},
        std::shared_ptr<session::SubscriptionRegistry> subscriptions = {});
    void Handle(AdmittedMcpRequest request, DrogonResponseCallback callback);
    std::string ContextDocumentation(mcp::ProtocolVersion version,
        security::TokenRole role, std::string_view clientName) const;
    std::string ToolDocumentation(mcp::ProtocolVersion version,
        security::TokenRole role) const;

    std::shared_ptr<session::SubscriptionRegistry> Subscriptions() const;

  private:
    void PublishChanges(const mcp::ValidatedRequest& request,
        const security::TokenRecord& principal,
        const std::optional<session::AnalysisSessionRecord>& analysisSession) const;

    session::AnalysisSessionRegistry& sessions_;
    std::string serverVersion_;
    Mode mode_ = Mode::Local;
    mcp::Foundation foundation_;
    SteadyNow steadyNow_;
    UnixNow unixNow_;
    std::shared_ptr<session::SubscriptionRegistry> subscriptions_;
};
}
