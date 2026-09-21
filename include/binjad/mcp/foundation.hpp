#pragma once

#include "binjad/config.hpp"
#include "binjad/mcp/protocol.hpp"
#include "binjad/security/token_authenticator.hpp"
#include "binjad/session/analysis_session_registry.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace binjad::overseer
{
class FileChildCoordinator;
class ProjectChildCoordinator;
class AnalysisScheduler;
class CollaborationChildManager;
}

namespace binjad::project
{
class LocalProjectRegistry;
class CollaborationProjectRegistry;
}

namespace binjad::upload
{
class UploadRegistry;
}

namespace binjad::session
{
class OpenItemRegistry;
class JobRegistry;
struct JobRecord;
}

namespace binjad::mcp
{
struct FoundationResult
{
    bool handled = false;
    int httpStatus = 200;
    std::string body;
    std::optional<ProtocolError> error;
};

class Foundation
{
  public:
    using JobProgressCallback = std::function<void(const session::JobRecord&)>;
    using AttachedJobCallback = std::function<void(
        std::string_view, std::function<void()>)>;

    Foundation(Config config, session::AnalysisSessionRegistry& sessions,
        std::string serverVersion, session::OpenItemRegistry* openItems = nullptr,
        overseer::FileChildCoordinator* fileCoordinator = nullptr,
        session::JobRegistry* jobs = nullptr,
        project::LocalProjectRegistry* projects = nullptr,
        overseer::ProjectChildCoordinator* projectCoordinator = nullptr,
        overseer::AnalysisScheduler* scheduler = nullptr,
        upload::UploadRegistry* uploads = nullptr,
        project::CollaborationProjectRegistry* collaborationProjects = nullptr,
        overseer::CollaborationChildManager* collaborationManager = nullptr);
    FoundationResult Handle(const ValidatedRequest& request,
        const security::TokenRecord& principal,
        const std::optional<session::AnalysisSessionRecord>& currentSession,
        session::AnalysisSessionRegistry::Clock::time_point now,
        std::uint64_t unixNow, JobProgressCallback progress = {},
        AttachedJobCallback attached = {});
    FoundationResult Handle(const ValidatedRequest& request,
        const security::TokenRecord& principal,
        session::AnalysisSessionRegistry::Clock::time_point now,
        std::uint64_t unixNow)
    {
        return Handle(request, principal, std::nullopt, now, unixNow);
    }
    std::string ContextDocumentation(ProtocolVersion version,
        security::TokenRole role, std::string_view clientName) const;
    std::string ToolDocumentation(ProtocolVersion version,
        security::TokenRole role) const;

  private:
    Config config_;
    session::AnalysisSessionRegistry& sessions_;
    std::string serverVersion_;
    session::OpenItemRegistry* openItems_;
    overseer::FileChildCoordinator* fileCoordinator_;
    session::JobRegistry* jobs_;
    project::LocalProjectRegistry* projects_;
    overseer::ProjectChildCoordinator* projectCoordinator_;
    overseer::AnalysisScheduler* scheduler_;
    upload::UploadRegistry* uploads_;
    project::CollaborationProjectRegistry* collaborationProjects_;
    overseer::CollaborationChildManager* collaborationManager_;
};
}
