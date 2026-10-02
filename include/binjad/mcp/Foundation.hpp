#pragma once

#include "binjad/Config.hpp"
#include "binjad/mcp/Protocol.hpp"
#include "binjad/security/TokenAuthenticator.hpp"
#include "binjad/session/AnalysisSessionRegistry.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace binjad::overseer {
	class FileChildCoordinator;
	class ProjectChildCoordinator;
	class AnalysisScheduler;
}  // namespace binjad::overseer

namespace binjad::project {
	class LocalProjectRegistry;
}

namespace binjad::upload {
	class UploadRegistry;
}

namespace binjad::download {
	class DownloadRegistry;
}

namespace binjad::session {
	class OpenItemRegistry;
	class JobRegistry;
	struct JobRecord;
}  // namespace binjad::session

namespace binjad::mcp {
	struct FoundationResult
	{
		FoundationResult() = default;
		FoundationResult(bool handled, int httpStatus, std::string body, std::optional<ProtocolError> error,
			std::string invokedTool = {}) :
			handled(handled), httpStatus(httpStatus), body(std::move(body)), error(std::move(error)),
			invokedTool(std::move(invokedTool))
		{}

		bool handled = false;
		int httpStatus = 200;
		std::string body;
		std::optional<ProtocolError> error;
		std::string invokedTool;
	};

	class Foundation
	{
	public:
		using JobProgressCallback = std::function<void(const session::JobRecord&)>;
		using AttachedJobCallback = std::function<void(std::string_view, std::function<void()>)>;

		Foundation(Config config, session::AnalysisSessionRegistry& sessions, std::string serverVersion,
			session::OpenItemRegistry* openItems = nullptr, overseer::FileChildCoordinator* fileCoordinator = nullptr,
			session::JobRegistry* jobs = nullptr, project::LocalProjectRegistry* projects = nullptr,
			overseer::ProjectChildCoordinator* projectCoordinator = nullptr,
			overseer::AnalysisScheduler* scheduler = nullptr, upload::UploadRegistry* uploads = nullptr,
			download::DownloadRegistry* downloads = nullptr);
		FoundationResult Handle(const ValidatedRequest& request, const security::TokenRecord& principal,
			const std::optional<session::AnalysisSessionRecord>& currentSession,
			session::AnalysisSessionRegistry::Clock::time_point now, std::uint64_t unixNow,
			JobProgressCallback progress = {}, AttachedJobCallback attached = {});
		FoundationResult Handle(const ValidatedRequest& request, const security::TokenRecord& principal,
			session::AnalysisSessionRegistry::Clock::time_point now, std::uint64_t unixNow)
		{
			return Handle(request, principal, std::nullopt, now, unixNow);
		}
		std::string ContextDocumentation(
			ProtocolVersion version, security::TokenRole role, std::string_view clientName) const;
		std::string ToolDocumentation(ProtocolVersion version, security::TokenRole role) const;
		void SetToolConfig(ToolConfig config);

	private:
		Config EffectiveConfig() const;

		Config config_;
		ToolConfig toolConfig_;
		mutable std::mutex toolConfigMutex_;
		session::AnalysisSessionRegistry& sessions_;
		std::string serverVersion_;
		session::OpenItemRegistry* openItems_;
		overseer::FileChildCoordinator* fileCoordinator_;
		session::JobRegistry* jobs_;
		project::LocalProjectRegistry* projects_;
		overseer::ProjectChildCoordinator* projectCoordinator_;
		overseer::AnalysisScheduler* scheduler_;
		upload::UploadRegistry* uploads_;
		download::DownloadRegistry* downloads_;
	};
}  // namespace binjad::mcp
