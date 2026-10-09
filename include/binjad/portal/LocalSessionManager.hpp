#pragma once

#include "binjad/portal/SessionManager.hpp"

#include <memory>

namespace binjad::overseer {
	class FileChildCoordinator;
	class ProjectChildCoordinator;
}  // namespace binjad::overseer

namespace binjad::session {
	class AnalysisSessionRegistry;
	class JobRegistry;
	class OpenItemRegistry;
}  // namespace binjad::session

namespace binjad::portal {
	class LocalSessionManager final : public SessionManager
	{
	public:
		LocalSessionManager(std::shared_ptr<session::AnalysisSessionRegistry> sessions,
			std::shared_ptr<session::OpenItemRegistry> openItems, std::shared_ptr<session::JobRegistry> jobs,
			std::shared_ptr<overseer::FileChildCoordinator> files,
			std::shared_ptr<overseer::ProjectChildCoordinator> projects);

		Result<std::vector<RecoverySessionSummary>> List(std::string_view ownerTokenId) override;
		Result<RecoverySessionDetails> Details(
			std::string_view ownerTokenId, std::string_view analysisSession) override;
		Result<RecoverySave> Save(std::string_view ownerTokenId, std::string_view analysisSession,
			std::string_view binaryView, std::optional<std::string> destination) override;
		Result<RecoveryBatchSave> SaveAll(std::string_view ownerTokenId, std::string_view analysisSession) override;
		Result<bool> Abort(
			std::string_view ownerTokenId, std::string_view analysisSession, std::string_view binaryView) override;
		Result<bool> CancelJob(
			std::string_view ownerTokenId, std::string_view analysisSession, std::string_view job) override;
		Result<bool> CloseItem(std::string_view ownerTokenId, std::string_view analysisSession,
			std::string_view openItem, bool discard) override;
		Result<bool> ForceClose(std::string_view ownerTokenId, std::string_view analysisSession) override;

	private:
		std::weak_ptr<session::AnalysisSessionRegistry> sessions_;
		std::weak_ptr<session::OpenItemRegistry> openItems_;
		std::weak_ptr<session::JobRegistry> jobs_;
		std::weak_ptr<overseer::FileChildCoordinator> files_;
		std::weak_ptr<overseer::ProjectChildCoordinator> projects_;
	};
}  // namespace binjad::portal
