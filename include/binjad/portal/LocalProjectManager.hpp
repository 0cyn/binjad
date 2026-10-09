#pragma once

#include "binjad/Config.hpp"
#include "binjad/portal/ProjectManager.hpp"

#include <memory>

namespace binjad::download {
	class DownloadRegistry;
}

namespace binjad::overseer {
	class ProjectChildCoordinator;
}

namespace binjad::project {
	class LocalProjectRegistry;
}

namespace binjad::session {
	class OpenItemRegistry;
}

namespace binjad::upload {
	class UploadRegistry;
}

namespace binjad::portal {
	class LocalProjectManager final : public ProjectManager
	{
	public:
		LocalProjectManager(Config config, std::shared_ptr<project::LocalProjectRegistry> projects,
			std::shared_ptr<session::OpenItemRegistry> openItems,
			std::shared_ptr<overseer::ProjectChildCoordinator> coordinator,
			std::shared_ptr<download::DownloadRegistry> downloads, std::shared_ptr<upload::UploadRegistry> uploads);

		std::vector<ProjectSummary> List() const override;
		Result<ProjectSummary> Create(
			std::string name, std::optional<std::string> path, std::string description) override;
		Result<ProjectSummary> Update(
			std::string_view project, std::optional<std::string> name, std::optional<std::string> description) override;
		Result<bool> Delete(std::string_view project) override;
		Result<ProjectContents> Contents(std::string_view project) override;

		Result<ProjectFolder> CreateFolder(std::string_view project, std::optional<std::string> parent,
			std::string name, std::string description) override;
		Result<ProjectFolder> UpdateFolder(std::string_view project, std::string_view path,
			std::optional<std::string> name, std::optional<std::string> description,
			std::optional<std::optional<std::string>> parent) override;
		Result<bool> DeleteFolder(std::string_view project, std::string_view path) override;

		Result<ProjectFile> UpdateFile(std::string_view project, std::string_view path, std::optional<std::string> name,
			std::optional<std::string> description, std::optional<std::optional<std::string>> folder) override;
		Result<bool> DeleteFile(std::string_view project, std::string_view path) override;

		Result<ProjectDownload> Download(
			std::string_view project, ProjectDownloadKind kind, const std::vector<std::string>& paths) override;
		Result<ProjectUpload> StartUpload(std::string_view project, std::string filename) override;
		Result<ProjectFile> CommitUpload(std::string_view project, std::string_view upload,
			std::optional<std::string> folder, std::string description) override;
		Result<ProjectDocument> ReadDocument(std::string_view project, std::string_view path) override;

	private:
		Config config_;
		std::weak_ptr<project::LocalProjectRegistry> projects_;
		std::weak_ptr<session::OpenItemRegistry> openItems_;
		std::weak_ptr<overseer::ProjectChildCoordinator> coordinator_;
		std::weak_ptr<download::DownloadRegistry> downloads_;
		std::weak_ptr<upload::UploadRegistry> uploads_;
	};
}  // namespace binjad::portal
