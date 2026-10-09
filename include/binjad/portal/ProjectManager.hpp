#pragma once

#include "binjad/portal/Service.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::portal {
	struct ProjectSummary
	{
		std::string reference;
		std::string name;
		std::string description;
	};

	struct ProjectFile
	{
		std::string path;
		std::string name;
		std::string description;
		std::int64_t createdAt = 0;
		std::optional<std::string> folder;
	};

	struct ProjectFolder
	{
		std::string path;
		std::string name;
		std::string description;
		std::optional<std::string> parent;
	};

	struct ProjectContents
	{
		ProjectSummary project;
		std::vector<ProjectFolder> folders;
		std::vector<ProjectFile> files;
	};

	enum class ProjectDownloadKind
	{
		File,
		Files,
		Folder,
		Project,
	};

	struct ProjectDownload
	{
		std::string url;
		std::string filename;
		std::string contentType;
		std::string sha256;
		std::uint64_t size = 0;
		std::uint64_t expiresAt = 0;
		std::uint64_t files = 0;
		std::uint64_t directories = 0;
		bool archive = false;
	};

	struct ProjectUpload
	{
		std::string id;
		std::string url;
		std::string filename;
		std::uint64_t expiresAt = 0;
	};

	enum class ProjectDocumentKind
	{
		Text,
		Markdown,
		Json,
	};

	struct ProjectDocument
	{
		std::string path;
		ProjectDocumentKind kind = ProjectDocumentKind::Text;
		std::string content;
		std::uint64_t size = 0;
	};

	class ProjectManager
	{
	public:
		virtual ~ProjectManager() = default;

		virtual std::vector<ProjectSummary> List() const = 0;
		virtual Result<ProjectSummary> Create(
			std::string name, std::optional<std::string> path, std::string description) = 0;
		virtual Result<ProjectSummary> Update(
			std::string_view project, std::optional<std::string> name, std::optional<std::string> description) = 0;
		virtual Result<bool> Delete(std::string_view project) = 0;
		virtual Result<ProjectContents> Contents(std::string_view project) = 0;

		virtual Result<ProjectFolder> CreateFolder(
			std::string_view project, std::optional<std::string> parent, std::string name, std::string description) = 0;
		virtual Result<ProjectFolder> UpdateFolder(std::string_view project, std::string_view path,
			std::optional<std::string> name, std::optional<std::string> description,
			std::optional<std::optional<std::string>> parent) = 0;
		virtual Result<bool> DeleteFolder(std::string_view project, std::string_view path) = 0;

		virtual Result<ProjectFile> UpdateFile(std::string_view project, std::string_view path,
			std::optional<std::string> name, std::optional<std::string> description,
			std::optional<std::optional<std::string>> folder) = 0;
		virtual Result<bool> DeleteFile(std::string_view project, std::string_view path) = 0;

		virtual Result<ProjectDownload> Download(
			std::string_view project, ProjectDownloadKind kind, const std::vector<std::string>& paths) = 0;
		virtual Result<ProjectUpload> StartUpload(std::string_view project, std::string filename) = 0;
		virtual Result<ProjectFile> CommitUpload(std::string_view project, std::string_view upload,
			std::optional<std::string> folder, std::string description) = 0;
		virtual Result<ProjectDocument> ReadDocument(std::string_view project, std::string_view path) = 0;
	};
}  // namespace binjad::portal
