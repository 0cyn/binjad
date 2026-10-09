#include "binjad/portal/LocalProjectManager.hpp"

#include "binjad/download/DownloadRegistry.hpp"
#include "binjad/download/ProjectDownload.hpp"
#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/project/LocalProjectRegistry.hpp"
#include "binjad/session/OpenItemRegistry.hpp"
#include "binjad/upload/UploadRegistry.hpp"

#include <rapidjsonwrapper.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <system_error>

namespace binjad::portal {
	namespace {
		std::uint64_t CurrentUnixSeconds()
		{
			return static_cast<std::uint64_t>(
				std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
					.count());
		}

		bool SafeProjectFilename(std::string_view value)
		{
			return !value.empty() && value != "." && value != ".."
				&& std::none_of(value.begin(), value.end(), [](unsigned char character) {
					   return character < 0x20 || character == 0x7f || character == '/' || character == '\\';
				   });
		}

		std::optional<std::string> ProjectPath(std::string_view value)
		{
			const std::filesystem::path supplied(value);
			const auto normalized = supplied.lexically_normal();
			if (value.empty() || supplied.is_absolute() || normalized.empty() || normalized == "."
				|| *normalized.begin() == "..")
				return std::nullopt;
			return normalized.generic_string();
		}

		ProjectSummary Summary(const project::LocalProjectRecord& project)
		{
			return {project.reference, project.name, project.description};
		}

		ProjectFolder Folder(const project::LocalProjectFolderRecord& folder)
		{
			return {folder.path, folder.name, folder.description, folder.parentPath};
		}

		ProjectFile File(const project::LocalProjectFileRecord& file)
		{
			return {file.path, file.name, file.description, file.creationTimestamp, file.folderPath};
		}

		overseer::ProjectDownloadKind DownloadKind(ProjectDownloadKind kind)
		{
			switch (kind)
			{
			case ProjectDownloadKind::File:
				return overseer::ProjectDownloadKind::File;
			case ProjectDownloadKind::Files:
				return overseer::ProjectDownloadKind::Files;
			case ProjectDownloadKind::Folder:
				return overseer::ProjectDownloadKind::Folder;
			case ProjectDownloadKind::Project:
				return overseer::ProjectDownloadKind::Project;
			}
			return overseer::ProjectDownloadKind::Project;
		}

		void RemoveDirectory(const std::filesystem::path& path)
		{
			std::error_code ignored;
			std::filesystem::remove_all(path, ignored);
		}

		class ScopedWorkingDirectory
		{
		public:
			explicit ScopedWorkingDirectory(std::filesystem::path path) : path_(std::move(path)) {}
			~ScopedWorkingDirectory() { RemoveDirectory(path_); }

		private:
			std::filesystem::path path_;
		};

		std::optional<ProjectDocumentKind> DocumentKind(std::string_view path)
		{
			auto extension = std::filesystem::path(path).extension().string();
			std::transform(extension.begin(), extension.end(), extension.begin(), [](unsigned char character) {
				return static_cast<char>(std::tolower(character));
			});
			if (extension == ".txt")
				return ProjectDocumentKind::Text;
			if (extension == ".md")
				return ProjectDocumentKind::Markdown;
			if (extension == ".json")
				return ProjectDocumentKind::Json;
			return std::nullopt;
		}

		bool ValidUtf8(std::string_view value)
		{
			for (std::size_t offset = 0; offset < value.size();)
			{
				const auto first = static_cast<unsigned char>(value[offset]);
				std::uint32_t codepoint = 0;
				std::size_t length = 1;
				if (first <= 0x7f)
					codepoint = first;
				else if (first >= 0xc2 && first <= 0xdf)
				{
					codepoint = first & 0x1f;
					length = 2;
				}
				else if (first >= 0xe0 && first <= 0xef)
				{
					codepoint = first & 0x0f;
					length = 3;
				}
				else if (first >= 0xf0 && first <= 0xf4)
				{
					codepoint = first & 0x07;
					length = 4;
				}
				else
					return false;
				if (offset + length > value.size())
					return false;
				for (std::size_t index = 1; index < length; ++index)
				{
					const auto continuation = static_cast<unsigned char>(value[offset + index]);
					if ((continuation & 0xc0) != 0x80)
						return false;
					codepoint = (codepoint << 6) | (continuation & 0x3f);
				}
				if ((length == 3 && codepoint < 0x800) || (length == 4 && codepoint < 0x10000)
					|| (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
					return false;
				offset += length;
			}
			return true;
		}
	}  // namespace

	LocalProjectManager::LocalProjectManager(Config config, std::shared_ptr<project::LocalProjectRegistry> projects,
		std::shared_ptr<session::OpenItemRegistry> openItems,
		std::shared_ptr<overseer::ProjectChildCoordinator> coordinator,
		std::shared_ptr<download::DownloadRegistry> downloads, std::shared_ptr<upload::UploadRegistry> uploads) :
		config_(std::move(config)), projects_(std::move(projects)), openItems_(std::move(openItems)),
		coordinator_(std::move(coordinator)), downloads_(std::move(downloads)), uploads_(std::move(uploads))
	{}

	std::vector<ProjectSummary> LocalProjectManager::List() const
	{
		const auto projects = projects_.lock();
		if (!projects)
			return {};
		std::vector<ProjectSummary> result;
		for (const auto& project : projects->List())
			result.push_back(Summary(project));
		return result;
	}

	Result<ProjectSummary> LocalProjectManager::Create(
		std::string name, std::optional<std::string> path, std::string description)
	{
		const auto coordinator = coordinator_.lock();
		if (!coordinator)
			return {{}, "local project service is unavailable"};
		if (!path)
		{
			if (!config_.projects.defaultRoot)
				return {{}, "project creation requires a configured default project root"};
			if (!SafeProjectFilename(name))
				return {{}, "project name cannot be used as a filename; provide a path"};
			path = name + ".bnpr";
		}

		const std::filesystem::path supplied(*path);
		const auto normalized = supplied.lexically_normal();
		std::filesystem::path destination;
		if (supplied.is_absolute())
		{
			if (!config_.projects.allowProjectRegistration)
				return {{}, "outside-root project creation is disabled"};
			if (normalized.extension() != ".bnpr")
				return {{}, "absolute project path must end in .bnpr"};
			destination = normalized;
		}
		else
		{
			if (!config_.projects.defaultRoot || normalized.empty() || normalized == "." || *normalized.begin() == ".."
				|| normalized.extension() != ".bnpr")
				return {{}, "project path must stay inside the default root and end in .bnpr"};
			destination = (*config_.projects.defaultRoot / normalized).lexically_normal();
		}
		const auto created = coordinator->CreateProject(destination, std::move(name), std::move(description));
		return created.value ?
			Result<ProjectSummary> {Summary(*created.value), {}} :
			Result<ProjectSummary> {{}, created.error};
	}

	Result<ProjectSummary> LocalProjectManager::Update(
		std::string_view project, std::optional<std::string> name, std::optional<std::string> description)
	{
		const auto coordinator = coordinator_.lock();
		if (!coordinator)
			return {{}, "local project service is unavailable"};
		const auto updated = coordinator->UpdateProject(project, std::move(name), std::move(description));
		return updated.value ?
			Result<ProjectSummary> {Summary(*updated.value), {}} :
			Result<ProjectSummary> {{}, updated.error};
	}

	Result<bool> LocalProjectManager::Delete(std::string_view project)
	{
		const auto projects = projects_.lock();
		const auto openItems = openItems_.lock();
		const auto coordinator = coordinator_.lock();
		if (!projects || !openItems || !coordinator)
			return {{}, "local project service is unavailable"};
		if (!projects->Find(project))
			return {{}, "project not found"};
		if (openItems->HasProject(project))
			return {{}, "project has open analysis handles"};
		const auto error = coordinator->DeleteProject(project);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<ProjectContents> LocalProjectManager::Contents(std::string_view reference)
	{
		const auto projects = projects_.lock();
		const auto coordinator = coordinator_.lock();
		if (!projects || !coordinator)
			return {{}, "local project service is unavailable"};
		const auto project = projects->Find(reference);
		if (!project)
			return {{}, "project not found"};
		const auto folders = coordinator->ListFolders(reference);
		if (!folders.value)
			return {{}, folders.error};
		const auto files = coordinator->ListFiles(reference);
		if (!files.value)
			return {{}, files.error};
		ProjectContents result;
		result.project = Summary(*project);
		for (const auto& folder : *folders.value)
			result.folders.push_back(Folder(folder));
		for (const auto& file : *files.value)
			result.files.push_back(File(file));
		return {std::move(result), {}};
	}

	Result<ProjectFolder> LocalProjectManager::CreateFolder(
		std::string_view project, std::optional<std::string> parent, std::string name, std::string description)
	{
		const auto coordinator = coordinator_.lock();
		if (!coordinator)
			return {{}, "local project service is unavailable"};
		std::optional<std::string> parentId;
		if (parent)
		{
			const auto normalized = ProjectPath(*parent);
			if (!normalized)
				return {{}, "parent must be a contained project-relative path"};
			const auto found = coordinator->FindFolder(project, *normalized);
			if (!found.value)
				return {{}, found.error};
			parentId = found.value->internalId;
		}
		const auto created = coordinator->CreateFolder(project,
			parentId ? std::optional<std::string_view>(*parentId) : std::nullopt, std::move(name),
			std::move(description));
		return created.value ?
			Result<ProjectFolder> {Folder(*created.value), {}} :
			Result<ProjectFolder> {{}, created.error};
	}

	Result<ProjectFolder> LocalProjectManager::UpdateFolder(std::string_view project, std::string_view path,
		std::optional<std::string> name, std::optional<std::string> description,
		std::optional<std::optional<std::string>> parent)
	{
		const auto coordinator = coordinator_.lock();
		const auto openItems = openItems_.lock();
		if (!coordinator || !openItems)
			return {{}, "local project service is unavailable"};
		const auto normalized = ProjectPath(path);
		if (!normalized)
			return {{}, "folder path must be a contained project-relative path"};
		const auto previous = coordinator->FindFolder(project, *normalized);
		if (!previous.value)
			return {{}, previous.error};
		std::optional<std::optional<std::string>> parentId;
		if (parent)
		{
			parentId = std::optional<std::string> {};
			if (*parent)
			{
				const auto parentPath = ProjectPath(**parent);
				if (!parentPath)
					return {{}, "parent must be a contained project-relative path"};
				const auto found = coordinator->FindFolder(project, *parentPath);
				if (!found.value)
					return {{}, found.error};
				parentId = std::optional<std::string>(found.value->internalId);
			}
		}
		const auto updated = coordinator->UpdateFolder(
			project, previous.value->internalId, std::move(name), std::move(description), std::move(parentId));
		if (!updated.value)
			return {{}, updated.error};
		if (previous.value->path != updated.value->path)
			openItems->UpdateProjectSourcePrefix(project, previous.value->path, updated.value->path);
		return {Folder(*updated.value), {}};
	}

	Result<bool> LocalProjectManager::DeleteFolder(std::string_view project, std::string_view path)
	{
		const auto coordinator = coordinator_.lock();
		const auto openItems = openItems_.lock();
		if (!coordinator || !openItems)
			return {{}, "local project service is unavailable"};
		const auto normalized = ProjectPath(path);
		if (!normalized)
			return {{}, "folder path must be a contained project-relative path"};
		const auto existing = coordinator->FindFolder(project, *normalized);
		if (!existing.value)
			return {{}, existing.error};
		if (openItems->HasProjectSourcePrefix(project, existing.value->path))
			return {{}, "project folder contains an open analysis handle"};
		const auto error = coordinator->DeleteFolder(project, existing.value->internalId, true);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<ProjectFile> LocalProjectManager::UpdateFile(std::string_view project, std::string_view path,
		std::optional<std::string> name, std::optional<std::string> description,
		std::optional<std::optional<std::string>> folder)
	{
		const auto projects = projects_.lock();
		const auto coordinator = coordinator_.lock();
		const auto openItems = openItems_.lock();
		if (!projects || !coordinator || !openItems)
			return {{}, "local project service is unavailable"};
		const auto normalized = ProjectPath(path);
		if (!normalized)
			return {{}, "file path must be a contained project-relative path"};
		const auto listed = coordinator->ListFiles(project);
		if (!listed.value)
			return {{}, listed.error};
		const auto previous = projects->FindFile(project, *normalized);
		if (!previous)
			return {{}, "project file not found"};
		std::optional<std::optional<std::string>> folderId;
		if (folder)
		{
			folderId = std::optional<std::string> {};
			if (*folder)
			{
				const auto folderPath = ProjectPath(**folder);
				if (!folderPath)
					return {{}, "folder must be a contained project-relative path"};
				const auto found = coordinator->FindFolder(project, *folderPath);
				if (!found.value)
					return {{}, found.error};
				folderId = std::optional<std::string>(found.value->internalId);
			}
		}
		const auto updated =
			coordinator->UpdateFile(project, *normalized, std::move(name), std::move(description), std::move(folderId));
		if (!updated.value)
			return {{}, updated.error};
		if (previous->path != updated.value->path)
			openItems->UpdateProjectSource(project, previous->path, updated.value->path);
		return {File(*updated.value), {}};
	}

	Result<bool> LocalProjectManager::DeleteFile(std::string_view project, std::string_view path)
	{
		const auto projects = projects_.lock();
		const auto coordinator = coordinator_.lock();
		const auto openItems = openItems_.lock();
		if (!projects || !coordinator || !openItems)
			return {{}, "local project service is unavailable"};
		const auto normalized = ProjectPath(path);
		if (!normalized)
			return {{}, "file path must be a contained project-relative path"};
		const auto listed = coordinator->ListFiles(project);
		if (!listed.value)
			return {{}, listed.error};
		if (!projects->FindFile(project, *normalized))
			return {{}, "project file not found"};
		if (openItems->HasProjectSource(project, *normalized))
			return {{}, "project file has an open analysis handle"};
		const auto error = coordinator->DeleteFile(project, *normalized, true);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<ProjectDownload> LocalProjectManager::Download(
		std::string_view project, ProjectDownloadKind kind, const std::vector<std::string>& paths)
	{
		const auto projects = projects_.lock();
		const auto coordinator = coordinator_.lock();
		const auto downloads = downloads_.lock();
		if (!projects || !coordinator || !downloads)
			return {{}, "local project and download services are required"};
		const auto record = projects->Find(project);
		if (!record)
			return {{}, "project not found"};
		std::string attachmentSeed;
		if (kind == ProjectDownloadKind::Files)
			attachmentSeed = record->name + "-files";
		else if (kind == ProjectDownloadKind::Folder && !paths.empty())
			attachmentSeed = std::filesystem::path(paths.front()).filename().string();
		const auto prepared = download::PrepareProjectArtifact(
			*coordinator, project, DownloadKind(kind), paths, std::move(attachmentSeed));
		if (!prepared.artifact)
			return {{}, prepared.cancelled ? "download preparation cancelled" : prepared.error};
		const auto issued = downloads->IssuePortal(std::string(project), prepared.artifact->path,
			prepared.artifact->workingDirectory, prepared.artifact->attachmentName, prepared.artifact->contentType,
			prepared.artifact->size, prepared.artifact->sha256, CurrentUnixSeconds(),
			download::DownloadRegistry::Clock::now());
		if (!issued.download)
		{
			RemoveDirectory(prepared.artifact->workingDirectory);
			return {{}, issued.error};
		}
		return {
			ProjectDownload {issued.url, issued.download->attachmentName, issued.download->contentType,
				issued.download->sha256, issued.download->size, issued.download->expiresAtUnix,
				prepared.artifact->files, prepared.artifact->directories, prepared.artifact->archive},
			{}};
	}

	Result<ProjectUpload> LocalProjectManager::StartUpload(std::string_view project, std::string filename)
	{
		const auto uploads = uploads_.lock();
		if (!uploads)
			return {{}, "upload service is unavailable"};
		const auto issued = uploads->IssuePortal(
			std::string(project), std::move(filename), CurrentUnixSeconds(), upload::UploadRegistry::Clock::now());
		if (!issued.upload)
			return {{}, issued.error};
		return {
			ProjectUpload {issued.upload->id, issued.url, issued.upload->filename, issued.upload->expiresAtUnix}, {}};
	}

	Result<ProjectFile> LocalProjectManager::CommitUpload(
		std::string_view project, std::string_view upload, std::optional<std::string> folder, std::string description)
	{
		const auto coordinator = coordinator_.lock();
		const auto uploads = uploads_.lock();
		if (!coordinator || !uploads)
			return {{}, "local project and upload services are required"};
		auto payload =
			uploads->PreparePayload(upload::kPortalUploadOwner, {}, upload, upload::UploadRegistry::Clock::now());
		if (!payload.first)
			return {{}, payload.second};
		if (payload.first->upload.project != project)
		{
			uploads->CommitFailed(upload::kPortalUploadOwner, upload);
			return {{}, "upload belongs to another project"};
		}
		std::filesystem::path destination(payload.first->upload.filename);
		if (folder)
		{
			const auto normalized = ProjectPath(*folder);
			if (!normalized)
			{
				uploads->CommitFailed(upload::kPortalUploadOwner, upload);
				return {{}, "folder must be a contained project-relative path"};
			}
			destination = std::filesystem::path(*normalized) / destination;
		}
		const auto committed = coordinator->CommitFile(
			project, destination.generic_string(), payload.first->path, false, false, description);
		if (!committed.value)
		{
			uploads->CommitFailed(upload::kPortalUploadOwner, upload);
			return {{}, committed.error};
		}
		if (!uploads->RecordCommit(upload::kPortalUploadOwner, upload, "{}"))
			return {{}, "project file was imported but upload cleanup failed"};
		if (!uploads->Consume(upload::kPortalUploadOwner, upload))
			return {{}, "project file was imported but upload cleanup failed"};
		const auto refreshed = coordinator->ListFiles(project);
		if (refreshed.value)
		{
			const auto found = std::find_if(refreshed.value->begin(), refreshed.value->end(), [&](const auto& file) {
				return file.path == committed.value->path;
			});
			if (found != refreshed.value->end())
				return {File(*found), {}};
		}
		return {File(*committed.value), {}};
	}

	Result<ProjectDocument> LocalProjectManager::ReadDocument(std::string_view project, std::string_view path)
	{
		constexpr std::uint64_t kMaximumDocumentBytes = 8ull * 1024 * 1024;
		const auto kind = DocumentKind(path);
		if (!kind)
			return {{}, "project document must use a .txt, .md, or .json extension"};
		const auto coordinator = coordinator_.lock();
		if (!coordinator)
			return {{}, "local project service is unavailable"};
		const auto exported = coordinator->ExportFile(project, path);
		if (!exported.value)
			return {{}, exported.error};
		ScopedWorkingDirectory cleanup(exported.value->workingDirectory);

		std::error_code filesystemError;
		const auto size = std::filesystem::file_size(exported.value->path, filesystemError);
		if (filesystemError)
			return {{}, "cannot inspect project document: " + filesystemError.message()};
		if (size > kMaximumDocumentBytes)
			return {{}, "project document exceeds the 8 MiB reading limit"};
		std::ifstream input(exported.value->path, std::ios::binary);
		if (!input)
			return {{}, "cannot read project document"};
		std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
		if (input.bad())
			return {{}, "cannot read project document"};
		if (content.starts_with("\xef\xbb\xbf"))
			content.erase(0, 3);
		if (content.find('\0') != std::string::npos || !ValidUtf8(content))
			return {{}, "project document is not valid UTF-8 text"};

		if (*kind == ProjectDocumentKind::Json)
		{
			rapidjson::Document parsed;
			try
			{
				parsed.Parse<rapidjson::kParseValidateEncodingFlag>(content.data(), content.size());
			}
			catch (const ParseException& exception)
			{
				return {{}, "invalid project JSON at byte " + std::to_string(exception.Offset())};
			}
			if (parsed.HasParseError())
				return {{}, "invalid project JSON at byte " + std::to_string(parsed.GetErrorOffset())};
			rapidjson::StringBuffer buffer;
			rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
			writer.SetIndent(' ', 2);
			parsed.Accept(writer);
			content.assign(buffer.GetString(), buffer.GetSize());
		}
		return {ProjectDocument {std::string(path), *kind, std::move(content), size}, {}};
	}
}  // namespace binjad::portal
