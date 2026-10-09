#include "binjad/download/ProjectDownload.hpp"

#include "binjad/download/ZipArchive.hpp"
#include "binjad/security/Crypto.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <system_error>
#include <utility>

namespace binjad::download {
	namespace {
		std::string SafeAttachmentName(std::string_view requested, std::string_view fallback)
		{
			std::string result;
			result.reserve(std::min<std::size_t>(requested.size(), 200));
			for (const unsigned char character : requested)
			{
				if (result.size() == 200)
					break;
				const bool punctuation = character == '.' || character == '_' || character == '-';
				const bool safe = character < 0x80 && (std::isalnum(character) != 0 || punctuation);
				result.push_back(safe ? static_cast<char>(character) : '_');
			}
			if (result.empty() || result == "." || result == "..")
				result = fallback;
			return result;
		}

		bool Report(const ProjectDownloadProgress& progress, std::string_view phase, std::uint64_t completed,
			std::uint64_t total, std::string_view message)
		{
			return !progress || progress(phase, completed, total, message);
		}

		void Remove(const std::filesystem::path& path)
		{
			if (path.empty())
				return;
			std::error_code ignored;
			std::filesystem::remove_all(path, ignored);
		}

		class WorkingDirectoryGuard
		{
		public:
			explicit WorkingDirectoryGuard(std::filesystem::path path) : path_(std::move(path)) {}
			~WorkingDirectoryGuard() { Remove(path_); }
			void Release() { path_.clear(); }

		private:
			std::filesystem::path path_;
		};
	}  // namespace

	ProjectArtifactResult PrepareProjectArtifact(overseer::ProjectChildCoordinator& coordinator,
		std::string_view project, overseer::ProjectDownloadKind kind, const std::vector<std::string>& paths,
		std::string attachmentSeed, const ProjectDownloadProgress& progress)
	{
		if (!Report(progress, "export", 0, 1, "Exporting project content"))
			return {{}, {}, true};
		auto prepared = coordinator.PrepareDownload(project, kind, paths);
		if (!prepared.value)
			return {{}, prepared.error, false};
		const auto workingDirectory = prepared.value->workingDirectory;
		WorkingDirectoryGuard cleanup(workingDirectory);
		if (!Report(progress, "export", 1, 1, "Project content exported"))
			return {{}, {}, true};

		PreparedProjectArtifact artifact;
		artifact.workingDirectory = workingDirectory;
		artifact.archive = kind != overseer::ProjectDownloadKind::File;
		artifact.files = prepared.value->files;
		artifact.directories = prepared.value->directories;
		if (artifact.archive)
		{
			artifact.path = workingDirectory / "download.zip";
			if (kind == overseer::ProjectDownloadKind::Project)
				attachmentSeed = prepared.value->rootName;
			artifact.attachmentName = SafeAttachmentName(attachmentSeed, "project") + ".zip";
			artifact.contentType = "application/zip";
			const auto zipped = CreateZipArchive(prepared.value->contentDirectory, artifact.path,
				[&](std::uint64_t completed, std::uint64_t total, std::string_view current) {
					return Report(progress, "archive", completed, total, current);
				});
			if (!zipped.created)
				return {{}, zipped.cancelled ? std::string {} : zipped.error, zipped.cancelled};
			artifact.files = zipped.files;
			artifact.directories = zipped.directories;
		}
		else
		{
			artifact.path = prepared.value->contentDirectory / std::filesystem::path(paths.front());
			artifact.attachmentName =
				SafeAttachmentName(std::filesystem::path(paths.front()).filename().string(), "project-file");
			artifact.contentType = "application/octet-stream";
		}

		std::error_code error;
		artifact.size = std::filesystem::file_size(artifact.path, error);
		if (error)
			return {{}, "cannot inspect prepared download: " + error.message(), false};
		std::ifstream input(artifact.path, std::ios::binary);
		if (!input)
			return {{}, "cannot open prepared download", false};
		security::Sha256Hasher hasher;
		std::vector<char> buffer(1024 * 1024);
		std::uint64_t completed = 0;
		while (input)
		{
			input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
			const auto count = input.gcount();
			if (count > 0)
				hasher.Update(std::string_view(buffer.data(), static_cast<std::size_t>(count)));
			completed += static_cast<std::uint64_t>(count);
			if (!Report(progress, "hash", completed, artifact.size, artifact.path.filename().string()))
				return {{}, {}, true};
		}
		if (input.bad())
			return {{}, "cannot read prepared download", false};
		artifact.sha256 = hasher.FinalHex();
		cleanup.Release();
		return {std::move(artifact), {}, false};
	}
}  // namespace binjad::download
