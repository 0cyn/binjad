#include "binjad/download/DownloadRegistry.hpp"

#include "binjad/security/Random.hpp"

#include <algorithm>
#include <cctype>
#include <limits>

namespace binjad::download {
	namespace {
		bool SafeAttachmentName(std::string_view name)
		{
			if (name.empty() || name == "." || name == ".." || name.size() > 255)
				return false;
			return std::all_of(name.begin(), name.end(), [](unsigned char character) {
				return character < 0x80
					&& (std::isalnum(character) != 0 || character == '.' || character == '_' || character == '-');
			});
		}

		bool Contained(const std::filesystem::path& path, const std::filesystem::path& directory)
		{
			const auto relative = path.lexically_normal().lexically_relative(directory.lexically_normal());
			return !relative.empty() && !relative.is_absolute() && *relative.begin() != "..";
		}
	}  // namespace

	DownloadRegistry::DownloadRegistry(Config config, session::AnalysisSessionRegistry& sessions,
		project::LocalProjectRegistry& projects) : config_(std::move(config)), sessions_(sessions), projects_(projects)
	{}

	DownloadRegistry::~DownloadRegistry()
	{
		std::lock_guard lock(mutex_);
		while (!downloads_.empty())
			RemoveEntry(downloads_.begin());
	}

	DownloadIssueResult DownloadRegistry::Issue(std::string ownerTokenId, std::string analysisSession,
		std::string project, std::filesystem::path artifactPath, std::filesystem::path workingDirectory,
		std::string attachmentName, std::string contentType, std::uint64_t size, std::string sha256,
		std::uint64_t nowUnix, Clock::time_point now)
	{
		if (!sessions_.Find(analysisSession, ownerTokenId, now))
			return {{}, {}, "analysis session not found"};
		return IssueValidated(std::move(ownerTokenId), std::move(analysisSession), std::move(project),
			std::move(artifactPath), std::move(workingDirectory), std::move(attachmentName), std::move(contentType),
			size, std::move(sha256), nowUnix, now);
	}

	DownloadIssueResult DownloadRegistry::IssuePortal(std::string project, std::filesystem::path artifactPath,
		std::filesystem::path workingDirectory, std::string attachmentName, std::string contentType, std::uint64_t size,
		std::string sha256, std::uint64_t nowUnix, Clock::time_point now)
	{
		return IssueValidated("portal", {}, std::move(project), std::move(artifactPath), std::move(workingDirectory),
			std::move(attachmentName), std::move(contentType), size, std::move(sha256), nowUnix, now);
	}

	DownloadIssueResult DownloadRegistry::IssueValidated(std::string ownerTokenId, std::string analysisSession,
		std::string project, std::filesystem::path artifactPath, std::filesystem::path workingDirectory,
		std::string attachmentName, std::string contentType, std::uint64_t size, std::string sha256,
		std::uint64_t nowUnix, Clock::time_point now)
	{
		if (!projects_.Find(project))
			return {{}, {}, "project not found"};
		if (!SafeAttachmentName(attachmentName))
			return {{}, {}, "download attachment name is unsafe"};
		if (contentType != "application/octet-stream" && contentType != "application/zip")
			return {{}, {}, "download content type is unsupported"};
		if (!artifactPath.is_absolute() || !workingDirectory.is_absolute()
			|| !Contained(artifactPath, workingDirectory))
			return {{}, {}, "download artifact is outside its working directory"};
		std::error_code error;
		const auto status = std::filesystem::symlink_status(artifactPath, error);
		if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status))
			return {{}, {}, "download artifact is not a non-symlink regular file"};
		if (std::filesystem::file_size(artifactPath, error) != size || error)
			return {{}, {}, "download artifact size changed"};
		if (sha256.size() != 64 || !std::all_of(sha256.begin(), sha256.end(), [](unsigned char character) {
				return std::isdigit(character) != 0 || (character >= 'a' && character <= 'f');
			}))
			return {{}, {}, "download artifact digest is invalid"};
		if (nowUnix > std::numeric_limits<std::uint64_t>::max() - static_cast<std::uint64_t>(kDownloadTtl.count()))
			return {{}, {}, "download expiry overflows Unix time"};

		auto capability = security::GenerateHex256();
		if (!capability.value)
			return {{}, {}, capability.error};
		DownloadRecord record {std::move(ownerTokenId), std::move(analysisSession), std::move(project),
			std::move(artifactPath), std::move(workingDirectory), std::move(attachmentName), std::move(contentType),
			std::move(sha256), size, nowUnix, nowUnix + static_cast<std::uint64_t>(kDownloadTtl.count()), false};
		{
			std::lock_guard lock(mutex_);
			downloads_.emplace(*capability.value, Entry {record, now + kDownloadTtl});
		}
		return {record, config_.http.publicBaseUrl + std::string(binjad::kDownloadPath) + "/" + *capability.value, {}};
	}

	std::optional<DownloadRecord> DownloadRegistry::Claim(std::string_view capability, Clock::time_point now)
	{
		std::lock_guard lock(mutex_);
		const auto found = downloads_.find(std::string(capability));
		if (found == downloads_.end() || found->second.record.consumed || now >= found->second.expiresAt)
			return std::nullopt;
		std::error_code error;
		const auto status = std::filesystem::symlink_status(found->second.record.artifactPath, error);
		if (error || std::filesystem::is_symlink(status) || !std::filesystem::is_regular_file(status))
			return std::nullopt;
		found->second.record.consumed = true;
		return found->second.record;
	}

	void DownloadRegistry::RemoveByAnalysisSession(std::string_view analysisSession)
	{
		std::lock_guard lock(mutex_);
		for (auto entry = downloads_.begin(); entry != downloads_.end();)
		{
			if (entry->second.record.analysisSession == analysisSession && !entry->second.record.consumed)
				RemoveEntry(entry++);
			else
				++entry;
		}
	}

	void DownloadRegistry::RemoveByToken(std::string_view ownerTokenId)
	{
		std::lock_guard lock(mutex_);
		for (auto entry = downloads_.begin(); entry != downloads_.end();)
		{
			if (entry->second.record.ownerTokenId == ownerTokenId && !entry->second.record.consumed)
				RemoveEntry(entry++);
			else
				++entry;
		}
	}

	void DownloadRegistry::Sweep(Clock::time_point now)
	{
		std::lock_guard lock(mutex_);
		for (auto entry = downloads_.begin(); entry != downloads_.end();)
		{
			if (now >= entry->second.expiresAt)
				RemoveEntry(entry++);
			else
				++entry;
		}
	}

	std::size_t DownloadRegistry::Size() const
	{
		std::lock_guard lock(mutex_);
		return downloads_.size();
	}

	void DownloadRegistry::RemoveEntry(EntryMap::iterator entry)
	{
		std::error_code ignored;
		std::filesystem::remove_all(entry->second.record.workingDirectory, ignored);
		downloads_.erase(entry);
	}
}  // namespace binjad::download
