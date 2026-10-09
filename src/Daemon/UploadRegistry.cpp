#include "binjad/upload/UploadRegistry.hpp"

#include "binjad/platform/Paths.hpp"
#include "binjad/security/Random.hpp"

#include <algorithm>
#include <cctype>
#include <utility>

namespace binjad::upload {
	UploadTransfer::UploadTransfer(UploadRegistry& registry, std::string id, std::uint64_t maximum,
		std::uint64_t memoryThreshold, std::filesystem::path spoolDirectory) :
		registry_(&registry), id_(std::move(id)), maximum_(maximum), memoryThreshold_(memoryThreshold),
		spoolDirectory_(std::move(spoolDirectory)), spoolPath_(spoolDirectory_ / "content")
	{}

	UploadTransfer::~UploadTransfer()
	{
		Abort();
	}

	bool UploadTransfer::Spill(std::string& error)
	{
		std::string_view contents(memory_.empty() ? "" : memory_.data(), memory_.size());
		const auto created = platform::CreatePrivateFileIfAbsent(spoolPath_, contents);
		if (!created.created || !created.error.empty())
		{
			error = created.error.empty() ? "cannot create upload spool file" : created.error;
			return false;
		}
		stream_.open(spoolPath_, std::ios::binary | std::ios::app);
		if (!stream_)
		{
			error = "cannot open upload spool file";
			return false;
		}
		memory_.clear();
		memory_.shrink_to_fit();
		return true;
	}

	bool UploadTransfer::Write(std::string_view data, std::string& error)
	{
		if (!active_)
		{
			error = "upload transfer is not active";
			return false;
		}
		if (data.size() > maximum_ - size_)
		{
			error = "upload exceeds configured maximum";
			return false;
		}
		if (!stream_.is_open() && size_ + data.size() > memoryThreshold_ && !Spill(error))
			return false;
		if (stream_.is_open())
		{
			stream_.write(data.data(), static_cast<std::streamsize>(data.size()));
			if (!stream_)
			{
				error = "cannot write upload spool file";
				return false;
			}
		}
		else
		{
			memory_.insert(memory_.end(), data.begin(), data.end());
		}
		hasher_.Update(data);
		size_ += data.size();
		return true;
	}

	std::optional<UploadRecord> UploadTransfer::Finish(std::string& error)
	{
		if (!active_)
		{
			error = "upload transfer is not active";
			return std::nullopt;
		}
		if (stream_.is_open())
		{
			stream_.flush();
			if (!stream_)
			{
				error = "cannot flush upload spool file";
				return std::nullopt;
			}
			stream_.close();
		}
		auto result = registry_->Complete(id_, std::move(memory_),
			stream_.is_open() ?
				spoolPath_ :
				(std::filesystem::exists(spoolPath_) ? spoolPath_ : std::filesystem::path {}),
			size_, hasher_.FinalHex(), error);
		if (result)
			active_ = false;
		return result;
	}

	void UploadTransfer::Abort()
	{
		if (!active_)
			return;
		if (stream_.is_open())
			stream_.close();
		registry_->Abort(id_, spoolDirectory_);
		active_ = false;
	}

	UploadRegistry::UploadRegistry(Config config, reference::FriendlyReferencePool& references,
		session::AnalysisSessionRegistry& sessions, project::LocalProjectRegistry& projects) :
		config_(std::move(config)), references_(references), sessions_(sessions), projects_(projects)
	{}

	UploadRegistry::~UploadRegistry()
	{
		std::lock_guard lock(mutex_);
		while (!uploads_.empty())
			RemoveEntry(uploads_.begin());
	}

	bool UploadRegistry::ValidFilename(std::string_view filename)
	{
		if (filename.empty() || filename == "." || filename == ".." || filename.find('/') != std::string_view::npos
			|| filename.find('\\') != std::string_view::npos)
			return false;
		return std::none_of(filename.begin(), filename.end(), [](unsigned char value) {
			return std::iscntrl(value) != 0;
		});
	}

	UploadIssueResult UploadRegistry::Issue(std::string ownerTokenId, std::string analysisSession, std::string project,
		std::string filename, std::uint64_t nowUnix, Clock::time_point now)
	{
		if (!sessions_.Find(analysisSession, ownerTokenId, now))
			return {{}, {}, "analysis session not found"};
		return IssueValidated(
			std::move(ownerTokenId), std::move(analysisSession), std::move(project), std::move(filename), nowUnix, now);
	}

	UploadIssueResult UploadRegistry::IssuePortal(
		std::string project, std::string filename, std::uint64_t nowUnix, Clock::time_point now)
	{
		return IssueValidated(
			std::string(kPortalUploadOwner), {}, std::move(project), std::move(filename), nowUnix, now);
	}

	UploadIssueResult UploadRegistry::IssueValidated(std::string ownerTokenId, std::string analysisSession,
		std::string project, std::string filename, std::uint64_t nowUnix, Clock::time_point now)
	{
		if (!ValidFilename(filename))
			return {{}, {}, "filename must be one safe filename component"};
		if (!projects_.Find(project))
			return {{}, {}, "project not found"};
		auto reference = references_.Acquire();
		if (!reference.value)
			return {{}, {}, reference.error};
		auto capability = security::GenerateHex256();
		if (!capability.value)
		{
			references_.Release(*reference.value);
			return {{}, {}, capability.error};
		}
		const auto ttl = config_.uploads.urlTtl;
		UploadRecord record {*reference.value, std::move(ownerTokenId), std::move(analysisSession), std::move(project),
			std::move(filename), UploadState::Ready, nowUnix, nowUnix + static_cast<std::uint64_t>(ttl.count()), 0, {}};
		Entry entry {record, *capability.value, now + ttl, {}, {}, {}};
		{
			std::lock_guard lock(mutex_);
			capabilities_.emplace(entry.capability, record.id);
			uploads_.emplace(record.id, std::move(entry));
		}
		return {record, config_.http.publicBaseUrl + config_.http.uploadPath + "/" + *capability.value, {}};
	}

	std::pair<std::unique_ptr<UploadTransfer>, std::string> UploadRegistry::Begin(
		std::string_view capability, Clock::time_point now)
	{
		std::lock_guard lock(mutex_);
		const auto mapped = capabilities_.find(std::string(capability));
		if (mapped == capabilities_.end())
			return {std::unique_ptr<UploadTransfer> {}, std::string("upload not found")};
		const auto upload = uploads_.find(mapped->second);
		if (upload == uploads_.end() || now >= upload->second.expiresAt
			|| upload->second.record.state != UploadState::Ready)
			return {std::unique_ptr<UploadTransfer> {}, std::string("upload not found")};
		upload->second.record.state = UploadState::Receiving;
		const auto directory = config_.storage.spoolPath / "uploads" / upload->second.record.id;
		return {std::unique_ptr<UploadTransfer>(new UploadTransfer(*this, upload->second.record.id,
					config_.uploads.maxBytes, config_.uploads.memoryThresholdBytes, directory)),
			std::string {}};
	}

	std::optional<UploadRecord> UploadRegistry::Complete(std::string_view id, std::vector<char> memory,
		std::filesystem::path path, std::uint64_t size, std::string sha256, std::string& error)
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.state != UploadState::Receiving)
		{
			error = "upload not found";
			return std::nullopt;
		}
		upload->second.record.state = UploadState::Completed;
		upload->second.record.size = size;
		upload->second.record.sha256 = std::move(sha256);
		upload->second.memory = std::move(memory);
		upload->second.path = std::move(path);
		capabilities_.erase(upload->second.capability);
		upload->second.capability.clear();
		return upload->second.record;
	}

	void UploadRegistry::Abort(std::string_view id, const std::filesystem::path& spoolDirectory)
	{
		std::lock_guard lock(mutex_);
		if (const auto upload = uploads_.find(std::string(id));
			upload != uploads_.end() && upload->second.record.state == UploadState::Receiving)
			upload->second.record.state = UploadState::Ready;
		std::error_code ignored;
		std::filesystem::remove_all(spoolDirectory, ignored);
	}

	std::optional<UploadRecord> UploadRegistry::FindCompleted(std::string_view ownerTokenId,
		std::string_view analysisSession, std::string_view id, Clock::time_point now) const
	{
		(void)now;
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| upload->second.record.analysisSession != analysisSession
			|| upload->second.record.state != UploadState::Completed)
			return std::nullopt;
		return upload->second.record;
	}

	std::pair<std::optional<UploadPayload>, std::string> UploadRegistry::PreparePayload(
		std::string_view ownerTokenId, std::string_view analysisSession, std::string_view id, Clock::time_point now)
	{
		(void)now;
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| upload->second.record.analysisSession != analysisSession
			|| upload->second.record.state != UploadState::Completed)
			return {{}, "upload not found"};
		if (upload->second.path.empty())
		{
			const auto path = config_.storage.spoolPath / "uploads" / upload->second.record.id / "commit";
			const std::string_view contents(
				upload->second.memory.empty() ? "" : upload->second.memory.data(), upload->second.memory.size());
			const auto created = platform::CreatePrivateFileIfAbsent(path, contents);
			if (!created.created || !created.error.empty())
				return {{}, created.error.empty() ? "cannot stage upload payload" : created.error};
			upload->second.path = path;
		}
		auto payload = UploadPayload {upload->second.record, upload->second.path};
		upload->second.record.state = UploadState::Committing;
		return {std::move(payload), {}};
	}

	std::optional<std::string> UploadRegistry::FindCommitResult(
		std::string_view ownerTokenId, std::string_view analysisSession, std::string_view id) const
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| upload->second.record.analysisSession != analysisSession
			|| (upload->second.record.state != UploadState::Committing
				&& upload->second.record.state != UploadState::Committed)
			|| upload->second.commitResultJson.empty())
			return std::nullopt;
		return upload->second.commitResultJson;
	}

	bool UploadRegistry::RecordCommit(
		std::string_view ownerTokenId, std::string_view id, std::string resultJson, bool cleanupPayload)
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| (upload->second.record.state != UploadState::Committing
				&& upload->second.record.state != UploadState::Committed))
			return false;
		upload->second.commitResultJson = std::move(resultJson);
		if (cleanupPayload)
		{
			upload->second.record.state = UploadState::Committed;
			upload->second.memory.clear();
			upload->second.memory.shrink_to_fit();
			upload->second.path.clear();
			std::error_code ignored;
			std::filesystem::remove_all(config_.storage.spoolPath / "uploads" / upload->second.record.id, ignored);
		}
		return true;
	}

	bool UploadRegistry::CommitFailed(std::string_view ownerTokenId, std::string_view id)
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| upload->second.record.state != UploadState::Committing)
			return false;
		upload->second.record.state = UploadState::Completed;
		return true;
	}

	std::vector<UploadRecord> UploadRegistry::List(std::string_view ownerTokenId) const
	{
		std::lock_guard lock(mutex_);
		std::vector<UploadRecord> result;
		for (const auto& [id, upload] : uploads_)
		{
			if (upload.record.ownerTokenId == ownerTokenId)
				result.push_back(upload.record);
		}
		std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
			return left.createdAtUnix < right.createdAtUnix
				|| (left.createdAtUnix == right.createdAtUnix && left.id < right.id);
		});
		return result;
	}

	std::string UploadRegistry::Cancel(std::string_view ownerTokenId, std::string_view id)
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId)
			return "upload not found";
		if (upload->second.record.state == UploadState::Receiving
			|| upload->second.record.state == UploadState::Committing)
			return "active upload cannot be cancelled";
		RemoveEntry(upload);
		return {};
	}

	bool UploadRegistry::Consume(std::string_view ownerTokenId, std::string_view id)
	{
		std::lock_guard lock(mutex_);
		const auto upload = uploads_.find(std::string(id));
		if (upload == uploads_.end() || upload->second.record.ownerTokenId != ownerTokenId
			|| (upload->second.record.state != UploadState::Completed
				&& upload->second.record.state != UploadState::Committed))
			return false;
		RemoveEntry(upload);
		return true;
	}

	void UploadRegistry::RemoveByAnalysisSession(std::string_view analysisSession)
	{
		std::lock_guard lock(mutex_);
		for (auto upload = uploads_.begin(); upload != uploads_.end();)
		{
			if (upload->second.record.analysisSession == analysisSession)
				RemoveEntry(upload++);
			else
				++upload;
		}
	}

	void UploadRegistry::RemoveByToken(std::string_view ownerTokenId)
	{
		std::lock_guard lock(mutex_);
		for (auto upload = uploads_.begin(); upload != uploads_.end();)
		{
			if (upload->second.record.ownerTokenId == ownerTokenId)
				RemoveEntry(upload++);
			else
				++upload;
		}
	}

	void UploadRegistry::Sweep(Clock::time_point now)
	{
		std::lock_guard lock(mutex_);
		for (auto upload = uploads_.begin(); upload != uploads_.end();)
		{
			const bool inactivePortalUpload = upload->second.record.ownerTokenId == kPortalUploadOwner
				&& upload->second.record.state != UploadState::Receiving
				&& upload->second.record.state != UploadState::Committing;
			if (now >= upload->second.expiresAt
				&& (upload->second.record.state == UploadState::Ready || inactivePortalUpload))
				RemoveEntry(upload++);
			else
				++upload;
		}
	}

	void UploadRegistry::RemoveEntry(std::unordered_map<std::string, Entry>::iterator entry)
	{
		if (!entry->second.capability.empty())
			capabilities_.erase(entry->second.capability);
		references_.Release(entry->second.record.id);
		std::error_code ignored;
		std::filesystem::remove_all(config_.storage.spoolPath / "uploads" / entry->second.record.id, ignored);
		uploads_.erase(entry);
	}

	std::size_t UploadRegistry::Size() const
	{
		std::lock_guard lock(mutex_);
		return uploads_.size();
	}
}  // namespace binjad::upload
