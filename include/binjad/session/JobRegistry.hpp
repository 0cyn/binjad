#pragma once

#include "binjad/reference/FriendlyReference.hpp"
#include "binjad/session/AnalysisSessionRegistry.hpp"

#include <cstdint>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

namespace binjad::session {
	enum class JobState
	{
		Queued,
		Running,
		Complete,
		Failed,
		Cancelled,
	};

	struct JobProgress
	{
		std::uint64_t sequence = 0;
		std::uint64_t timestampUnix = 0;
		std::string phase;
		std::uint64_t completed = 0;
		std::uint64_t total = 0;
		std::string message;
	};

	struct JobRecord
	{
		std::string reference;
		std::string ownerTokenId;
		std::optional<std::string> analysisSession;
		std::optional<std::string> binaryView;
		std::string operation;
		JobState state = JobState::Queued;
		std::uint64_t createdAtUnix = 0;
		std::uint64_t updatedAtUnix = 0;
		std::optional<JobProgress> progress;
		bool cancelRequested = false;
		std::string resultJson;
	};

	struct JobResult
	{
		std::optional<JobRecord> job;
		std::string error;
	};

	class JobRegistry
	{
	public:
		using Clock = AnalysisSessionRegistry::Clock;
		using CancelCallback = std::function<std::string()>;
		using ProgressCallback = std::function<void(const JobRecord&)>;
		using ChangedCallback = std::function<void(const JobRecord&)>;

		JobRegistry(reference::FriendlyReferencePool& references, AnalysisSessionRegistry& sessions);
		JobRegistry(const JobRegistry&) = delete;
		JobRegistry& operator=(const JobRegistry&) = delete;
		~JobRegistry();

		JobResult Create(std::string ownerTokenId, std::optional<std::string> analysisSession,
			std::optional<std::string> binaryView, std::string operation, std::uint64_t nowUnix, Clock::time_point now,
			CancelCallback cancel = {});
		bool Start(std::string_view ownerTokenId, std::string_view job, std::uint64_t nowUnix);
		bool ReportProgress(std::string_view ownerTokenId, std::string_view job, std::string phase,
			std::uint64_t completed, std::uint64_t total, std::string message, std::uint64_t nowUnix);
		bool Complete(
			std::string_view ownerTokenId, std::string_view job, std::string resultJson, std::uint64_t nowUnix);
		bool Fail(std::string_view ownerTokenId, std::string_view job, std::string resultJson, std::uint64_t nowUnix);
		bool MarkCancelled(
			std::string_view ownerTokenId, std::string_view job, std::string resultJson, std::uint64_t nowUnix);
		JobResult Info(std::string_view ownerTokenId, std::string_view job) const;
		JobResult WaitForTerminal(std::string_view ownerTokenId, std::string_view job, Clock::duration timeout) const;
		std::vector<JobRecord> List(std::string_view ownerTokenId) const;
		JobResult TakeResult(std::string_view ownerTokenId, std::string_view job);
		std::string Cancel(std::string_view ownerTokenId, std::string_view job);
		void CancelByToken(std::string_view ownerTokenId);
		void RemoveByToken(std::string_view ownerTokenId);
		std::string StartWorker(std::function<void()> worker);
		void SetProgressCallback(ProgressCallback callback);
		void SetChangedCallback(ChangedCallback callback);
		std::size_t Size() const;

	private:
		struct Entry
		{
			JobRecord record;
			CancelCallback cancel;
			bool sessionRetained = false;
		};

		bool Finish(std::string_view ownerTokenId, std::string_view job, JobState state, std::string resultJson,
			std::uint64_t nowUnix);
		void ReleaseSession(Entry& entry);

		reference::FriendlyReferencePool& references_;
		AnalysisSessionRegistry& sessions_;
		std::unordered_map<std::string, Entry> jobs_;
		ProgressCallback progressCallback_;
		ChangedCallback changedCallback_;
		std::vector<std::jthread> workers_;
		mutable std::mutex workerMutex_;
		mutable std::mutex mutex_;
		mutable std::condition_variable condition_;
	};

	std::string_view JobStateName(JobState state);
}  // namespace binjad::session
