#include "binjad/portal/LocalSessionManager.hpp"

#include "binjad/overseer/BinaryViewPersistence.hpp"
#include "binjad/overseer/FileChildCoordinator.hpp"
#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/session/AnalysisSessionRegistry.hpp"
#include "binjad/session/JobRegistry.hpp"
#include "binjad/session/OpenItemRegistry.hpp"

#include <algorithm>
#include <chrono>

namespace binjad::portal {
	namespace {
		std::string SourceKindName(session::OpenItemSourceKind kind)
		{
			return kind == session::OpenItemSourceKind::LocalProject ? "local_project" : "path";
		}

		std::string AnalysisStateName(ipc::AnalysisState state)
		{
			switch (state)
			{
			case ipc::ANALYSIS_STATE_IDLE:
				return "idle";
			case ipc::ANALYSIS_STATE_RUNNING:
				return "running";
			case ipc::ANALYSIS_STATE_COMPLETE:
				return "complete";
			case ipc::ANALYSIS_STATE_ABORTED:
				return "aborted";
			case ipc::ANALYSIS_STATE_FAILED:
				return "failed";
			default:
				return "unknown";
			}
		}

		RecoveryJob Job(const session::JobRecord& job)
		{
			RecoveryJob result {job.reference, job.operation, std::string(session::JobStateName(job.state)),
				job.binaryView, job.createdAtUnix, job.updatedAtUnix, {}, 0, 0, {}, job.cancelRequested};
			if (job.progress)
			{
				result.phase = job.progress->phase;
				result.completed = job.progress->completed;
				result.total = job.progress->total;
				result.message = job.progress->message;
			}
			return result;
		}

		RecoverySessionSummary Summary(const session::AnalysisSessionRecord& record,
			const std::vector<session::OpenItemRecord>& items, const std::vector<session::JobRecord>& jobs,
			session::AnalysisSessionRegistry::Clock::time_point now)
		{
			RecoverySessionSummary result;
			result.reference = record.reference;
			result.createdAt = record.createdAtUnix;
			result.inactiveSeconds = now > record.lastActive ?
				static_cast<std::uint64_t>(
					std::chrono::duration_cast<std::chrono::seconds>(now - record.lastActive).count()) :
				0;
			result.legacy = record.legacyTransportId.has_value();
			result.retainers = record.retainers;
			result.openItems = std::count_if(items.begin(), items.end(), [&](const auto& item) {
				return item.analysisSession == record.reference;
			});
			for (const auto& job : jobs)
			{
				if (!job.analysisSession || *job.analysisSession != record.reference)
					continue;
				++result.jobs;
				if (job.state == session::JobState::Queued || job.state == session::JobState::Running)
					++result.activeJobs;
			}
			return result;
		}

		RecoverySave Saved(const overseer::CommittedBinaryView& saved)
		{
			return {saved.binaryView, saved.openItem, saved.destination, SourceKindName(saved.sourceKind),
				saved.createdDatabase};
		}
	}  // namespace

	LocalSessionManager::LocalSessionManager(std::shared_ptr<session::AnalysisSessionRegistry> sessions,
		std::shared_ptr<session::OpenItemRegistry> openItems, std::shared_ptr<session::JobRegistry> jobs,
		std::shared_ptr<overseer::FileChildCoordinator> files,
		std::shared_ptr<overseer::ProjectChildCoordinator> projects) :
		sessions_(std::move(sessions)), openItems_(std::move(openItems)), jobs_(std::move(jobs)),
		files_(std::move(files)), projects_(std::move(projects))
	{}

	Result<std::vector<RecoverySessionSummary>> LocalSessionManager::List(std::string_view ownerTokenId)
	{
		const auto sessions = sessions_.lock();
		const auto openItems = openItems_.lock();
		const auto jobs = jobs_.lock();
		if (!sessions || !openItems || !jobs)
			return {{}, "session recovery service is unavailable"};
		const auto now = session::AnalysisSessionRegistry::Clock::now();
		const auto records = sessions->List(ownerTokenId, now);
		const auto itemRecords = openItems->ListForToken(ownerTokenId);
		const auto jobRecords = jobs->List(ownerTokenId);
		std::vector<RecoverySessionSummary> result;
		result.reserve(records.size());
		for (const auto& record : records)
			result.push_back(Summary(record, itemRecords, jobRecords, now));
		return {std::move(result), {}};
	}

	Result<RecoverySessionDetails> LocalSessionManager::Details(
		std::string_view ownerTokenId, std::string_view analysisSession)
	{
		const auto sessions = sessions_.lock();
		const auto openItems = openItems_.lock();
		const auto jobs = jobs_.lock();
		const auto files = files_.lock();
		if (!sessions || !openItems || !jobs || !files)
			return {{}, "session recovery service is unavailable"};
		const auto now = session::AnalysisSessionRegistry::Clock::now();
		const auto record = sessions->Find(analysisSession, ownerTokenId, now);
		if (!record)
			return {{}, "session not found"};
		const auto allItems = openItems->ListForToken(ownerTokenId);
		const auto allJobs = jobs->List(ownerTokenId);
		RecoverySessionDetails result;
		result.session = Summary(*record, allItems, allJobs, now);
		for (const auto& item : allItems)
		{
			if (item.analysisSession != analysisSession)
				continue;
			RecoveryOpenItem recovered {item.reference, SourceKindName(item.sourceKind), item.source, item.project, {}};
			for (const auto& view : item.binaryViews)
			{
				RecoveryView recoveredView;
				recoveredView.reference = view.reference;
				recoveredView.openItem = view.openItem;
				recoveredView.viewType = view.viewType;
				recoveredView.architecture = view.architecture;
				recoveredView.platform = view.platform;
				recoveredView.recommended = view.recommended;
				recoveredView.created = view.created;
				if (view.created)
				{
					const auto status = files->AnalysisStatus(ownerTokenId, analysisSession, view.reference);
					if (status.value)
					{
						recoveredView.statusAvailable = true;
						recoveredView.analysisState = AnalysisStateName(status.value->state());
						recoveredView.modified = status.value->modified();
						recoveredView.analysisChanged = status.value->analysis_changed();
						recoveredView.completed = status.value->completed();
						recoveredView.total = status.value->total();
					}
					else
					{
						recoveredView.error = status.error;
					}
				}
				recovered.views.push_back(std::move(recoveredView));
			}
			result.openItems.push_back(std::move(recovered));
		}
		for (const auto& job : allJobs)
			if (job.analysisSession && *job.analysisSession == analysisSession)
				result.jobs.push_back(Job(job));
		return {std::move(result), {}};
	}

	Result<RecoverySave> LocalSessionManager::Save(std::string_view ownerTokenId, std::string_view analysisSession,
		std::string_view binaryView, std::optional<std::string> destination)
	{
		const auto sessions = sessions_.lock();
		const auto openItems = openItems_.lock();
		const auto files = files_.lock();
		const auto projects = projects_.lock();
		if (!sessions || !openItems || !files)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now()))
			return {{}, "session not found"};
		const auto saved = overseer::SaveAndCommitBinaryView(
			*files, projects.get(), *openItems, ownerTokenId, analysisSession, binaryView, destination);
		return saved.value ? Result<RecoverySave> {Saved(*saved.value), {}} : Result<RecoverySave> {{}, saved.error};
	}

	Result<RecoveryBatchSave> LocalSessionManager::SaveAll(
		std::string_view ownerTokenId, std::string_view analysisSession)
	{
		const auto sessions = sessions_.lock();
		const auto openItems = openItems_.lock();
		const auto files = files_.lock();
		const auto projects = projects_.lock();
		if (!sessions || !openItems || !files)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now()))
			return {{}, "session not found"};
		RecoveryBatchSave result;
		for (const auto& item : openItems->ListForToken(ownerTokenId))
		{
			if (item.analysisSession != analysisSession)
				continue;
			const auto preferred = std::find_if(item.binaryViews.begin(), item.binaryViews.end(), [](const auto& view) {
				return view.created && view.recommended;
			});
			const auto selected = preferred != item.binaryViews.end() ?
				preferred :
				std::find_if(item.binaryViews.begin(), item.binaryViews.end(), [](const auto& view) {
					return view.created;
				});
			if (selected == item.binaryViews.end())
			{
				++result.skipped;
				continue;
			}
			const auto status = files->AnalysisStatus(ownerTokenId, analysisSession, selected->reference);
			if (!status.value)
			{
				result.failed.push_back({selected->reference, item.source, status.error});
				continue;
			}
			if (!status.value->modified() && !status.value->analysis_changed())
			{
				++result.skipped;
				continue;
			}
			const auto saved = overseer::SaveAndCommitBinaryView(
				*files, projects.get(), *openItems, ownerTokenId, analysisSession, selected->reference);
			if (saved.value)
				result.saved.push_back(Saved(*saved.value));
			else
				result.failed.push_back({selected->reference, item.source, saved.error});
		}
		return {std::move(result), {}};
	}

	Result<bool> LocalSessionManager::Abort(
		std::string_view ownerTokenId, std::string_view analysisSession, std::string_view binaryView)
	{
		const auto sessions = sessions_.lock();
		const auto files = files_.lock();
		if (!sessions || !files)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now()))
			return {{}, "session not found"};
		const auto error = files->AbortAnalysis(ownerTokenId, analysisSession, binaryView);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<bool> LocalSessionManager::CancelJob(
		std::string_view ownerTokenId, std::string_view analysisSession, std::string_view job)
	{
		const auto sessions = sessions_.lock();
		const auto jobs = jobs_.lock();
		if (!sessions || !jobs)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now()))
			return {{}, "session not found"};
		const auto found = jobs->Info(ownerTokenId, job);
		if (!found.job || !found.job->analysisSession || *found.job->analysisSession != analysisSession)
			return {{}, "job not found"};
		const auto error = jobs->Cancel(ownerTokenId, job);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<bool> LocalSessionManager::CloseItem(
		std::string_view ownerTokenId, std::string_view analysisSession, std::string_view openItem, bool discard)
	{
		const auto sessions = sessions_.lock();
		const auto openItems = openItems_.lock();
		const auto files = files_.lock();
		if (!sessions || !openItems || !files)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now()))
			return {{}, "session not found"};
		const auto item = openItems->FindOpenItem(ownerTokenId, openItem);
		if (!item || item->analysisSession != analysisSession)
			return {{}, "open item not found"};
		const auto error = files->Close(ownerTokenId, openItem, discard);
		return error.empty() ? Result<bool> {true, {}} : Result<bool> {{}, error};
	}

	Result<bool> LocalSessionManager::ForceClose(std::string_view ownerTokenId, std::string_view analysisSession)
	{
		const auto sessions = sessions_.lock();
		const auto jobs = jobs_.lock();
		if (!sessions || !jobs)
			return {{}, "session recovery service is unavailable"};
		if (!sessions->Find(analysisSession, ownerTokenId, session::AnalysisSessionRegistry::Clock::now(), false))
			return {{}, "session not found"};
		for (const auto& job : jobs->List(ownerTokenId))
		{
			if (!job.analysisSession || *job.analysisSession != analysisSession)
				continue;
			if (job.state == session::JobState::Queued || job.state == session::JobState::Running)
				(void)jobs->Cancel(ownerTokenId, job.reference);
			else
				(void)jobs->TakeResult(ownerTokenId, job.reference);
		}
		return sessions->Close(analysisSession, ownerTokenId, true) ?
			Result<bool> {true, {}} :
			Result<bool> {{}, "session not found"};
	}
}  // namespace binjad::portal
