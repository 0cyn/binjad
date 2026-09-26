#include "binjad/session/JobRegistry.hpp"

#include <algorithm>
#include <utility>

namespace binjad::session
{
JobRegistry::JobRegistry(reference::FriendlyReferencePool& references,
    AnalysisSessionRegistry& sessions)
    : references_(references), sessions_(sessions)
{
}

JobRegistry::~JobRegistry()
{
    {
        std::vector<std::jthread> workers;
        {
            std::lock_guard lock(workerMutex_);
            workers.swap(workers_);
        }
    }
    std::lock_guard lock(mutex_);
    for (auto& [reference, entry] : jobs_)
    {
        ReleaseSession(entry);
        references_.Release(reference);
    }
}

JobResult JobRegistry::Create(std::string ownerTokenId,
    std::optional<std::string> analysisSession, std::optional<std::string> binaryView,
    std::string operation, std::uint64_t nowUnix, Clock::time_point now,
    CancelCallback cancel)
{
    bool retained = false;
    if (analysisSession)
    {
        retained = sessions_.Retain(*analysisSession, ownerTokenId, now);
        if (!retained)
            return {{}, "analysis session not found"};
    }
    auto reference = references_.Acquire();
    if (!reference.value)
    {
        if (retained)
            sessions_.Release(*analysisSession, ownerTokenId);
        return {{}, std::move(reference.error)};
    }
    JobRecord record{*reference.value, std::move(ownerTokenId),
        std::move(analysisSession), std::move(binaryView), std::move(operation),
        JobState::Queued, nowUnix, nowUnix, {}, false, {}};
    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        jobs_.emplace(record.reference, Entry{record, std::move(cancel), retained});
        changed = changedCallback_;
    }
    if (changed)
        changed(record);
    return {std::move(record), {}};
}

bool JobRegistry::Start(
    std::string_view ownerTokenId, std::string_view job, std::uint64_t nowUnix)
{
    ChangedCallback changed;
    JobRecord record;
    {
        std::lock_guard lock(mutex_);
        const auto entry = jobs_.find(std::string(job));
        if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId ||
            entry->second.record.state != JobState::Queued)
            return false;
        entry->second.record.state = JobState::Running;
        entry->second.record.updatedAtUnix = nowUnix;
        record = entry->second.record;
        changed = changedCallback_;
    }
    if (changed)
        changed(record);
    return true;
}

bool JobRegistry::ReportProgress(std::string_view ownerTokenId, std::string_view job,
    std::string phase, std::uint64_t completed, std::uint64_t total,
    std::string message, std::uint64_t nowUnix)
{
    ProgressCallback callback;
    ChangedCallback changed;
    JobRecord record;
    {
        std::lock_guard lock(mutex_);
        const auto entry = jobs_.find(std::string(job));
        if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId ||
            (entry->second.record.state != JobState::Queued &&
                entry->second.record.state != JobState::Running))
            return false;
        const auto sequence = entry->second.record.progress
            ? entry->second.record.progress->sequence + 1 : 1;
        entry->second.record.progress = JobProgress{sequence, nowUnix,
            std::move(phase), completed, total, std::move(message)};
        entry->second.record.updatedAtUnix = nowUnix;
        record = entry->second.record;
        callback = progressCallback_;
        changed = changedCallback_;
    }
    if (callback)
        callback(record);
    if (changed)
        changed(record);
    return true;
}

bool JobRegistry::Complete(std::string_view ownerTokenId, std::string_view job,
    std::string resultJson, std::uint64_t nowUnix)
{
    return Finish(ownerTokenId, job, JobState::Complete, std::move(resultJson), nowUnix);
}

bool JobRegistry::Fail(std::string_view ownerTokenId, std::string_view job,
    std::string resultJson, std::uint64_t nowUnix)
{
    return Finish(ownerTokenId, job, JobState::Failed, std::move(resultJson), nowUnix);
}

bool JobRegistry::MarkCancelled(std::string_view ownerTokenId, std::string_view job,
    std::string resultJson, std::uint64_t nowUnix)
{
    return Finish(ownerTokenId, job, JobState::Cancelled, std::move(resultJson), nowUnix);
}

JobResult JobRegistry::Info(std::string_view ownerTokenId, std::string_view job) const
{
    std::lock_guard lock(mutex_);
    const auto entry = jobs_.find(std::string(job));
    if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId)
        return {{}, "job not found"};
    return {entry->second.record, {}};
}

JobResult JobRegistry::WaitForTerminal(std::string_view ownerTokenId,
    std::string_view job, Clock::duration timeout) const
{
    const auto terminal = [this, owner = std::string(ownerTokenId),
                              reference = std::string(job)] {
        const auto entry = jobs_.find(reference);
        return entry == jobs_.end() || entry->second.record.ownerTokenId != owner ||
            (entry->second.record.state != JobState::Queued &&
                entry->second.record.state != JobState::Running);
    };
    std::unique_lock lock(mutex_);
    condition_.wait_for(lock, timeout, terminal);
    const auto entry = jobs_.find(std::string(job));
    if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId)
        return {{}, "job not found"};
    return {entry->second.record, {}};
}

std::vector<JobRecord> JobRegistry::List(std::string_view ownerTokenId) const
{
    std::lock_guard lock(mutex_);
    std::vector<JobRecord> result;
    for (const auto& [reference, entry] : jobs_)
    {
        if (entry.record.ownerTokenId == ownerTokenId)
            result.push_back(entry.record);
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.createdAtUnix < right.createdAtUnix ||
            (left.createdAtUnix == right.createdAtUnix && left.reference < right.reference);
    });
    return result;
}

JobResult JobRegistry::TakeResult(std::string_view ownerTokenId, std::string_view job)
{
    ChangedCallback changed;
    JobRecord record;
    {
        std::lock_guard lock(mutex_);
        const auto entry = jobs_.find(std::string(job));
        if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId)
            return {{}, "job not found"};
        if (entry->second.record.state == JobState::Queued ||
            entry->second.record.state == JobState::Running)
            return {{}, "job has not finished"};
        record = entry->second.record;
        ReleaseSession(entry->second);
        references_.Release(entry->first);
        jobs_.erase(entry);
        changed = changedCallback_;
        condition_.notify_all();
    }
    if (changed)
        changed(record);
    return {std::move(record), {}};
}

std::string JobRegistry::Cancel(std::string_view ownerTokenId, std::string_view job)
{
    CancelCallback cancel;
    ChangedCallback changed;
    JobRecord record;
    {
        std::lock_guard lock(mutex_);
        const auto entry = jobs_.find(std::string(job));
        if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId)
            return "job not found";
        if (entry->second.record.state != JobState::Queued &&
            entry->second.record.state != JobState::Running)
            return {};
        entry->second.record.cancelRequested = true;
        record = entry->second.record;
        cancel = entry->second.cancel;
        changed = changedCallback_;
    }
    if (changed)
        changed(record);
    return cancel ? cancel() : std::string{};
}

void JobRegistry::CancelByToken(std::string_view ownerTokenId)
{
    std::vector<std::string> jobs;
    {
        std::lock_guard lock(mutex_);
        for (const auto& [reference, entry] : jobs_)
        {
            if (entry.record.ownerTokenId == ownerTokenId &&
                (entry.record.state == JobState::Queued || entry.record.state == JobState::Running))
                jobs.push_back(reference);
        }
    }
    for (const auto& job : jobs)
        Cancel(ownerTokenId, job);
}

void JobRegistry::RemoveByToken(std::string_view ownerTokenId)
{
    std::lock_guard lock(mutex_);
    bool removed = false;
    for (auto job = jobs_.begin(); job != jobs_.end();)
    {
        if (job->second.record.ownerTokenId != ownerTokenId)
        {
            ++job;
            continue;
        }
        ReleaseSession(job->second);
        references_.Release(job->first);
        job = jobs_.erase(job);
        removed = true;
    }
    if (removed)
        condition_.notify_all();
}

std::string JobRegistry::StartWorker(std::function<void()> worker)
{
    if (!worker)
        return "job worker must not be empty";
    try
    {
        std::jthread thread([worker = std::move(worker)] { worker(); });
        std::lock_guard lock(workerMutex_);
        workers_.push_back(std::move(thread));
        return {};
    }
    catch (const std::exception& exception)
    {
        return exception.what();
    }
}

void JobRegistry::SetProgressCallback(ProgressCallback callback)
{
    std::lock_guard lock(mutex_);
    progressCallback_ = std::move(callback);
}

void JobRegistry::SetChangedCallback(ChangedCallback callback)
{
    std::lock_guard lock(mutex_);
    changedCallback_ = std::move(callback);
}

std::size_t JobRegistry::Size() const
{
    std::lock_guard lock(mutex_);
    return jobs_.size();
}

bool JobRegistry::Finish(std::string_view ownerTokenId, std::string_view job,
    JobState state, std::string resultJson, std::uint64_t nowUnix)
{
    ChangedCallback changed;
    JobRecord record;
    {
        std::lock_guard lock(mutex_);
        const auto entry = jobs_.find(std::string(job));
        if (entry == jobs_.end() || entry->second.record.ownerTokenId != ownerTokenId ||
            (entry->second.record.state != JobState::Queued &&
                entry->second.record.state != JobState::Running))
            return false;
        entry->second.record.state = state;
        entry->second.record.resultJson = std::move(resultJson);
        entry->second.record.updatedAtUnix = nowUnix;
        record = entry->second.record;
        changed = changedCallback_;
        ReleaseSession(entry->second);
        condition_.notify_all();
    }
    if (changed)
        changed(record);
    return true;
}

void JobRegistry::ReleaseSession(Entry& entry)
{
    if (entry.sessionRetained && entry.record.analysisSession)
    {
        sessions_.Release(*entry.record.analysisSession, entry.record.ownerTokenId);
        entry.sessionRetained = false;
    }
}

std::string_view JobStateName(JobState state)
{
    switch (state)
    {
        case JobState::Queued: return "queued";
        case JobState::Running: return "running";
        case JobState::Complete: return "complete";
        case JobState::Failed: return "failed";
        case JobState::Cancelled: return "cancelled";
    }
    return {};
}
}
