#include "binjad/overseer/AnalysisScheduler.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <utility>

namespace binjad::overseer
{
struct AnalysisScheduler::Entry
{
    std::uint64_t id = 0;
    std::uint64_t sequence = 0;
    AnalysisScheduleRequest request;
    AllocationCallback allocation;
    std::size_t workers = 0;
    bool active = false;
    bool cancelled = false;
    std::condition_variable condition;
};

struct AnalysisScheduler::AllocationAction
{
    AllocationCallback callback;
    std::size_t workers = 0;
};

AnalysisScheduler::Lease::Lease(AnalysisScheduler* scheduler, std::uint64_t id)
    : scheduler_(scheduler), id_(id)
{
}

AnalysisScheduler::Lease::Lease(Lease&& other) noexcept
    : scheduler_(std::exchange(other.scheduler_, nullptr)),
      id_(std::exchange(other.id_, 0))
{
}

AnalysisScheduler::Lease& AnalysisScheduler::Lease::operator=(Lease&& other) noexcept
{
    if (this != &other)
    {
        Reset();
        scheduler_ = std::exchange(other.scheduler_, nullptr);
        id_ = std::exchange(other.id_, 0);
    }
    return *this;
}

AnalysisScheduler::Lease::~Lease()
{
    Reset();
}

std::size_t AnalysisScheduler::Lease::Workers() const
{
    return scheduler_ ? scheduler_->Workers(id_) : 0;
}

void AnalysisScheduler::Lease::Reset()
{
    if (scheduler_)
        scheduler_->Release(id_);
    scheduler_ = nullptr;
    id_ = 0;
}

AnalysisScheduler::AnalysisScheduler(CpuConfig config, Capacity capacity)
    : config_(std::move(config)), capacity_(capacity ? std::move(capacity)
        : [] { return platform::ActiveLogicalCpuCount(); })
{
    std::lock_guard lock(mutex_);
    (void)RebalanceLocked();
}

AnalysisScheduler::~AnalysisScheduler()
{
    std::lock_guard lock(mutex_);
    shuttingDown_ = true;
    for (auto& [id, entry] : entries_)
    {
        entry->cancelled = true;
        entry->condition.notify_all();
    }
}

std::optional<AnalysisScheduler::Lease> AnalysisScheduler::Acquire(
    AnalysisScheduleRequest request, AllocationCallback allocation, std::string& error)
{
    auto entry = std::make_shared<Entry>();
    std::vector<AllocationAction> actions;
    {
        std::lock_guard lock(mutex_);
        if (shuttingDown_)
        {
            error = "analysis scheduler is shutting down";
            return std::nullopt;
        }
        entry->id = nextId_++;
        entry->sequence = nextSequence_++;
        entry->request = std::move(request);
        entry->allocation = std::move(allocation);
        entries_.emplace(entry->id, entry);
        actions = RebalanceLocked();
    }
    RunActions(std::move(actions));

    std::unique_lock lock(mutex_);
    entry->condition.wait(lock, [&] {
        return entry->active || entry->cancelled || shuttingDown_;
    });
    if (!entry->active)
    {
        entries_.erase(entry->id);
        error = shuttingDown_ ? "analysis scheduler is shutting down"
                              : "analysis request was cancelled";
        return std::nullopt;
    }
    return Lease(this, entry->id);
}

bool AnalysisScheduler::Cancel(std::uint64_t id)
{
    std::vector<AllocationAction> actions;
    {
        std::lock_guard lock(mutex_);
        const auto entry = entries_.find(id);
        if (entry == entries_.end() || entry->second->active)
            return false;
        entry->second->cancelled = true;
        entry->second->condition.notify_all();
        entries_.erase(entry);
        actions = RebalanceLocked();
    }
    RunActions(std::move(actions));
    return true;
}

std::size_t AnalysisScheduler::CancelQueued(std::string_view token,
    std::string_view analysisSession, std::string_view file)
{
    std::vector<AllocationAction> actions;
    std::size_t count = 0;
    {
        std::lock_guard lock(mutex_);
        for (auto entry = entries_.begin(); entry != entries_.end();)
        {
            const auto& request = entry->second->request;
            if (!entry->second->active && request.token == token &&
                request.analysisSession == analysisSession && request.file == file)
            {
                entry->second->cancelled = true;
                entry->second->condition.notify_all();
                entry = entries_.erase(entry);
                ++count;
            }
            else
                ++entry;
        }
        actions = RebalanceLocked();
    }
    RunActions(std::move(actions));
    return count;
}

AnalysisSchedulerStatus AnalysisScheduler::Status() const
{
    std::lock_guard lock(mutex_);
    return status_;
}

std::string AnalysisScheduler::UnitKey(const Entry& entry) const
{
    switch (config_.fairness)
    {
        case FairnessUnit::AnalysisSession: return "s:" + entry.request.analysisSession;
        case FairnessUnit::BearerToken: return "t:" + entry.request.token;
        case FairnessUnit::File: return "f:" + entry.request.file;
        case FairnessUnit::AnalysisJob: return "j:" + std::to_string(entry.id);
    }
    return {};
}

std::vector<AnalysisScheduler::AllocationAction> AnalysisScheduler::RebalanceLocked()
{
    const auto capacity = capacity_();
    status_.logicalCpuCount = capacity.logicalCpuCount.value_or(1);
    status_.workerBudget = std::max<std::size_t>(1,
        status_.logicalCpuCount * config_.percentage / 100);

    struct Unit
    {
        std::string key;
        std::uint64_t sequence = 0;
        std::vector<std::shared_ptr<Entry>> entries;
        bool active = false;
        std::size_t share = 0;
    };
    std::map<std::string, Unit> byKey;
    for (const auto& [id, entry] : entries_)
    {
        if (entry->cancelled)
            continue;
        const auto key = UnitKey(*entry);
        auto& unit = byKey[key];
        unit.key = key;
        unit.sequence = unit.sequence == 0 ? entry->sequence
                                          : std::min(unit.sequence, entry->sequence);
        unit.active = unit.active || entry->active;
        unit.entries.push_back(entry);
    }
    std::vector<Unit*> units;
    for (auto& [key, unit] : byKey)
    {
        std::sort(unit.entries.begin(), unit.entries.end(), [](const auto& left, const auto& right) {
            return left->sequence < right->sequence;
        });
        units.push_back(&unit);
    }
    std::sort(units.begin(), units.end(), [](const auto* left, const auto* right) {
        return left->sequence < right->sequence;
    });

    std::vector<Unit*> selected;
    std::set<std::string> selectedFiles;
    for (auto* unit : units)
    {
        if (unit->active)
        {
            selected.push_back(unit);
            for (const auto& entry : unit->entries)
            {
                if (entry->active)
                    selectedFiles.insert(entry->request.file);
            }
        }
    }
    if (selected.size() < status_.workerBudget)
    {
        for (auto* unit : units)
        {
            if (unit->active)
                continue;
            const auto available = std::find_if(unit->entries.begin(), unit->entries.end(),
                [&](const auto& entry) {
                    return !selectedFiles.contains(entry->request.file);
                });
            if (available == unit->entries.end())
                continue;
            selected.push_back(unit);
            selectedFiles.insert((*available)->request.file);
            if (selected.size() >= status_.workerBudget)
                break;
        }
    }

    const bool overcommitted = selected.size() > status_.workerBudget;
    if (!selected.empty())
    {
        const auto base = overcommitted ? 1 : status_.workerBudget / selected.size();
        auto remainder = overcommitted ? 0 : status_.workerBudget % selected.size();
        for (auto* unit : selected)
            unit->share = base;
        if (remainder != 0)
        {
            const auto first = rotation_++ % selected.size();
            for (std::size_t index = 0; index < remainder; ++index)
                ++selected[(first + index) % selected.size()]->share;
        }
    }

    std::set<std::uint64_t> shouldRun;
    std::set<std::string> runningFiles;
    for (const auto& [id, entry] : entries_)
    {
        if (entry->active)
            runningFiles.insert(entry->request.file);
    }
    std::unordered_map<std::uint64_t, std::size_t> allocations;
    for (auto* unit : selected)
    {
        std::vector<std::shared_ptr<Entry>> active;
        for (const auto& entry : unit->entries)
        {
            if (entry->active)
                active.push_back(entry);
        }
        if (config_.subdivision == "equal")
        {
            for (const auto& entry : unit->entries)
            {
                if (active.size() >= unit->share)
                    break;
                if (!entry->active && runningFiles.insert(entry->request.file).second)
                    active.push_back(entry);
            }
        }
        else if (active.empty() && !unit->entries.empty())
        {
            const auto available = std::find_if(unit->entries.begin(), unit->entries.end(),
                [&](const auto& entry) {
                    return runningFiles.insert(entry->request.file).second;
                });
            if (available != unit->entries.end())
                active.push_back(*available);
        }
        if (active.empty())
            continue;
        const auto base = std::max<std::size_t>(1, unit->share / active.size());
        auto remainder = unit->share > active.size()
            ? unit->share % active.size() : 0;
        for (std::size_t index = 0; index < active.size(); ++index)
        {
            shouldRun.insert(active[index]->id);
            allocations[active[index]->id] = base + (index < remainder ? 1 : 0);
        }
    }

    std::vector<AllocationAction> actions;
    status_.allocatedWorkers = 0;
    status_.activeAnalyses = 0;
    status_.queuedAnalyses = 0;
    for (auto& [id, entry] : entries_)
    {
        if (entry->cancelled)
            continue;
        if (shouldRun.contains(id))
        {
            const auto workers = allocations[id];
            const bool changed = !entry->active || entry->workers != workers;
            entry->active = true;
            entry->workers = workers;
            status_.allocatedWorkers += workers;
            ++status_.activeAnalyses;
            if (changed && entry->allocation)
                actions.push_back({entry->allocation, workers});
            entry->condition.notify_all();
        }
        else
        {
            if (entry->active)
            {
                entry->active = false;
                entry->workers = 0;
                if (entry->allocation)
                    actions.push_back({entry->allocation, 1});
            }
            ++status_.queuedAnalyses;
        }
    }
    return actions;
}

void AnalysisScheduler::RunActions(std::vector<AllocationAction> actions)
{
    for (auto& action : actions)
    {
        try
        {
            action.callback(action.workers);
        }
        catch (...)
        {}
    }
}

void AnalysisScheduler::Release(std::uint64_t id)
{
    std::vector<AllocationAction> actions;
    AllocationCallback reset;
    {
        std::lock_guard lock(mutex_);
        const auto entry = entries_.find(id);
        if (entry == entries_.end())
            return;
        reset = entry->second->allocation;
        entries_.erase(entry);
        actions = RebalanceLocked();
    }
    if (reset)
    {
        try { reset(1); } catch (...) {}
    }
    RunActions(std::move(actions));
}

std::size_t AnalysisScheduler::Workers(std::uint64_t id) const
{
    std::lock_guard lock(mutex_);
    const auto entry = entries_.find(id);
    return entry == entries_.end() ? 0 : entry->second->workers;
}
}
