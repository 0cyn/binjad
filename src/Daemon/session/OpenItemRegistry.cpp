#include "binjad/session/OpenItemRegistry.hpp"

#include <algorithm>
#include <utility>

namespace binjad::session
{
OpenItemRegistry::OpenItemRegistry(reference::FriendlyReferencePool& references)
    : references_(references)
{
}

OpenItemRegistry::~OpenItemRegistry()
{
    std::lock_guard lock(mutex_);
    for (const auto& [reference, record] : openItems_)
        ReleaseReferences(record);
}

OpenItemCreateResult OpenItemRegistry::Create(std::string ownerTokenId,
    std::string analysisSession, OpenItemSourceKind sourceKind, std::string source,
    std::optional<std::string> project, const std::vector<BinaryViewCandidateSpec>& candidates)
{
    if (candidates.empty())
        return {{}, "open item must have at least one BinaryView candidate"};
    if (std::count_if(candidates.begin(), candidates.end(), [](const auto& candidate) {
        return candidate.recommended;
    }) > 1)
        return {{}, "open item must not have multiple recommended BinaryView candidates"};
    std::vector<std::string> acquired;
    auto openItem = references_.Acquire();
    if (!openItem.value)
        return {{}, openItem.error};
    acquired.push_back(*openItem.value);

    OpenItemRecord record{*openItem.value, std::move(ownerTokenId),
        std::move(analysisSession), sourceKind, std::move(source), std::move(project), {}};
    for (const auto& candidate : candidates)
    {
        if (candidate.viewType.empty())
        {
            for (const auto& reference : acquired)
                references_.Release(reference);
            return {{}, "BinaryView candidate type must not be empty"};
        }
        if (std::any_of(record.binaryViews.begin(), record.binaryViews.end(),
            [&](const auto& existing) { return existing.viewType == candidate.viewType; }))
        {
            for (const auto& reference : acquired)
                references_.Release(reference);
            return {{}, "BinaryView candidate types must be unique within an open item"};
        }
        auto binaryView = references_.Acquire();
        if (!binaryView.value)
        {
            for (const auto& reference : acquired)
                references_.Release(reference);
            return {{}, binaryView.error};
        }
        acquired.push_back(*binaryView.value);
        BinaryViewRecord view;
        view.reference = *binaryView.value;
        view.openItem = record.reference;
        view.analysisSession = record.analysisSession;
        view.viewType = candidate.viewType;
        view.recommended = candidate.recommended;
        view.loadSettingsSchemaJson = candidate.loadSettingsSchemaJson;
        record.binaryViews.push_back(std::move(view));
    }

    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        openItems_.emplace(record.reference, record);
        for (const auto& view : record.binaryViews)
            viewOwners_.emplace(view.reference, record.reference);
        changed = changedCallback_;
    }
    if (changed)
        changed(record.ownerTokenId);
    return {std::move(record), {}};
}

std::vector<OpenItemRecord> OpenItemRegistry::ListForToken(std::string_view ownerTokenId) const
{
    std::lock_guard lock(mutex_);
    std::vector<OpenItemRecord> result;
    for (const auto& [reference, record] : openItems_)
    {
        if (record.ownerTokenId == ownerTokenId)
            result.push_back(record);
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.reference < right.reference;
    });
    return result;
}

std::vector<BinaryViewRecord> OpenItemRegistry::ListViews(
    std::string_view ownerTokenId, std::string_view analysisSession) const
{
    std::lock_guard lock(mutex_);
    std::vector<BinaryViewRecord> result;
    for (const auto& [reference, record] : openItems_)
    {
        if (record.ownerTokenId != ownerTokenId || record.analysisSession != analysisSession)
            continue;
        result.insert(result.end(), record.binaryViews.begin(), record.binaryViews.end());
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.reference < right.reference;
    });
    return result;
}

std::optional<OpenItemRecord> OpenItemRegistry::FindOpenItem(
    std::string_view ownerTokenId, std::string_view openItem) const
{
    std::lock_guard lock(mutex_);
    const auto record = openItems_.find(std::string(openItem));
    return record != openItems_.end() && record->second.ownerTokenId == ownerTokenId
        ? std::optional(record->second) : std::nullopt;
}

std::optional<BinaryViewRecord> OpenItemRegistry::FindView(std::string_view ownerTokenId,
    std::string_view analysisSession, std::string_view binaryView) const
{
    std::lock_guard lock(mutex_);
    const auto owner = viewOwners_.find(std::string(binaryView));
    if (owner == viewOwners_.end())
        return std::nullopt;
    const auto item = openItems_.find(owner->second);
    if (item == openItems_.end() || item->second.ownerTokenId != ownerTokenId ||
        item->second.analysisSession != analysisSession)
        return std::nullopt;
    const auto view = std::find_if(item->second.binaryViews.begin(), item->second.binaryViews.end(),
        [&](const auto& candidate) { return candidate.reference == binaryView; });
    return view == item->second.binaryViews.end() ? std::nullopt : std::optional(*view);
}

std::optional<BinaryViewRecord> OpenItemRegistry::MarkViewCreated(std::string_view ownerTokenId,
    std::string_view analysisSession, std::string_view binaryView,
    std::string architecture, std::string platform,
    std::string effectiveLoadSettingsJson, std::uint64_t start,
    std::uint64_t end, std::uint64_t entryPoint)
{
    ChangedCallback changed;
    std::optional<BinaryViewRecord> result;
    {
        std::lock_guard lock(mutex_);
        const auto owner = viewOwners_.find(std::string(binaryView));
        if (owner == viewOwners_.end())
            return std::nullopt;
        const auto item = openItems_.find(owner->second);
        if (item == openItems_.end() || item->second.ownerTokenId != ownerTokenId ||
            item->second.analysisSession != analysisSession)
            return std::nullopt;
        const auto view = std::find_if(item->second.binaryViews.begin(), item->second.binaryViews.end(),
            [&](const auto& candidate) { return candidate.reference == binaryView; });
        if (view == item->second.binaryViews.end())
            return std::nullopt;
        view->created = true;
        view->architecture = std::move(architecture);
        view->platform = std::move(platform);
        view->effectiveLoadSettingsJson = std::move(effectiveLoadSettingsJson);
        view->start = start;
        view->end = end;
        view->entryPoint = entryPoint;
        result = *view;
        changed = changedCallback_;
    }
    if (changed)
        changed(ownerTokenId);
    return result;
}

std::optional<OpenItemRecord> OpenItemRegistry::UpdateSource(
    std::string_view ownerTokenId, std::string_view openItem,
    OpenItemSourceKind sourceKind, std::string source,
    std::optional<std::string> project)
{
    ChangedCallback changed;
    std::optional<OpenItemRecord> result;
    {
        std::lock_guard lock(mutex_);
        const auto item = openItems_.find(std::string(openItem));
        if (item == openItems_.end() || item->second.ownerTokenId != ownerTokenId)
            return std::nullopt;
        item->second.sourceKind = sourceKind;
        item->second.source = std::move(source);
        item->second.project = std::move(project);
        result = item->second;
        changed = changedCallback_;
    }
    if (changed)
        changed(ownerTokenId);
    return result;
}

void OpenItemRegistry::UpdateProjectSource(std::string_view project,
    std::string_view oldSource, std::string newSource)
{
    std::unordered_set<std::string> owners;
    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        for (auto& [reference, item] : openItems_)
        {
            (void)reference;
            if (item.project && *item.project == project && item.source == oldSource)
            {
                item.source = newSource;
                owners.insert(item.ownerTokenId);
            }
        }
        changed = changedCallback_;
    }
    if (changed)
        for (const auto& owner : owners) changed(owner);
}

bool OpenItemRegistry::HasProjectSource(
    std::string_view project, std::string_view source) const
{
    std::lock_guard lock(mutex_);
    return std::any_of(openItems_.begin(), openItems_.end(), [&](const auto& entry) {
        const auto& item = entry.second;
        return item.project && *item.project == project && item.source == source;
    });
}

void OpenItemRegistry::UpdateProjectSourcePrefix(std::string_view project,
    std::string_view oldPrefix, std::string_view newPrefix)
{
    std::unordered_set<std::string> owners;
    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        const auto prefix = std::string(oldPrefix) + '/';
        for (auto& [reference, item] : openItems_)
        {
            (void)reference;
            if (!item.project || *item.project != project)
                continue;
            if (item.source == oldPrefix)
            {
                item.source = newPrefix;
                owners.insert(item.ownerTokenId);
            }
            else if (item.source.starts_with(prefix))
            {
                item.source = std::string(newPrefix) + item.source.substr(oldPrefix.size());
                owners.insert(item.ownerTokenId);
            }
        }
        changed = changedCallback_;
    }
    if (changed)
        for (const auto& owner : owners) changed(owner);
}

bool OpenItemRegistry::HasProjectSourcePrefix(
    std::string_view project, std::string_view prefix) const
{
    std::lock_guard lock(mutex_);
    const auto childPrefix = std::string(prefix) + '/';
    return std::any_of(openItems_.begin(), openItems_.end(), [&](const auto& entry) {
        const auto& item = entry.second;
        return item.project && *item.project == project &&
            (item.source == prefix || item.source.starts_with(childPrefix));
    });
}

bool OpenItemRegistry::HasProject(std::string_view project) const
{
    std::lock_guard lock(mutex_);
    return std::any_of(openItems_.begin(), openItems_.end(), [&](const auto& entry) {
        return entry.second.project && *entry.second.project == project;
    });
}

std::optional<OpenItemRecord> OpenItemRegistry::Close(
    std::string_view ownerTokenId, std::string_view openItem)
{
    ChangedCallback changed;
    std::optional<OpenItemRecord> removed;
    {
        std::lock_guard lock(mutex_);
        const auto record = openItems_.find(std::string(openItem));
        if (record == openItems_.end() || record->second.ownerTokenId != ownerTokenId)
            return std::nullopt;
        removed = record->second;
        for (const auto& view : record->second.binaryViews)
            viewOwners_.erase(view.reference);
        ReleaseReferences(record->second);
        openItems_.erase(record);
        changed = changedCallback_;
    }
    if (changed)
        changed(ownerTokenId);
    return removed;
}

std::vector<OpenItemRecord> OpenItemRegistry::CloseByAnalysisSession(
    std::string_view analysisSession)
{
    std::vector<OpenItemRecord> removed;
    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        for (auto record = openItems_.begin(); record != openItems_.end();)
        {
            if (record->second.analysisSession != analysisSession)
            {
                ++record;
                continue;
            }
            removed.push_back(record->second);
            for (const auto& view : record->second.binaryViews)
                viewOwners_.erase(view.reference);
            ReleaseReferences(record->second);
            record = openItems_.erase(record);
        }
        changed = changedCallback_;
    }
    if (changed)
    {
        std::unordered_set<std::string> owners;
        for (const auto& record : removed) owners.insert(record.ownerTokenId);
        for (const auto& owner : owners) changed(owner);
    }
    return removed;
}

std::vector<OpenItemRecord> OpenItemRegistry::CloseByToken(std::string_view ownerTokenId)
{
    std::vector<OpenItemRecord> removed;
    ChangedCallback changed;
    {
        std::lock_guard lock(mutex_);
        for (auto record = openItems_.begin(); record != openItems_.end();)
        {
            if (record->second.ownerTokenId != ownerTokenId)
            {
                ++record;
                continue;
            }
            removed.push_back(record->second);
            for (const auto& view : record->second.binaryViews)
                viewOwners_.erase(view.reference);
            ReleaseReferences(record->second);
            record = openItems_.erase(record);
        }
        changed = changedCallback_;
    }
    if (!removed.empty() && changed)
        changed(ownerTokenId);
    return removed;
}

void OpenItemRegistry::SetChangedCallback(ChangedCallback callback)
{
    std::lock_guard lock(mutex_);
    changedCallback_ = std::move(callback);
}

std::size_t OpenItemRegistry::Size() const
{
    std::lock_guard lock(mutex_);
    return openItems_.size();
}

void OpenItemRegistry::ReleaseReferences(const OpenItemRecord& record)
{
    for (const auto& view : record.binaryViews)
        references_.Release(view.reference);
    references_.Release(record.reference);
}
}
