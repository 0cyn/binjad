#include "binjad/session/AnalysisSessionRegistry.hpp"

#include "binjad/security/Random.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace binjad::session
{
AnalysisSessionRegistry::AnalysisSessionRegistry(
    reference::FriendlyReferencePool& references, std::chrono::seconds ttl)
    : references_(references), ttl_(ttl)
{
    if (ttl_ <= std::chrono::seconds::zero())
        throw std::invalid_argument("analysis session TTL must be greater than zero");
}

AnalysisSessionRegistry::~AnalysisSessionRegistry()
{
    std::lock_guard lock(mutex_);
    for (const auto& [reference, record] : sessions_)
        references_.Release(reference);
}

AnalysisSessionCreateResult AnalysisSessionRegistry::Create(std::string ownerTokenId,
    std::uint64_t createdAtUnix, Clock::time_point now,
    std::optional<mcp::ProtocolVersion> legacyVersion)
{
    auto reference = references_.Acquire();
    if (!reference.value)
        return {{}, std::move(reference.error)};

    if (legacyVersion && mcp::IsModern(*legacyVersion))
    {
        references_.Release(*reference.value);
        return {{}, "legacy transport session cannot use a modern protocol version"};
    }

    if (!legacyVersion)
    {
        AnalysisSessionRecord record{*reference.value, std::move(ownerTokenId), createdAtUnix,
            now, {}, {}, 0};
        std::lock_guard lock(mutex_);
        sessions_.emplace(record.reference, record);
        return {std::move(record), {}};
    }

    for (int attempt = 0; attempt < 100; ++attempt)
    {
        auto generated = security::GenerateBase64Url256();
        if (!generated.value)
        {
            references_.Release(*reference.value);
            return {{}, "cannot generate legacy transport session ID: " + generated.error};
        }
        AnalysisSessionRecord record{*reference.value, ownerTokenId, createdAtUnix,
            now, *generated.value, legacyVersion, 0};
        std::lock_guard lock(mutex_);
        if (legacySessions_.contains(*generated.value))
            continue;
        sessions_.emplace(record.reference, record);
        legacySessions_.emplace(*generated.value, record.reference);
        return {std::move(record), {}};
    }
    references_.Release(*reference.value);
    return {{}, "cannot generate a unique legacy transport session ID"};
}

std::optional<AnalysisSessionRecord> AnalysisSessionRegistry::Find(
    std::string_view reference, std::string_view ownerTokenId, Clock::time_point now, bool refresh)
{
    std::lock_guard lock(mutex_);
    const auto record = sessions_.find(std::string(reference));
    if (record == sessions_.end() || record->second.ownerTokenId != ownerTokenId)
        return std::nullopt;
    if (Expired(record->second, now))
    {
        Remove(record);
        return std::nullopt;
    }
    if (refresh)
        record->second.lastActive = now;
    return record->second;
}

std::optional<AnalysisSessionRecord> AnalysisSessionRegistry::FindLegacy(
    std::string_view transportId, std::string_view ownerTokenId, Clock::time_point now, bool refresh)
{
    std::lock_guard lock(mutex_);
    const auto mapping = legacySessions_.find(std::string(transportId));
    if (mapping == legacySessions_.end())
        return std::nullopt;
    const auto record = sessions_.find(mapping->second);
    if (record == sessions_.end() || record->second.ownerTokenId != ownerTokenId)
        return std::nullopt;
    if (Expired(record->second, now))
    {
        Remove(record);
        return std::nullopt;
    }
    if (refresh)
        record->second.lastActive = now;
    return record->second;
}

std::vector<AnalysisSessionRecord> AnalysisSessionRegistry::List(
    std::string_view ownerTokenId, Clock::time_point now)
{
    std::lock_guard lock(mutex_);
    std::vector<AnalysisSessionRecord> result;
    for (auto record = sessions_.begin(); record != sessions_.end();)
    {
        if (record->second.ownerTokenId == ownerTokenId && Expired(record->second, now))
        {
            const auto expired = record++;
            Remove(expired);
            continue;
        }
        if (record->second.ownerTokenId == ownerTokenId)
            result.push_back(record->second);
        ++record;
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.createdAtUnix < right.createdAtUnix ||
            (left.createdAtUnix == right.createdAtUnix && left.reference < right.reference);
    });
    return result;
}

bool AnalysisSessionRegistry::Close(
    std::string_view reference, std::string_view ownerTokenId, bool force)
{
    std::lock_guard lock(mutex_);
    const auto record = sessions_.find(std::string(reference));
    if (record == sessions_.end() || record->second.ownerTokenId != ownerTokenId)
        return false;
    if (!force && record->second.retainers != 0)
        return false;
    Remove(record);
    return true;
}

std::vector<AnalysisSessionRecord> AnalysisSessionRegistry::CloseByOwner(
    std::string_view ownerTokenId)
{
    std::lock_guard lock(mutex_);
    std::vector<AnalysisSessionRecord> removed;
    for (auto record = sessions_.begin(); record != sessions_.end();)
    {
        if (record->second.ownerTokenId != ownerTokenId)
        {
            ++record;
            continue;
        }
        removed.push_back(record->second);
        const auto current = record++;
        Remove(current);
    }
    return removed;
}

bool AnalysisSessionRegistry::Retain(
    std::string_view reference, std::string_view ownerTokenId, Clock::time_point now)
{
    std::lock_guard lock(mutex_);
    const auto record = sessions_.find(std::string(reference));
    if (record == sessions_.end() || record->second.ownerTokenId != ownerTokenId)
        return false;
    if (Expired(record->second, now))
    {
        Remove(record);
        return false;
    }
    ++record->second.retainers;
    record->second.lastActive = now;
    return true;
}

bool AnalysisSessionRegistry::Release(std::string_view reference, std::string_view ownerTokenId)
{
    std::lock_guard lock(mutex_);
    const auto record = sessions_.find(std::string(reference));
    if (record == sessions_.end() || record->second.ownerTokenId != ownerTokenId ||
        record->second.retainers == 0)
        return false;
    --record->second.retainers;
    return true;
}

std::vector<AnalysisSessionRecord> AnalysisSessionRegistry::Sweep(Clock::time_point now)
{
    std::lock_guard lock(mutex_);
    std::vector<AnalysisSessionRecord> expired;
    for (auto record = sessions_.begin(); record != sessions_.end();)
    {
        if (!Expired(record->second, now))
        {
            ++record;
            continue;
        }
        expired.push_back(record->second);
        const auto removed = record++;
        Remove(removed);
    }
    return expired;
}

std::size_t AnalysisSessionRegistry::Size() const
{
    std::lock_guard lock(mutex_);
    return sessions_.size();
}

void AnalysisSessionRegistry::SetClosedCallback(ClosedCallback callback)
{
    std::lock_guard lock(mutex_);
    closedCallback_ = std::move(callback);
}

bool AnalysisSessionRegistry::Expired(
    const AnalysisSessionRecord& record, Clock::time_point now) const
{
    return record.retainers == 0 && now - record.lastActive >= ttl_;
}

void AnalysisSessionRegistry::Remove(
    std::unordered_map<std::string, AnalysisSessionRecord>::iterator record)
{
    const auto removed = record->second;
    if (record->second.legacyTransportId)
        legacySessions_.erase(*record->second.legacyTransportId);
    references_.Release(record->first);
    sessions_.erase(record);
    if (closedCallback_)
        closedCallback_(removed);
}
}
