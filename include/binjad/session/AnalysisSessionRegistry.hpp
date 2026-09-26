#pragma once

#include "binjad/mcp/Protocol.hpp"
#include "binjad/reference/FriendlyReference.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binjad::session
{
struct AnalysisSessionRecord
{
    std::string reference;
    std::string ownerTokenId;
    std::uint64_t createdAtUnix = 0;
    std::chrono::steady_clock::time_point lastActive;
    std::optional<std::string> legacyTransportId;
    std::optional<mcp::ProtocolVersion> legacyVersion;
    std::size_t retainers = 0;
};

struct AnalysisSessionCreateResult
{
    std::optional<AnalysisSessionRecord> session;
    std::string error;
};

class AnalysisSessionRegistry
{
  public:
    using Clock = std::chrono::steady_clock;
    using ClosedCallback = std::function<void(const AnalysisSessionRecord&)>;

    AnalysisSessionRegistry(
        reference::FriendlyReferencePool& references, std::chrono::seconds ttl);
    AnalysisSessionRegistry(const AnalysisSessionRegistry&) = delete;
    AnalysisSessionRegistry& operator=(const AnalysisSessionRegistry&) = delete;
    ~AnalysisSessionRegistry();

    AnalysisSessionCreateResult Create(std::string ownerTokenId, std::uint64_t createdAtUnix,
        Clock::time_point now, std::optional<mcp::ProtocolVersion> legacyVersion = std::nullopt);
    std::optional<AnalysisSessionRecord> Find(
        std::string_view reference, std::string_view ownerTokenId, Clock::time_point now,
        bool refresh = true);
    std::optional<AnalysisSessionRecord> FindLegacy(
        std::string_view transportId, std::string_view ownerTokenId, Clock::time_point now,
        bool refresh = true);
    std::vector<AnalysisSessionRecord> List(
        std::string_view ownerTokenId, Clock::time_point now);
    bool Close(std::string_view reference, std::string_view ownerTokenId, bool force = false);
    std::vector<AnalysisSessionRecord> CloseByOwner(std::string_view ownerTokenId);
    bool Retain(std::string_view reference, std::string_view ownerTokenId, Clock::time_point now);
    bool Release(std::string_view reference, std::string_view ownerTokenId);
    std::vector<AnalysisSessionRecord> Sweep(Clock::time_point now);
    std::size_t Size() const;
    void SetClosedCallback(ClosedCallback callback);

  private:
    bool Expired(const AnalysisSessionRecord& record, Clock::time_point now) const;
    void Remove(std::unordered_map<std::string, AnalysisSessionRecord>::iterator record);

    reference::FriendlyReferencePool& references_;
    std::chrono::seconds ttl_;
    std::unordered_map<std::string, AnalysisSessionRecord> sessions_;
    std::unordered_map<std::string, std::string> legacySessions_;
    ClosedCallback closedCallback_;
    mutable std::mutex mutex_;
};
}
