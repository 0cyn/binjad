#pragma once

#include "binjad/config.hpp"
#include "binjad/project/local_project_registry.hpp"
#include "binjad/project/collaboration_project_registry.hpp"
#include "binjad/reference/friendly_reference.hpp"
#include "binjad/security/crypto.hpp"
#include "binjad/session/analysis_session_registry.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binjad::upload
{
enum class UploadState
{
    Ready,
    Receiving,
    Completed,
    Committing,
    Committed,
};

struct UploadRecord
{
    std::string id;
    std::string ownerTokenId;
    std::string analysisSession;
    std::string project;
    std::string filename;
    UploadState state = UploadState::Ready;
    std::uint64_t createdAtUnix = 0;
    std::uint64_t expiresAtUnix = 0;
    std::uint64_t size = 0;
    std::string sha256;
};

struct UploadIssueResult
{
    std::optional<UploadRecord> upload;
    std::string url;
    std::string error;
};

struct UploadPayload
{
    UploadRecord upload;
    std::filesystem::path path;
};

class UploadRegistry;

class UploadTransfer
{
  public:
    UploadTransfer(const UploadTransfer&) = delete;
    UploadTransfer& operator=(const UploadTransfer&) = delete;
    ~UploadTransfer();

    bool Write(std::string_view data, std::string& error);
    std::optional<UploadRecord> Finish(std::string& error);
    void Abort();

  private:
    friend class UploadRegistry;
    UploadTransfer(UploadRegistry& registry, std::string id,
        std::uint64_t maximum, std::uint64_t memoryThreshold,
        std::filesystem::path spoolDirectory);
    bool Spill(std::string& error);

    UploadRegistry* registry_;
    std::string id_;
    std::uint64_t maximum_;
    std::uint64_t memoryThreshold_;
    std::filesystem::path spoolDirectory_;
    std::filesystem::path spoolPath_;
    std::vector<char> memory_;
    std::ofstream stream_;
    security::Sha256Hasher hasher_;
    std::uint64_t size_ = 0;
    bool active_ = true;
};

class UploadRegistry
{
  public:
    using Clock = session::AnalysisSessionRegistry::Clock;

    UploadRegistry(Config config, reference::FriendlyReferencePool& references,
        session::AnalysisSessionRegistry& sessions,
        project::LocalProjectRegistry& projects,
        project::CollaborationProjectRegistry* collaborationProjects = nullptr);
    UploadRegistry(const UploadRegistry&) = delete;
    UploadRegistry& operator=(const UploadRegistry&) = delete;
    ~UploadRegistry();

    UploadIssueResult Issue(std::string ownerTokenId, std::string analysisSession,
        std::string project, std::string filename,
        std::uint64_t nowUnix, Clock::time_point now);
    std::pair<std::unique_ptr<UploadTransfer>, std::string> Begin(
        std::string_view capability, std::string_view ownerTokenId,
        Clock::time_point now);
    std::pair<std::unique_ptr<UploadTransfer>, std::string> Begin(
        std::string_view capability, Clock::time_point now);
    std::optional<UploadRecord> FindCompleted(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view id,
        Clock::time_point now) const;
    std::pair<std::optional<UploadPayload>, std::string> PreparePayload(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view id, Clock::time_point now);
    std::optional<std::string> FindCommitResult(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view id) const;
    bool RecordCommit(std::string_view ownerTokenId, std::string_view id,
        std::string resultJson, bool cleanupPayload = true);
    bool CommitFailed(std::string_view ownerTokenId, std::string_view id);
    std::vector<UploadRecord> List(std::string_view ownerTokenId) const;
    std::string Cancel(std::string_view ownerTokenId, std::string_view id);
    bool Consume(std::string_view ownerTokenId, std::string_view id);
    void RemoveByAnalysisSession(std::string_view analysisSession);
    void RemoveByToken(std::string_view ownerTokenId);
    void Sweep(Clock::time_point now);
    std::size_t Size() const;

  private:
    friend class UploadTransfer;
    struct Entry
    {
        UploadRecord record;
        std::string capability;
        Clock::time_point expiresAt;
        std::vector<char> memory;
        std::filesystem::path path;
        std::string commitResultJson;
    };

    std::optional<UploadRecord> Complete(std::string_view id,
        std::vector<char> memory, std::filesystem::path path,
        std::uint64_t size, std::string sha256, std::string& error);
    void Abort(std::string_view id, const std::filesystem::path& spoolDirectory);
    void RemoveEntry(std::unordered_map<std::string, Entry>::iterator entry);
    static bool ValidFilename(std::string_view filename);
    std::pair<std::unique_ptr<UploadTransfer>, std::string> BeginImpl(
        std::string_view capability, std::optional<std::string_view> ownerTokenId,
        Clock::time_point now);

    Config config_;
    reference::FriendlyReferencePool& references_;
    session::AnalysisSessionRegistry& sessions_;
    project::LocalProjectRegistry& projects_;
    project::CollaborationProjectRegistry* collaborationProjects_;
    std::unordered_map<std::string, Entry> uploads_;
    std::unordered_map<std::string, std::string> capabilities_;
    mutable std::mutex mutex_;
};
}
