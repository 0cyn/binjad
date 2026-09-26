#pragma once

#include "binjad/Config.hpp"
#include "binjad/process/Supervisor.hpp"
#include "binjad/security/TokenAuthenticator.hpp"
#include "binjad/session/OpenItemRegistry.hpp"

#include <ipc.pb.h>

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace binjad::overseer
{
template <typename T>
struct CoordinatorResult
{
    std::optional<T> value;
    std::string error;
};

struct DiffSecondary
{
    std::filesystem::path path;
    std::string key;
};

class FileChildCoordinator
{
  public:
    using EventCallback = std::function<void(std::string_view, const ipc::Event&)>;
    using AnalysisProgressCallback = std::function<void(const ipc::Progress&)>;

    FileChildCoordinator(Config config, std::filesystem::path executable,
        ProcessSupervisor& supervisor, ChildChannelAcceptor& acceptor,
        session::OpenItemRegistry& openItems, EventCallback eventCallback = {},
        std::mutex* launchMutex = nullptr);
    FileChildCoordinator(const FileChildCoordinator&) = delete;
    FileChildCoordinator& operator=(const FileChildCoordinator&) = delete;
    ~FileChildCoordinator();

    CoordinatorResult<session::OpenItemRecord> OpenArbitraryPath(
        const security::TokenRecord& principal, std::string analysisSession,
        const std::filesystem::path& path, std::string optionsJson = "{}",
        bool reuseDatabase = true);
    CoordinatorResult<session::OpenItemRecord> OpenManagedPath(
        const security::TokenRecord& principal, std::string analysisSession,
        const std::filesystem::path& path, std::string optionsJson = "{}",
        bool reuseDatabase = true,
        session::OpenItemSourceKind sourceKind = session::OpenItemSourceKind::ArbitraryPath,
        std::string source = {}, std::optional<std::string> project = {});
    CoordinatorResult<session::BinaryViewRecord> OpenBinaryView(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view binaryView, std::string optionsJson = "{}", bool analyze = true);
    CoordinatorResult<ipc::AnalysisStatus> AnalysisStatus(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view binaryView);
    std::string UpdateAnalysis(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view binaryView);
    std::string SetWorkerCount(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view binaryView,
        std::size_t count);
    CoordinatorResult<ipc::AnalysisFinished> UpdateAnalysisAndWait(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view binaryView, AnalysisProgressCallback progress = {});
    CoordinatorResult<ipc::BinaryViewSaved> SaveBinaryView(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view binaryView, const std::filesystem::path& destination,
        AnalysisProgressCallback progress = {});
    CoordinatorResult<std::string> ExecuteAnalysisTool(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view binaryView, std::string_view name,
        std::string argumentsJson);
    CoordinatorResult<DiffSecondary> StageDiffView(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view primary,
        std::string_view secondary, std::string key);
    CoordinatorResult<DiffSecondary> StageDiffFile(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view primary,
        const std::filesystem::path& source, std::string key);
    CoordinatorResult<ipc::AnalysisFinished> RunDiffAndWait(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view primary, const DiffSecondary& secondary,
        AnalysisProgressCallback progress = {});
    CoordinatorResult<std::string> ExecuteDiffTool(
        std::string_view ownerTokenId, std::string_view analysisSession,
        std::string_view primary, const DiffSecondary& secondary,
        std::string_view name, std::string argumentsJson = "{}");
    std::string PromoteSavedBinaryView(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view binaryView,
        const std::filesystem::path& savedDatabase);
    std::string AbortAnalysis(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view binaryView);
    std::string Close(
        std::string_view ownerTokenId, std::string_view openItem, bool discardUncommitted);
    void CloseAnalysisSession(
        std::string_view ownerTokenId, std::string_view analysisSession);
    void CloseToken(std::string_view ownerTokenId);
    std::size_t Size() const;

  private:
    class Child;
    struct ExitGate;
    std::shared_ptr<Child> ChildForView(std::string_view ownerTokenId,
        std::string_view analysisSession, std::string_view binaryView,
        session::BinaryViewRecord& view, std::string& error);
    std::shared_ptr<Child> RecoverIfNeeded(
        std::string_view openItem, std::shared_ptr<Child> child, std::string& error);
    std::shared_ptr<Child> Restart(
        std::string_view openItem, const std::shared_ptr<Child>& previous, std::string& error);
    void HandleExit(const ChildExit& exit);
    void CleanupWorkingDirectory(const std::filesystem::path& path) const;

    Config config_;
    std::filesystem::path executable_;
    ProcessSupervisor& supervisor_;
    ChildChannelAcceptor& acceptor_;
    session::OpenItemRegistry& openItems_;
    EventCallback eventCallback_;
    std::mutex* launchMutex_;
    std::unordered_map<std::string, std::shared_ptr<Child>> children_;
    std::shared_ptr<ExitGate> exitGate_;
    mutable std::mutex restartMutex_;
    mutable std::mutex mutex_;
};
}
