#pragma once

#include "binjad/config.hpp"
#include "binjad/ipc/envelope.hpp"
#include "binjad/process/supervisor.hpp"
#include "binjad/project/local_project_registry.hpp"

#include <filesystem>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::overseer
{
class ProjectQueueGuard;

template <typename T>
struct ProjectCoordinatorResult
{
    std::optional<T> value;
    std::string error;
};

struct ExportedProjectFile
{
    std::filesystem::path path;
    std::filesystem::path workingDirectory;
    std::string internalId;
    std::string projectPath;
};

class ProjectChildCoordinator
{
  public:
    ProjectChildCoordinator(Config config, std::filesystem::path executable,
        ProcessSupervisor& supervisor, ChildChannelAcceptor& acceptor,
        project::LocalProjectRegistry& projects, std::mutex* launchMutex = nullptr,
        project::KnownProjectStore* knownProjects = nullptr);
    ProjectChildCoordinator(const ProjectChildCoordinator&) = delete;
    ProjectChildCoordinator& operator=(const ProjectChildCoordinator&) = delete;
    ~ProjectChildCoordinator();

    ProjectCoordinatorResult<std::vector<project::LocalProjectFileRecord>> ListFiles(
        std::string_view project);
    ProjectCoordinatorResult<ExportedProjectFile> ExportFile(
        std::string_view project, std::string_view path);
    ProjectCoordinatorResult<project::LocalProjectFileRecord> CommitFile(
        std::string_view project, std::string_view path,
        const std::filesystem::path& source, bool replaceExisting,
        bool createFolders = false,
        std::string_view description = "Saved analysis database");
    ProjectCoordinatorResult<project::LocalProjectRecord> CreateProject(
        const std::filesystem::path& path, std::string name, std::string description);
    ProjectCoordinatorResult<project::LocalProjectRecord> RegisterProject(
        const std::filesystem::path& path);
    ProjectCoordinatorResult<project::LocalProjectRecord> UpdateProject(
        std::string_view project, std::optional<std::string> name,
        std::optional<std::string> description);
    ProjectCoordinatorResult<std::vector<project::LocalProjectFolderRecord>> ListFolders(
        std::string_view project);
    ProjectCoordinatorResult<project::LocalProjectFolderRecord> FindFolder(
        std::string_view project, std::string_view path);
    ProjectCoordinatorResult<project::LocalProjectFolderRecord> CreateFolder(
        std::string_view project, std::optional<std::string_view> parentInternalId,
        std::string name, std::string description);
    ProjectCoordinatorResult<project::LocalProjectFolderRecord> UpdateFolder(
        std::string_view project, std::string_view folderInternalId,
        std::optional<std::string> name,
        std::optional<std::string> description,
        std::optional<std::optional<std::string>> parentInternalId);
    std::string DeleteFolder(std::string_view project,
        std::string_view folderInternalId, bool recursive);
    ProjectCoordinatorResult<project::LocalProjectFileRecord> UpdateFile(
        std::string_view project, std::string_view path,
        std::optional<std::string> name,
        std::optional<std::string> description,
        std::optional<std::optional<std::string>> folderInternalId);
    std::string DeleteFile(std::string_view project,
        std::string_view path, bool confirmed);
    std::string DeleteProject(std::string_view project);

  private:
    friend class ProjectQueueGuard;
    void Start();
    void Stop() noexcept;
    ipc::Reply Call(const ipc::Command& command);
    ipc::Reply CallWithRecovery(const ipc::Command& command);
    void LoadCatalog();
    void EnterQueue();
    void LeaveQueue();

    Config config_;
    std::filesystem::path executable_;
    ProcessSupervisor& supervisor_;
    ChildChannelAcceptor& acceptor_;
    project::LocalProjectRegistry& projects_;
    project::KnownProjectStore* knownProjects_;
    std::mutex* launchMutex_;
    ProcessId processId_ = 0;
    std::unique_ptr<ipc::ByteChannel> channel_;
    ipc::RequestIdSource requestIds_;
    std::mutex queueMutex_;
    std::condition_variable queueCondition_;
    std::uint64_t nextTicket_ = 0;
    std::uint64_t servingTicket_ = 0;
};
}
