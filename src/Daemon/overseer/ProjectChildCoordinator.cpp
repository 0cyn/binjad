#include "binjad/overseer/ProjectChildCoordinator.hpp"

#include "binjad/ipc/Envelope.hpp"
#include "binjad/platform/Paths.hpp"
#include "binjad/security/Random.hpp"

#include <algorithm>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace binjad::overseer
{
class ProjectQueueGuard
{
  public:
    explicit ProjectQueueGuard(ProjectChildCoordinator& coordinator)
        : coordinator_(coordinator)
    {
        coordinator_.EnterQueue();
    }
    ~ProjectQueueGuard() { coordinator_.LeaveQueue(); }

  private:
    ProjectChildCoordinator& coordinator_;
};

namespace
{
bool ValidProjectPath(std::string_view path)
{
    if (path.empty())
        return false;
    const std::filesystem::path value(path);
    if (value.is_absolute())
        return false;
    const auto normalized = value.lexically_normal();
    return normalized != "." && !normalized.empty() &&
        *normalized.begin() != "..";
}

bool LexicallyContained(const std::filesystem::path& path, const std::filesystem::path& root)
{
    const auto relative = path.lexically_normal().lexically_relative(root.lexically_normal());
    return !relative.empty() && !relative.is_absolute() && *relative.begin() != "..";
}

}

void ProjectChildCoordinator::EnterQueue()
{
    std::unique_lock lock(queueMutex_);
    const auto ticket = nextTicket_++;
    queueCondition_.wait(lock, [&] { return ticket == servingTicket_; });
}

void ProjectChildCoordinator::LeaveQueue()
{
    {
        std::lock_guard lock(queueMutex_);
        ++servingTicket_;
    }
    queueCondition_.notify_all();
}
ProjectChildCoordinator::ProjectChildCoordinator(Config config,
    std::filesystem::path executable, ProcessSupervisor& supervisor,
    ChildChannelAcceptor& acceptor, project::LocalProjectRegistry& projects,
    std::mutex* launchMutex, project::KnownProjectStore* knownProjects)
    : config_(std::move(config)), executable_(std::move(executable)),
      supervisor_(supervisor), acceptor_(acceptor), projects_(projects),
      knownProjects_(knownProjects), launchMutex_(launchMutex)
{
    if (executable_.empty())
        throw std::invalid_argument("project child executable path must not be empty");
    Start();
}

ProjectChildCoordinator::~ProjectChildCoordinator()
{
    Stop();
}

void ProjectChildCoordinator::Start()
{
    std::unique_lock<std::mutex> launchLock;
    if (launchMutex_)
        launchLock = std::unique_lock(*launchMutex_);
    processId_ = supervisor_.Spawn(executable_, ProcessRole::ProjectChild);
    try
    {
        channel_ = acceptor_.Accept(processId_, ProcessRole::ProjectChild);
        LoadCatalog();
    }
    catch (...)
    {
        Stop();
        throw;
    }
}

void ProjectChildCoordinator::Stop() noexcept
{
    bool graceful = false;
    if (channel_)
    {
        try
        {
            ipc::Command command;
            command.mutable_shutdown();
            const auto reply = Call(command);
            graceful = reply.success();
        }
        catch (...)
        {}
        channel_->Close();
        channel_.reset();
    }
    if (processId_ != 0 && !graceful)
    {
        try
        {
            supervisor_.Terminate(processId_);
        }
        catch (...)
        {}
        processId_ = 0;
    }
}

ipc::Reply ProjectChildCoordinator::CallWithRecovery(const ipc::Command& command)
{
    try
    {
        return Call(command);
    }
    catch (...)
    {
        Stop();
        Start();
        return Call(command);
    }
}

ipc::Reply ProjectChildCoordinator::Call(const ipc::Command& command)
{
    if (!channel_)
        throw std::runtime_error("project child is unavailable");
    ipc::Envelope request;
    request.set_protocol_version(ipc::kProtocolVersion);
    request.set_request_id(requestIds_.Next());
    *request.mutable_command() = command;
    ipc::SendEnvelope(*channel_, request);
    const auto response = ipc::ReceiveEnvelope(*channel_);
    if (!response.has_reply() || response.request_id() != request.request_id())
        throw std::runtime_error("project child returned a mismatched reply");
    return response.reply();
}

void ProjectChildCoordinator::LoadCatalog()
{
    ipc::Command command;
    auto* scan = command.mutable_scan_local_projects();
    for (const auto& root : config_.projects.roots)
        scan->add_roots(root.string());
    const auto reply = Call(command);
    if (!reply.success() || !reply.has_local_project_catalog())
        throw std::runtime_error(reply.success()
            ? "project child returned no catalog" : reply.error());
    std::vector<project::LocalProjectRecord> records;
    records.reserve(reply.local_project_catalog().projects_size());
    std::unordered_set<std::string> rootIds;
    for (const auto& item : reply.local_project_catalog().projects())
    {
        records.push_back({{}, item.id(), item.path(), item.name(), item.description()});
        rootIds.insert(item.id());
    }
    if (knownProjects_)
    {
        for (const auto& path : knownProjects_->Paths())
        {
            ipc::Command registeredCommand;
            registeredCommand.mutable_scan_local_projects()->add_projects(path.string());
            const auto registeredReply = Call(registeredCommand);
            if (!registeredReply.success() || !registeredReply.has_local_project_catalog()
                || registeredReply.local_project_catalog().projects_size() != 1)
                throw std::runtime_error(registeredReply.success()
                    ? "project child returned an invalid registered-project catalog" : registeredReply.error());
            const auto& item = registeredReply.local_project_catalog().projects(0);
            const auto existing = std::find_if(records.begin(), records.end(), [&](const auto& record) {
                return record.internalId == item.id();
            });
            if (existing != records.end())
            {
                if (!rootIds.contains(item.id()))
                    throw std::runtime_error("duplicate registered project ID at " + existing->storagePath.string()
                        + " and " + path.string());
                if (const auto error = knownProjects_->Remove(path); !error.empty())
                    throw std::runtime_error("cannot remove redundant rooted-project registration: " + error);
                continue;
            }
            records.push_back({{}, item.id(), item.path(), item.name(), item.description()});
        }
    }
    if (const auto error = projects_.Replace(std::move(records)); !error.empty())
        throw std::runtime_error("cannot register local project catalog: " + error);
}

ProjectCoordinatorResult<std::vector<project::LocalProjectFileRecord>>
ProjectChildCoordinator::ListFiles(std::string_view projectReference)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    const auto folders = ListFolders(projectReference);
    if (!folders.value)
        return {{}, folders.error};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        command.mutable_list_local_project_files()->set_project_path(
            project->storagePath.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_files())
            return {{}, reply.success() ? "project child returned no file list" : reply.error()};
        std::vector<project::LocalProjectFileRecord> result;
        result.reserve(reply.local_project_files().files_size());
        for (const auto& file : reply.local_project_files().files())
            result.push_back({file.id(), file.path(), file.name(), file.description(),
                file.creation_timestamp(), {}, file.folder_id(), {}, file.backing_path()});
        if (const auto assigned = projects_.AssignFiles(projectReference, result);
            !assigned.empty())
            return {{}, assigned};
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<ExportedProjectFile> ProjectChildCoordinator::ExportFile(
    std::string_view projectReference, std::string_view path)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    if (!ValidProjectPath(path))
        return {{}, "project file path must be relative and contained"};
    auto random = security::GenerateHex256();
    if (!random.value)
        return {{}, random.error};
    const auto directory = config_.storage.spoolPath / "project-exports" / *random.value;
    auto leaf = std::filesystem::path(path).filename();
    if (leaf.empty())
        leaf = "project-file";
    const auto destination = directory / leaf;
    const auto placeholder = platform::CreatePrivateFileIfAbsent(destination, {});
    if (!placeholder.created || !placeholder.error.empty())
        return {{}, placeholder.error};
    std::error_code ignored;
    std::filesystem::remove(destination, ignored);

    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        auto* exportFile = command.mutable_export_local_project_file();
        exportFile->set_project_path(project->storagePath.string());
        exportFile->set_path(path.data(), path.size());
        exportFile->set_destination(destination.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_file_exported())
        {
            std::filesystem::remove_all(directory, ignored);
            return {{}, reply.success() ? "project child returned no export result" : reply.error()};
        }
        const auto& result = reply.local_project_file_exported();
        return {ExportedProjectFile{destination, directory, result.id(), result.path()}, {}};
    }
    catch (const std::exception& exception)
    {
        std::filesystem::remove_all(directory, ignored);
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectFileRecord>
ProjectChildCoordinator::CommitFile(std::string_view projectReference,
    std::string_view path, const std::filesystem::path& source, bool replaceExisting,
    bool createFolders, std::string_view description)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    if (!ValidProjectPath(path))
        return {{}, "project file path must be relative and contained"};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        auto* commit = command.mutable_commit_local_project_file();
        commit->set_project_path(project->storagePath.string());
        commit->set_source_path(source.string());
        commit->set_path(path.data(), path.size());
        commit->set_replace_existing(replaceExisting);
        commit->set_create_folders(createFolders);
        commit->set_description(description.data(), description.size());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_file_committed())
            return {{}, reply.success() ? "project child returned no commit result" : reply.error()};
        const auto& result = reply.local_project_file_committed();
        return {project::LocalProjectFileRecord{
            result.id(), result.path(), std::filesystem::path(result.path()).filename().string(),
            {}, 0, std::string(projectReference), {}, {}, {}}, {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectRecord>
ProjectChildCoordinator::CreateProject(const std::filesystem::path& path,
    std::string name, std::string description)
{
    std::error_code filesystemError;
    if (std::filesystem::exists(path, filesystemError))
        return {{}, "project destination already exists"};
    std::filesystem::create_directories(path.parent_path(), filesystemError);
    if (filesystemError)
        return {{}, "cannot create project parent directory: " + filesystemError.message()};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        auto* create = command.mutable_create_local_project();
        create->set_path(path.string());
        create->set_name(std::move(name));
        create->set_description(std::move(description));
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project())
            return {{}, reply.success() ? "project child returned no project" : reply.error()};
        project::LocalProjectRecord result{{}, reply.local_project().id(),
            reply.local_project().path(), reply.local_project().name(),
            reply.local_project().description()};
        const bool rooted = std::any_of(config_.projects.roots.begin(), config_.projects.roots.end(),
            [&](const auto& root) { return LexicallyContained(result.storagePath, root); });
        if (knownProjects_ && !rooted)
        {
            if (const auto error = knownProjects_->Add(result.storagePath); !error.empty())
                return {{}, "project was created but registration could not be persisted: " + error};
        }
        if (const auto error = projects_.Upsert(result); !error.empty())
            return {{}, error};
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectRecord>
ProjectChildCoordinator::RegisterProject(const std::filesystem::path& path)
{
    if (!knownProjects_)
        return {{}, "known project registry is unavailable"};
    const auto normalized = path.lexically_normal();
    if (!normalized.is_absolute() ||
        (normalized.extension() != ".bnpr" && normalized.extension() != ".bnpm"))
        return {{}, "project path must be an absolute .bnpr or .bnpm path"};
    if (std::any_of(config_.projects.roots.begin(), config_.projects.roots.end(),
            [&](const auto& root) { return LexicallyContained(normalized, root); }))
        return {{}, "project is already managed by a configured project root"};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        command.mutable_scan_local_projects()->add_projects(normalized.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_catalog())
            return {{}, reply.success() ? "project child returned no catalog" : reply.error()};
        if (reply.local_project_catalog().projects_size() != 1)
            return {{}, "project child returned an unexpected project count"};
        const auto& item = reply.local_project_catalog().projects(0);
        for (const auto& existing : projects_.List())
        {
            if (existing.internalId == item.id() && existing.storagePath != normalized)
                return {{}, "project durable ID is already registered at another path"};
        }
        project::LocalProjectRecord result{
            {}, item.id(), item.path(), item.name(), item.description()};
        if (const auto error = knownProjects_->Add(result.storagePath); !error.empty())
            return {{}, error};
        if (const auto error = projects_.Upsert(result); !error.empty())
        {
            (void)knownProjects_->Remove(result.storagePath);
            return {{}, error};
        }
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectRecord>
ProjectChildCoordinator::RelocateProject(std::string_view projectReference,
    const std::filesystem::path& stagingPath, const std::filesystem::path& destination)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    if (!knownProjects_)
        return {{}, "known project registry is unavailable"};
    std::error_code filesystemError;
    if (std::filesystem::exists(destination, filesystemError) || filesystemError)
        return {{}, filesystemError ? "cannot inspect project destination: " + filesystemError.message()
                                    : "project destination already exists"};

    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        command.mutable_scan_local_projects()->add_projects(stagingPath.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_catalog())
            return {{}, reply.success() ? "project child returned no catalog" : reply.error()};
        if (reply.local_project_catalog().projects_size() != 1)
            return {{}, "project child returned an unexpected project count"};
        const auto& inspected = reply.local_project_catalog().projects(0);
        if (inspected.id() != project->internalId)
            return {{}, "copied project durable ID does not match the source project"};

        std::filesystem::rename(stagingPath, destination, filesystemError);
        if (filesystemError)
            return {{}, "cannot install copied project: " + filesystemError.message()};

        if (const auto error = knownProjects_->Remove(project->storagePath); !error.empty())
        {
            std::error_code rollbackError;
            std::filesystem::rename(destination, stagingPath, rollbackError);
            return {{}, "copied project was not adopted because registration removal failed: " + error
                    + (rollbackError ? "; destination rollback also failed: " + rollbackError.message() : "")};
        }

        project::LocalProjectRecord result{
            {}, inspected.id(), destination, inspected.name(), inspected.description()};
        if (const auto error = projects_.Upsert(result); !error.empty())
        {
            const auto registrationError = knownProjects_->Add(project->storagePath);
            std::error_code rollbackError;
            std::filesystem::rename(destination, stagingPath, rollbackError);
            return {{}, "copied project catalog update failed: " + error
                    + (registrationError.empty() ? "" : "; source re-registration failed: " + registrationError)
                    + (rollbackError ? "; destination rollback also failed: " + rollbackError.message() : "")};
        }
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectRecord>
ProjectChildCoordinator::UpdateProject(std::string_view projectReference,
    std::optional<std::string> name, std::optional<std::string> description)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        auto* update = command.mutable_update_local_project();
        update->set_project_path(project->storagePath.string());
        if (name)
            update->set_name(std::move(*name));
        if (description)
            update->set_description(std::move(*description));
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project())
            return {{}, reply.success() ? "project child returned no project" : reply.error()};
        project::LocalProjectRecord result{{}, reply.local_project().id(),
            reply.local_project().path(), reply.local_project().name(),
            reply.local_project().description()};
        if (const auto error = projects_.Upsert(result); !error.empty())
            return {{}, error};
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<std::vector<project::LocalProjectFolderRecord>>
ProjectChildCoordinator::ListFolders(std::string_view projectReference)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        command.mutable_list_local_project_folders()->set_project_path(
            project->storagePath.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success() || !reply.has_local_project_folders())
            return {{}, reply.success() ? "project child returned no folder list" : reply.error()};
        std::vector<project::LocalProjectFolderRecord> result;
        for (const auto& folder : reply.local_project_folders().folders())
            result.push_back({folder.id(), folder.parent_id(), folder.path(), folder.name(),
                folder.description(), {}, {}});
        if (const auto assigned = projects_.AssignFolders(projectReference, result);
            !assigned.empty())
            return {{}, assigned};
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        return {{}, exception.what()};
    }
}

ProjectCoordinatorResult<project::LocalProjectFolderRecord>
ProjectChildCoordinator::FindFolder(std::string_view projectReference, std::string_view path)
{
    const auto folders = ListFolders(projectReference);
    if (!folders.value)
        return {{}, folders.error};
    std::optional<project::LocalProjectFolderRecord> found;
    for (const auto& folder : *folders.value)
    {
        if (folder.path != path)
            continue;
        if (found)
            return {{}, "project folder path is ambiguous"};
        found = folder;
    }
    return found ? ProjectCoordinatorResult<project::LocalProjectFolderRecord>{*found, {}}
                 : ProjectCoordinatorResult<project::LocalProjectFolderRecord>{{},
                       "project folder not found"};
}

ProjectCoordinatorResult<project::LocalProjectFolderRecord>
ProjectChildCoordinator::CreateFolder(std::string_view projectReference,
    std::optional<std::string_view> parentInternalId,
    std::string name, std::string description)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return {{}, "project not found"};
    std::string parentId;
    if (parentInternalId) parentId = *parentInternalId;
    std::string createdId;
    {
        ProjectQueueGuard queue(*this);
        try
        {
            ipc::Command command;
            auto* create = command.mutable_create_local_project_folder();
            create->set_project_path(project->storagePath.string());
            create->set_parent_id(parentId);
            create->set_name(std::move(name));
            create->set_description(std::move(description));
            const auto reply = CallWithRecovery(command);
            if (!reply.success() || !reply.has_local_project_folder())
                return {{}, reply.success() ? "project child returned no folder" : reply.error()};
            createdId = reply.local_project_folder().id();
        }
        catch (const std::exception& exception)
        {
            return {{}, exception.what()};
        }
    }
    const auto folders = ListFolders(projectReference);
    if (!folders.value)
        return {{}, folders.error};
    const auto created = std::find_if(folders.value->begin(), folders.value->end(),
        [&](const auto& folder) { return folder.internalId == createdId; });
    return created == folders.value->end()
        ? ProjectCoordinatorResult<project::LocalProjectFolderRecord>{{}, "created folder not found"}
        : ProjectCoordinatorResult<project::LocalProjectFolderRecord>{*created, {}};
}

ProjectCoordinatorResult<project::LocalProjectFolderRecord>
ProjectChildCoordinator::UpdateFolder(std::string_view projectReference,
    std::string_view folderInternalId,
    std::optional<std::string> name, std::optional<std::string> description,
    std::optional<std::optional<std::string>> parentInternalId)
{
    const auto folder = projects_.FindFolderById(projectReference, folderInternalId);
    if (!folder)
        return {{}, "project folder not found"};
    const auto project = projects_.Find(folder->project);
    if (!project)
        return {{}, "project not found"};
    std::optional<std::string> parentId;
    if (parentInternalId)
    {
        parentId = std::string{};
        if (*parentInternalId) parentId = **parentInternalId;
    }
    {
        ProjectQueueGuard queue(*this);
        try
        {
            ipc::Command command;
            auto* update = command.mutable_update_local_project_folder();
            update->set_project_path(project->storagePath.string());
            update->set_id(folder->internalId);
            if (name)
                update->set_name(std::move(*name));
            if (description)
                update->set_description(std::move(*description));
            if (parentId)
                update->set_parent_id(*parentId);
            const auto reply = CallWithRecovery(command);
            if (!reply.success())
                return {{}, reply.error()};
        }
        catch (const std::exception& exception)
        {
            return {{}, exception.what()};
        }
    }
    const auto folders = ListFolders(folder->project);
    if (!folders.value)
        return {{}, folders.error};
    const auto updated = std::find_if(folders.value->begin(), folders.value->end(),
        [&](const auto& value) { return value.internalId == folder->internalId; });
    return updated == folders.value->end()
        ? ProjectCoordinatorResult<project::LocalProjectFolderRecord>{{}, "updated folder not found"}
        : ProjectCoordinatorResult<project::LocalProjectFolderRecord>{*updated, {}};
}

std::string ProjectChildCoordinator::DeleteFolder(
    std::string_view projectReference, std::string_view folderInternalId, bool recursive)
{
    const auto folder = projects_.FindFolderById(projectReference, folderInternalId);
    if (!folder)
        return "project folder not found";
    const auto project = projects_.Find(folder->project);
    if (!project)
        return "project not found";
    {
        ProjectQueueGuard queue(*this);
        try
        {
            ipc::Command command;
            auto* remove = command.mutable_delete_local_project_folder();
            remove->set_project_path(project->storagePath.string());
            remove->set_id(folder->internalId);
            remove->set_recursive(recursive);
            const auto reply = CallWithRecovery(command);
            if (!reply.success())
                return reply.error();
        }
        catch (const std::exception& exception)
        {
            return exception.what();
        }
    }
    (void)ListFolders(folder->project);
    (void)ListFiles(folder->project);
    return {};
}

ProjectCoordinatorResult<project::LocalProjectFileRecord>
ProjectChildCoordinator::UpdateFile(std::string_view projectReference,
    std::string_view path,
    std::optional<std::string> name, std::optional<std::string> description,
    std::optional<std::optional<std::string>> folderInternalId)
{
    const auto file = projects_.FindFile(projectReference, path);
    if (!file)
        return {{}, "project file not found"};
    const auto project = projects_.Find(file->project);
    if (!project)
        return {{}, "project not found"};
    std::optional<std::string> folderId;
    if (folderInternalId)
    {
        folderId = std::string{};
        if (*folderInternalId) folderId = **folderInternalId;
    }
    {
        ProjectQueueGuard queue(*this);
        try
        {
            ipc::Command command;
            auto* update = command.mutable_update_local_project_file();
            update->set_project_path(project->storagePath.string());
            update->set_id(file->internalId);
            if (name)
                update->set_name(std::move(*name));
            if (description)
                update->set_description(std::move(*description));
            if (folderId)
                update->set_folder_id(*folderId);
            const auto reply = CallWithRecovery(command);
            if (!reply.success())
                return {{}, reply.error()};
        }
        catch (const std::exception& exception)
        {
            return {{}, exception.what()};
        }
    }
    const auto files = ListFiles(file->project);
    if (!files.value)
        return {{}, files.error};
    const auto updated = std::find_if(files.value->begin(), files.value->end(),
        [&](const auto& value) { return value.internalId == file->internalId; });
    return updated == files.value->end()
        ? ProjectCoordinatorResult<project::LocalProjectFileRecord>{{}, "updated file not found"}
        : ProjectCoordinatorResult<project::LocalProjectFileRecord>{*updated, {}};
}

std::string ProjectChildCoordinator::DeleteFile(
    std::string_view projectReference, std::string_view path, bool confirmed)
{
    const auto file = projects_.FindFile(projectReference, path);
    if (!file)
        return "project file not found";
    const auto project = projects_.Find(file->project);
    if (!project)
        return "project not found";
    {
        ProjectQueueGuard queue(*this);
        try
        {
            ipc::Command command;
            auto* remove = command.mutable_delete_local_project_file();
            remove->set_project_path(project->storagePath.string());
            remove->set_id(file->internalId);
            remove->set_delete_(confirmed);
            const auto reply = CallWithRecovery(command);
            if (!reply.success())
                return reply.error();
        }
        catch (const std::exception& exception)
        {
            return exception.what();
        }
    }
    projects_.RemoveFile(projectReference, path);
    return {};
}

std::string ProjectChildCoordinator::DeleteProject(std::string_view projectReference)
{
    const auto project = projects_.Find(projectReference);
    if (!project)
        return "project not found";
    ProjectQueueGuard queue(*this);
    try
    {
        ipc::Command command;
        command.mutable_delete_local_project()->set_project_path(
            project->storagePath.string());
        const auto reply = CallWithRecovery(command);
        if (!reply.success())
            return reply.error();
    }
    catch (const std::exception& exception)
    {
        return exception.what();
    }
    projects_.RemoveProject(projectReference);
    return knownProjects_ ? knownProjects_->Remove(project->storagePath) : std::string{};
}
}
