#include "binjad/overseer/collaboration_child_manager.hpp"

#include "binjad/platform/paths.hpp"
#include "binjad/security/random.hpp"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace binjad::overseer
{
class CollaborationChildManager::Child
{
  public:
    Child(ProcessId process, std::unique_ptr<ipc::ByteChannel> channel,
        CollaborationIdentity identity)
        : process(process), channel(std::move(channel)), identity(std::move(identity))
    {
    }

    ipc::Reply Call(const ipc::Command& command)
    {
        std::lock_guard lock(mutex);
        ipc::Envelope request;
        request.set_protocol_version(ipc::kProtocolVersion);
        request.set_request_id(requestIds.Next());
        *request.mutable_command() = command;
        ipc::SendEnvelope(*channel, request);
        const auto response = ipc::ReceiveEnvelope(*channel);
        if (!response.has_reply() || response.request_id() != request.request_id())
            throw std::runtime_error("collaboration child returned a mismatched reply");
        return response.reply();
    }

    void Stop(ProcessSupervisor& supervisor) noexcept
    {
        bool graceful = false;
        try
        {
            ipc::Command command;
            command.mutable_shutdown();
            graceful = Call(command).success();
        }
        catch (...)
        {}
        channel->Close();
        if (!graceful)
        {
            try { supervisor.Terminate(process); } catch (...) {}
        }
    }

    ProcessId process;
    std::unique_ptr<ipc::ByteChannel> channel;
    CollaborationIdentity identity;
    ipc::RequestIdSource requestIds;
    std::mutex mutex;
};

CollaborationChildManager::CollaborationChildManager(Config config,
    std::filesystem::path executable, ProcessSupervisor& supervisor,
    ChildChannelAcceptor& acceptor, project::CollaborationProjectRegistry& projects,
    IdentityResolver identities, std::mutex* launchMutex)
    : config_(std::move(config)), executable_(std::move(executable)),
      supervisor_(supervisor), acceptor_(acceptor), projects_(projects),
      identities_(std::move(identities)), launchMutex_(launchMutex)
{
}

CollaborationChildManager::~CollaborationChildManager()
{
    std::vector<std::shared_ptr<Child>> children;
    {
        std::lock_guard lock(mutex_);
        for (auto& [token, child] : children_)
            children.push_back(std::move(child));
        children_.clear();
    }
    for (const auto& child : children)
        child->Stop(supervisor_);
}

std::shared_ptr<CollaborationChildManager::Child> CollaborationChildManager::Start(
    CollaborationIdentity identity, std::string& error)
{
    ProcessId process = 0;
    try
    {
        std::unique_lock<std::mutex> launchLock;
        if (launchMutex_)
            launchLock = std::unique_lock<std::mutex>(*launchMutex_);
        process = supervisor_.Spawn(executable_, ProcessRole::ProjectChild);
        auto channel = acceptor_.Accept(process, ProcessRole::ProjectChild);
        auto child = std::make_shared<Child>(process, std::move(channel), identity);
        ipc::Command command;
        auto* configure = command.mutable_configure_collaboration();
        configure->set_remote_name(config_.collaboration.remote->name);
        configure->set_remote_url(config_.collaboration.remote->url);
        configure->set_username(identity.username);
        configure->set_access_token(identity.accessToken);
        const auto reply = child->Call(command);
        if (!reply.success())
            throw std::runtime_error(reply.error());
        return child;
    }
    catch (const std::exception& exception)
    {
        if (process != 0)
        {
            try { supervisor_.Terminate(process); } catch (...) {}
        }
        error = exception.what();
        return {};
    }
}

std::shared_ptr<CollaborationChildManager::Child> CollaborationChildManager::Ensure(
    const security::TokenRecord& principal, std::string& error)
{
    if (!config_.collaboration.remote)
    {
        error = "collaboration remote is not configured";
        return {};
    }
    const auto identity = identities_(principal);
    if (!identity.value)
    {
        RemoveByToken(principal.id);
        error = identity.error;
        return {};
    }
    std::shared_ptr<Child> previous;
    {
        std::lock_guard lock(mutex_);
        const auto child = children_.find(principal.id);
        if (child != children_.end() &&
            child->second->identity.username == identity.value->username &&
            child->second->identity.accessToken == identity.value->accessToken)
            return child->second;
        if (child != children_.end())
        {
            previous = std::move(child->second);
            children_.erase(child);
        }
    }
    if (previous)
        previous->Stop(supervisor_);
    auto child = Start(*identity.value, error);
    if (child)
    {
        std::lock_guard lock(mutex_);
        children_[principal.id] = child;
    }
    return child;
}

CollaborationResult<std::vector<project::CollaborationProjectRecord>>
CollaborationChildManager::ListProjects(const security::TokenRecord& principal)
{
    std::string error;
    const auto child = Ensure(principal, error);
    if (!child)
        return {{}, std::move(error)};
    try
    {
        ipc::Command command;
        command.mutable_list_collaboration_projects();
        const auto reply = child->Call(command);
        if (!reply.success() || !reply.has_collaboration_project_catalog())
            return {{}, reply.success() ? "collaboration child returned no catalog" : reply.error()};
        std::vector<project::CollaborationProjectRecord> result;
        for (const auto& item : reply.collaboration_project_catalog().projects())
            result.push_back({{}, principal.id, item.id(), item.name(), item.description(),
                item.created(), item.last_modified(), item.admin()});
        if (const auto registryError = projects_.Replace(principal.id, result);
            !registryError.empty())
            return {{}, registryError};
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        RemoveByToken(principal.id);
        return {{}, exception.what()};
    }
}

CollaborationResult<std::vector<project::CollaborationFileRecord>>
CollaborationChildManager::ListFiles(const security::TokenRecord& principal,
    std::string_view projectReference)
{
    const auto project = projects_.Find(principal.id, projectReference);
    if (!project)
        return {{}, "project not found"};
    std::string error;
    const auto child = Ensure(principal, error);
    if (!child)
        return {{}, std::move(error)};
    try
    {
        ipc::Command command;
        command.mutable_list_collaboration_files()->set_project_id(project->internalId);
        const auto reply = child->Call(command);
        if (!reply.success() || !reply.has_collaboration_files())
            return {{}, reply.success() ? "collaboration child returned no file list" : reply.error()};
        std::vector<project::CollaborationFileRecord> result;
        for (const auto& file : reply.collaboration_files().files())
            result.push_back({principal.id, std::string(projectReference), file.id(),
                file.path(), file.name(), file.description(), file.size(), file.type()});
        projects_.AssignFiles(principal.id, projectReference, result);
        return {std::move(result), {}};
    }
    catch (const std::exception& exception)
    {
        RemoveByToken(principal.id);
        return {{}, exception.what()};
    }
}

CollaborationResult<CollaborationDownload> CollaborationChildManager::DownloadFile(
    const security::TokenRecord& principal, std::string_view projectReference,
    std::string_view path)
{
    auto files = ListFiles(principal, projectReference);
    if (!files.value)
        return {{}, files.error};
    const auto match = std::find_if(files.value->begin(), files.value->end(),
        [&](const auto& file) { return file.path == path; });
    if (match == files.value->end())
        return {{}, "collaboration file not found"};
    if (std::count_if(files.value->begin(), files.value->end(),
            [&](const auto& file) { return file.path == path; }) != 1)
        return {{}, "collaboration file path is ambiguous"};
    const auto project = projects_.Find(principal.id, projectReference);
    std::string error;
    const auto child = Ensure(principal, error);
    if (!child || !project)
        return {{}, child ? "project not found" : error};
    auto random = security::GenerateHex256();
    if (!random.value)
        return {{}, random.error};
    const auto directory = config_.storage.spoolPath / "collaboration-exports" / *random.value;
    const auto destination = directory / (match->name.empty() ? "remote-file" : match->name);
    const auto placeholder = platform::CreatePrivateFileIfAbsent(destination, {});
    if (!placeholder.created || !placeholder.error.empty())
        return {{}, placeholder.error};
    std::error_code ignored;
    std::filesystem::remove(destination, ignored);
    try
    {
        ipc::Command command;
        auto* download = command.mutable_download_collaboration_file();
        download->set_project_id(project->internalId);
        download->set_file_id(match->internalId);
        download->set_destination(destination.string());
        const auto reply = child->Call(command);
        if (!reply.success() || !reply.has_collaboration_file_downloaded())
        {
            std::filesystem::remove_all(directory, ignored);
            return {{}, reply.success() ? "collaboration child returned no download" : reply.error()};
        }
        return {CollaborationDownload{destination, directory, *match,
            reply.collaboration_file_downloaded().database_backed()}, {}};
    }
    catch (const std::exception& exception)
    {
        std::filesystem::remove_all(directory, ignored);
        RemoveByToken(principal.id);
        return {{}, exception.what()};
    }
}

CollaborationResult<CollaborationSave> CollaborationChildManager::SaveDatabase(
    const security::TokenRecord& principal, std::string_view projectReference,
    std::string_view path, const std::filesystem::path& database,
    bool createdDatabase, std::string message, std::string resolutionsJson)
{
    auto files = ListFiles(principal, projectReference);
    if (!files.value)
        return {{}, files.error};
    const auto match = std::find_if(files.value->begin(), files.value->end(),
        [&](const auto& file) { return file.path == path; });
    if (match == files.value->end())
        return {{}, "collaboration file not found"};
    if (std::count_if(files.value->begin(), files.value->end(),
            [&](const auto& file) { return file.path == path; }) != 1)
        return {{}, "collaboration file path is ambiguous"};
    const auto project = projects_.Find(principal.id, projectReference);
    std::string error;
    const auto child = Ensure(principal, error);
    if (!child || !project)
        return {{}, child ? "project not found" : error};
    try
    {
        ipc::Command command;
        auto* save = command.mutable_save_collaboration_database();
        save->set_project_id(project->internalId);
        save->set_file_id(match->internalId);
        save->set_database_path(database.string());
        save->set_created_database(createdDatabase);
        save->set_message(std::move(message));
        save->set_resolutions_json(std::move(resolutionsJson));
        const auto reply = child->Call(command);
        if (!reply.success() || !reply.has_collaboration_database_saved())
            return {{}, reply.success() ? "collaboration child returned no save result"
                                       : reply.error()};
        const auto& result = reply.collaboration_database_saved();
        return {CollaborationSave{result.synchronized(), result.path(),
            result.conflicts_json()}, {}};
    }
    catch (const std::exception& exception)
    {
        RemoveByToken(principal.id);
        return {{}, exception.what()};
    }
}

CollaborationResult<project::CollaborationFileRecord>
CollaborationChildManager::UploadFile(const security::TokenRecord& principal,
    std::string_view projectReference, const std::filesystem::path& source,
    std::string folder, std::string filename)
{
    const auto project = projects_.Find(principal.id, projectReference);
    if (!project)
        return {{}, "project not found"};
    std::string error;
    const auto child = Ensure(principal, error);
    if (!child)
        return {{}, error};
    try
    {
        ipc::Command command;
        auto* upload = command.mutable_upload_collaboration_file();
        upload->set_project_id(project->internalId);
        upload->set_source_path(source.string());
        upload->set_folder(std::move(folder));
        upload->set_filename(std::move(filename));
        const auto reply = child->Call(command);
        if (!reply.success() || !reply.has_collaboration_file())
            return {{}, reply.success() ? "collaboration child returned no uploaded file"
                                       : reply.error()};
        const auto& file = reply.collaboration_file();
        project::CollaborationFileRecord record{principal.id,
            std::string(projectReference), file.id(), file.path(), file.name(),
            file.description(), file.size(), file.type()};
        auto files = projects_.Files(principal.id, projectReference);
        files.push_back(record);
        projects_.AssignFiles(principal.id, projectReference, std::move(files));
        return {std::move(record), {}};
    }
    catch (const std::exception& exception)
    {
        RemoveByToken(principal.id);
        return {{}, exception.what()};
    }
}

void CollaborationChildManager::RemoveByToken(std::string_view ownerTokenId)
{
    std::shared_ptr<Child> child;
    {
        std::lock_guard lock(mutex_);
        const auto found = children_.find(std::string(ownerTokenId));
        if (found != children_.end())
        {
            child = std::move(found->second);
            children_.erase(found);
        }
    }
    if (child)
        child->Stop(supervisor_);
    projects_.RemoveByToken(ownerTokenId);
}

std::vector<std::string> CollaborationChildManager::Tokens() const
{
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    result.reserve(children_.size());
    for (const auto& [token, child] : children_)
        result.push_back(token);
    return result;
}
}
