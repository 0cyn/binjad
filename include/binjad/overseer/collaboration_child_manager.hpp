#pragma once

#include "binjad/config.hpp"
#include "binjad/ipc/envelope.hpp"
#include "binjad/process/supervisor.hpp"
#include "binjad/project/collaboration_project_registry.hpp"
#include "binjad/security/token_authenticator.hpp"

#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace binjad::overseer
{
struct CollaborationIdentity
{
    std::string username;
    std::string accessToken;
};

struct CollaborationDownload
{
    std::filesystem::path path;
    std::filesystem::path workingDirectory;
    project::CollaborationFileRecord file;
    bool databaseBacked = false;
};

struct CollaborationSave
{
    bool synchronized = false;
    std::string path;
    std::string conflictsJson;
};

template <typename T>
struct CollaborationResult
{
    std::optional<T> value;
    std::string error;
};

class CollaborationChildManager
{
  public:
    using IdentityResolver = std::function<CollaborationResult<CollaborationIdentity>(
        const security::TokenRecord&)>;

    CollaborationChildManager(Config config, std::filesystem::path executable,
        ProcessSupervisor& supervisor, ChildChannelAcceptor& acceptor,
        project::CollaborationProjectRegistry& projects,
        IdentityResolver identities, std::mutex* launchMutex = nullptr);
    ~CollaborationChildManager();

    CollaborationResult<std::vector<project::CollaborationProjectRecord>> ListProjects(
        const security::TokenRecord& principal);
    CollaborationResult<std::vector<project::CollaborationFileRecord>> ListFiles(
        const security::TokenRecord& principal, std::string_view project);
    CollaborationResult<CollaborationDownload> DownloadFile(
        const security::TokenRecord& principal, std::string_view project,
        std::string_view path);
    CollaborationResult<CollaborationSave> SaveDatabase(
        const security::TokenRecord& principal, std::string_view project,
        std::string_view path, const std::filesystem::path& database,
        bool createdDatabase, std::string message, std::string resolutionsJson);
    CollaborationResult<project::CollaborationFileRecord> UploadFile(
        const security::TokenRecord& principal, std::string_view project,
        const std::filesystem::path& source, std::string folder,
        std::string filename);
    void RemoveByToken(std::string_view ownerTokenId);
    std::vector<std::string> Tokens() const;

  private:
    class Child;
    std::shared_ptr<Child> Ensure(
        const security::TokenRecord& principal, std::string& error);
    std::shared_ptr<Child> Start(CollaborationIdentity identity, std::string& error);

    Config config_;
    std::filesystem::path executable_;
    ProcessSupervisor& supervisor_;
    ChildChannelAcceptor& acceptor_;
    project::CollaborationProjectRegistry& projects_;
    IdentityResolver identities_;
    std::mutex* launchMutex_;
    std::unordered_map<std::string, std::shared_ptr<Child>> children_;
    mutable std::mutex mutex_;
};
}
