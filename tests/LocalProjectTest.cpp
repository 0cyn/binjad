#include "binjad/ipc/Envelope.hpp"
#include "binjad/mcp/Foundation.hpp"
#include "binjad/overseer/FileChildCoordinator.hpp"
#include "binjad/overseer/ProjectChildCoordinator.hpp"
#include "binjad/project/LocalProjectRegistry.hpp"
#include "binjad/security/CredentialStore.hpp"
#include "binjad/session/JobRegistry.hpp"
#include "binjad/upload/UploadRegistry.hpp"

#include <rapidjsonwrapper.h>

#include <gtest/gtest.h>

#include <condition_variable>
#include <chrono>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <unistd.h>

namespace
{
class MemoryCredentialStore final : public binjad::security::CredentialStore
{
  public:
    binjad::security::CredentialReadResult Read(std::string_view key) override
    {
        const auto value = values.find(std::string(key));
        return value == values.end()
            ? binjad::security::CredentialReadResult{}
            : binjad::security::CredentialReadResult{value->second, {}};
    }

    std::string Write(std::string_view key, std::string_view value) override
    {
        values[std::string(key)] = std::string(value);
        return {};
    }

    std::string Remove(std::string_view key) override
    {
        values.erase(std::string(key));
        return {};
    }

    std::unordered_map<std::string, std::string> values;
};

class ScriptChannel final : public binjad::ipc::ByteChannel
{
  public:
    ScriptChannel(binjad::ProcessRole role, std::filesystem::path source)
        : role_(role), source_(std::move(source))
    {
    }

    void Send(std::span<const std::uint8_t> payload) override
    {
        const auto request = binjad::ipc::ParseEnvelope(payload);
        binjad::ipc::Envelope response;
        response.set_protocol_version(binjad::ipc::kProtocolVersion);
        response.set_request_id(request.request_id());
        auto* reply = response.mutable_reply();
        reply->set_success(true);
        const auto& command = request.command();
        if (role_ == binjad::ProcessRole::ProjectChild)
        {
            if (command.has_scan_local_projects())
            {
                auto* project = reply->mutable_local_project_catalog()->add_projects();
                if (command.scan_local_projects().projects_size() != 0)
                {
                    project->set_id("registered-project-id");
                    project->set_path(command.scan_local_projects().projects(0));
                    project->set_name("Registered");
                    project->set_description("Registered project");
                }
                else
                {
                    project->set_id("durable-project-id");
                    project->set_path("/private/catalog/Example.bnpr");
                    project->set_name("Example");
                    project->set_description("Integration project");
                }
            }
            else if (command.has_list_local_project_files())
            {
                auto* files = reply->mutable_local_project_files();
                if (!fileDeleted_)
                {
                    auto* file = files->add_files();
                    file->set_id("durable-file-id");
                    file->set_path(folderId_.empty() ? "folder/" + fileName_
                                                     : "Renamed/" + fileName_);
                    file->set_name(fileName_);
                    file->set_description(fileDescription_);
                    file->set_creation_timestamp(10);
                    file->set_folder_id(folderId_);
                    file->set_backing_path(source_.string());
                }
                for (const auto& [id, path] : importedFiles_)
                {
                    auto* file = files->add_files();
                    file->set_id(id);
                    file->set_path(path);
                    file->set_name(std::filesystem::path(path).filename().string());
                    file->set_description("Imported");
                    file->set_backing_path((source_.parent_path() / "project-data" / id).string());
                    if (path.starts_with("Renamed/")) file->set_folder_id("folder-id");
                }
            }
            else if (command.has_export_local_project_file())
            {
                std::filesystem::copy_file(source_,
                    command.export_local_project_file().destination(),
                    std::filesystem::copy_options::overwrite_existing);
                auto* exported = reply->mutable_local_project_file_exported();
                exported->set_id("durable-file-id");
                exported->set_path(command.export_local_project_file().path());
            }
            else if (command.has_commit_local_project_file())
            {
                auto* committed = reply->mutable_local_project_file_committed();
                const auto existing = std::find_if(importedFiles_.begin(), importedFiles_.end(),
                    [&](const auto& file) {
                        return file.second == command.commit_local_project_file().path();
                    });
                const auto id = existing == importedFiles_.end()
                    ? "saved-file-id-" + std::to_string(importedFiles_.size())
                    : existing->first;
                committed->set_id(id);
                committed->set_path(command.commit_local_project_file().path());
                if (existing == importedFiles_.end())
                    importedFiles_.emplace_back(id, command.commit_local_project_file().path());
            }
            else if (command.has_create_local_project())
            {
                auto* project = reply->mutable_local_project();
                project->set_id("created-project-id");
                project->set_path(command.create_local_project().path());
                project->set_name(command.create_local_project().name());
                project->set_description(command.create_local_project().description());
            }
            else if (command.has_update_local_project())
            {
                auto* project = reply->mutable_local_project();
                project->set_id("durable-project-id");
                project->set_path(command.update_local_project().project_path());
                project->set_name(command.update_local_project().has_name()
                    ? command.update_local_project().name() : "Example");
                project->set_description(command.update_local_project().has_description()
                    ? command.update_local_project().description() : "Integration project");
            }
            else if (command.has_list_local_project_folders())
            {
                auto* folders = reply->mutable_local_project_folders();
                if (folderExists_)
                {
                    auto* folder = folders->add_folders();
                    folder->set_id("folder-id");
                    folder->set_path("Renamed");
                    folder->set_name("Renamed");
                    folder->set_description("Folder");
                }
            }
            else if (command.has_create_local_project_folder() ||
                command.has_update_local_project_folder())
            {
                folderExists_ = true;
                auto* folder = reply->mutable_local_project_folder();
                folder->set_id("folder-id");
                folder->set_path("Renamed");
                folder->set_name("Renamed");
                folder->set_description("Folder");
            }
            else if (command.has_delete_local_project_folder())
            {
                folderExists_ = false;
            }
            else if (command.has_update_local_project_file())
            {
                if (command.update_local_project_file().has_name())
                    fileName_ = command.update_local_project_file().name();
                if (command.update_local_project_file().has_description())
                    fileDescription_ = command.update_local_project_file().description();
                if (command.update_local_project_file().has_folder_id())
                    folderId_ = command.update_local_project_file().folder_id();
                auto* file = reply->mutable_local_project_file();
                file->set_id("durable-file-id");
                file->set_name(fileName_);
                file->set_description(fileDescription_);
            }
            else if (command.has_delete_local_project_file())
            {
                fileDeleted_ = true;
            }
            else if (command.has_delete_local_project())
            {}
            else if (!command.has_shutdown())
            {
                reply->set_success(false);
                reply->set_error("unexpected project command");
            }
        }
        else
        {
            if (command.has_open_file())
            {
                auto* opened = reply->mutable_file_opened();
                auto* raw = opened->add_candidates();
                raw->set_view_type("Raw");
                auto* executable = opened->add_candidates();
                executable->set_view_type("Mach-O");
                executable->set_recommended(true);
            }
            else if (command.has_open_binary_view())
            {
                reply->mutable_binary_view_opened()->set_view_type(
                    command.open_binary_view().view_type());
            }
            else if (command.has_get_analysis_status())
            {
                reply->mutable_analysis_status()->set_has_view(true);
                reply->mutable_analysis_status()->set_state(
                    binjad::ipc::ANALYSIS_STATE_IDLE);
            }
            else if (command.has_save_binary_view())
            {
                if (!databaseCreated_)
                    std::filesystem::copy_file(source_, command.save_binary_view().destination(),
                        std::filesystem::copy_options::overwrite_existing);
                auto* saved = reply->mutable_binary_view_saved();
                saved->set_path(command.save_binary_view().destination());
                saved->set_created_database(!databaseCreated_);
                databaseCreated_ = true;
            }
            else if (!command.has_close_file() && !command.has_shutdown())
            {
                reply->set_success(false);
                reply->set_error("unexpected file command");
            }
        }
        {
            std::lock_guard lock(mutex_);
            responses_.push_back(binjad::ipc::SerializeEnvelope(response));
        }
        ready_.notify_one();
    }

    std::vector<std::uint8_t> Receive() override
    {
        std::unique_lock lock(mutex_);
        ready_.wait(lock, [&] { return closed_ || !responses_.empty(); });
        if (responses_.empty())
            throw binjad::ipc::ChannelError("script channel closed");
        auto response = std::move(responses_.front());
        responses_.pop_front();
        return response;
    }

    void Close() override
    {
        {
            std::lock_guard lock(mutex_);
            closed_ = true;
        }
        ready_.notify_all();
    }

  private:
    binjad::ProcessRole role_;
    std::filesystem::path source_;
    std::deque<std::vector<std::uint8_t>> responses_;
    std::mutex mutex_;
    std::condition_variable ready_;
    bool closed_ = false;
    bool databaseCreated_ = false;
    bool folderExists_ = false;
    bool fileDeleted_ = false;
    std::string folderId_;
    std::string fileName_ = "true";
    std::string fileDescription_ = "Fixture";
    std::vector<std::pair<std::string, std::string>> importedFiles_;
};

class FakeSupervisor final : public binjad::ProcessSupervisor
{
  public:
    binjad::ProcessId Spawn(const std::filesystem::path&, binjad::ProcessRole role) override
    {
        roles.push_back(role);
        return ++next;
    }
    void Terminate(binjad::ProcessId) override {}
    void SetExitCallback(ExitCallback callback) override { exitCallback = std::move(callback); }

    binjad::ProcessId next = 10;
    std::vector<binjad::ProcessRole> roles;
    ExitCallback exitCallback;
};

class FakeAcceptor final : public binjad::ChildChannelAcceptor
{
  public:
    explicit FakeAcceptor(std::filesystem::path source) : source_(std::move(source)) {}
    std::unique_ptr<binjad::ipc::ByteChannel> Accept(
        binjad::ProcessId, binjad::ProcessRole role) override
    {
        return std::make_unique<ScriptChannel>(role, source_);
    }

  private:
    std::filesystem::path source_;
};

binjad::mcp::ValidatedRequest Tool(std::string name, std::string arguments)
{
    binjad::mcp::ValidatedRequest request;
    request.version = binjad::mcp::ProtocolVersion::V2026_07_28;
    request.id = std::uint64_t{1};
    request.method = "tools/call";
    request.name = std::move(name);
    request.paramsJson = "{\"arguments\":" + std::move(arguments) + '}';
    return request;
}

rapidjson::Document Parse(const std::string& value)
{
    rapidjson::Document document;
    document.Parse(value.data(), value.size());
    return document;
}
}

TEST(LocalProjectRegistryTest, PreservesFriendlyReferenceAcrossCatalogRefresh)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::project::LocalProjectRegistry projects(references);
    ASSERT_TRUE(projects.Replace({{{}, "id", "/secret/One.bnpr", "One", "first"}}).empty());
    const auto first = projects.List();
    ASSERT_EQ(first.size(), 1U);
    ASSERT_TRUE(projects.Replace({{{}, "id", "/secret/Two.bnpr", "Two", "second"}}).empty());
    const auto second = projects.List();
    ASSERT_EQ(second.size(), 1U);
    EXPECT_EQ(second.front().reference, first.front().reference);
    EXPECT_EQ(second.front().name, "Two");
}

TEST(LocalProjectRegistryTest, UsesUniquePathsWithoutFileOrFolderReferences)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::project::LocalProjectRegistry projects(references);
    ASSERT_TRUE(projects.Replace({{{}, "project-id", "/secret/One.bnpr", "One", {}}}).empty());
    const auto project = projects.List().front().reference;
    std::vector<binjad::project::LocalProjectFolderRecord> folders{
        {"folder-id", {}, "reports", "reports", {}, {}, {}}};
    EXPECT_TRUE(projects.AssignFolders(project, folders).empty());
    std::vector<binjad::project::LocalProjectFileRecord> files{
        {"file-id", "reports/a.json", "a.json", {}, 1, {}, "folder-id", {}, {}}};
    EXPECT_TRUE(projects.AssignFiles(project, files).empty());
    ASSERT_TRUE(projects.FindFile(project, "reports/a.json"));
    EXPECT_EQ(references.Size(), 1U);

    std::vector<binjad::project::LocalProjectFileRecord> duplicateFiles{
        {"first", "same.md", "same.md", {}, 1, {}, {}, {}, {}},
        {"second", "same.md", "same.md", {}, 2, {}, {}, {}, {}}};
    EXPECT_NE(projects.AssignFiles(project, duplicateFiles).find("duplicate"),
        std::string::npos);
    std::vector<binjad::project::LocalProjectFolderRecord> duplicateFolders{
        {"first", {}, "same", "same", {}, {}, {}},
        {"second", {}, "same", "same", {}, {}, {}}};
    EXPECT_NE(projects.AssignFolders(project, duplicateFolders).find("duplicate"),
        std::string::npos);
}

TEST(KnownProjectStoreTest, PersistsExactNormalizedProjectPaths)
{
    const auto temporary = std::filesystem::temp_directory_path() /
        ("binjad-known-projects-" + std::to_string(getpid()));
    std::error_code ignored;
    std::filesystem::remove_all(temporary, ignored);
    struct Cleanup
    {
        std::filesystem::path path;
        ~Cleanup()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } cleanup{temporary};
    MemoryCredentialStore credentials;
    const auto registryPath = temporary / "projects.json";
    {
        binjad::project::KnownProjectStore projects(credentials, registryPath);
        ASSERT_TRUE(projects.Load().empty());
        EXPECT_FALSE(projects.Add("relative/Test.bnpr").empty());
        EXPECT_TRUE(projects.Add("/private/One.bnpr").empty());
        EXPECT_TRUE(projects.Add("/private/Two.bnpm").empty());
        EXPECT_TRUE(projects.Add("/private/One.bnpr").empty());
        EXPECT_EQ(projects.Paths().size(), 2U);
    }
    {
        binjad::project::KnownProjectStore projects(credentials, registryPath);
        ASSERT_TRUE(projects.Load().empty());
        ASSERT_EQ(projects.Paths().size(), 2U);
        EXPECT_TRUE(projects.Remove("/private/One.bnpr").empty());
        ASSERT_EQ(projects.Paths().size(), 1U);
        EXPECT_EQ(projects.Paths().front(), "/private/Two.bnpm");
    }
}

TEST(LocalProjectTest, ListsAndOpensProjectFileThroughSeparateChildren)
{
    const auto temporary = std::filesystem::temp_directory_path() /
        ("binjad-local-project-" + std::to_string(getpid()));
    std::error_code ignored;
    std::filesystem::remove_all(temporary, ignored);
    std::filesystem::create_directories(temporary);
    struct Cleanup
    {
        std::filesystem::path path;
        ~Cleanup()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path, ignored);
        }
    } cleanup{temporary};
    const auto source = temporary / "source";
    {
        std::ofstream stream(source, std::ios::binary);
        stream << "fixture";
    }

    binjad::Config config;
    config.projects.roots = {temporary / "projects"};
    config.projects.defaultRoot = temporary / "projects";
    config.projects.allowProjectRegistration = true;
    config.storage.spoolPath = temporary / "spool";
    FakeSupervisor supervisor;
    FakeAcceptor acceptor(source);
    binjad::reference::FriendlyReferencePool references;
    binjad::session::OpenItemRegistry openItems(references);
    binjad::project::LocalProjectRegistry projects(references);
    MemoryCredentialStore credentials;
    binjad::project::KnownProjectStore knownProjects(credentials, temporary / "projects.json");
    ASSERT_TRUE(knownProjects.Load().empty());
    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    binjad::session::JobRegistry jobs(references, sessions);
    binjad::upload::UploadRegistry uploads(config, references, sessions, projects);
    binjad::overseer::ProjectChildCoordinator projectCoordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, projects, nullptr,
        &knownProjects);
    binjad::overseer::FileChildCoordinator fileCoordinator(
        config, "/usr/local/bin/binjad", supervisor, acceptor, openItems);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0", &openItems,
        &fileCoordinator, &jobs, &projects, &projectCoordinator, nullptr, &uploads);
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::Admin, "test", 1, {}};
    const auto current = sessions.Create(principal.id, 1, {});
    ASSERT_TRUE(current.session);

    const auto listed = foundation.Handle(Tool("bn_local_project_list", "{}"),
        principal, current.session, {}, 1);
    EXPECT_EQ(listed.body.find("/private/catalog"), std::string::npos);
    auto listedJson = Parse(listed.body);
    const std::string project =
        listedJson["result"]["structuredContent"]["projects"][0]["project"].GetString();
    const auto files = foundation.Handle(Tool("bn_local_project_file_list",
        "{\"project\":\"" + project + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(files.body.find("folder/true"), std::string::npos) << files.body;
    EXPECT_EQ(files.body.find(R"("file":)"), std::string::npos);
    EXPECT_EQ(files.body.find(source.string()), std::string::npos);
    const std::string filePath = "folder/true";

    {
        std::ofstream stream(source, std::ios::binary | std::ios::trunc);
        stream << "# Report\nalpha result\n## Findings\nAlpha follow-up\nomega\n";
    }
    const auto textPage = foundation.Handle(Tool("bn_project_text_read",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\","
            "\"query\":\"alpha\",\"limit\":1}"),
        principal, current.session, {}, 1);
    EXPECT_NE(textPage.body.find(R"("line":2)"), std::string::npos) << textPage.body;
    EXPECT_NE(textPage.body.find(R"("total":2)"), std::string::npos) << textPage.body;
    EXPECT_NE(textPage.body.find(R"("nextOffset":1)"), std::string::npos) << textPage.body;
    const auto nextTextPage = foundation.Handle(Tool("bn_project_text_read",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\","
            "\"query\":\"alpha\",\"offset\":1,\"limit\":1}"),
        principal, current.session, {}, 1);
    EXPECT_NE(nextTextPage.body.find(R"("line":4)"), std::string::npos)
        << nextTextPage.body;

    {
        std::ofstream stream(source, std::ios::binary | std::ios::trunc);
        stream << R"({"meta":{"name":"fixture","tags":["one","two"]},"items":[{"id":1},{"id":2},{"id":3}],"large":{"nested":true}})";
    }
    const auto jsonRoot = foundation.Handle(Tool("bn_project_json_read",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\",\"limit\":2}"),
        principal, current.session, {}, 1);
    EXPECT_NE(jsonRoot.body.find(R"("key":"meta")"), std::string::npos) << jsonRoot.body;
    EXPECT_NE(jsonRoot.body.find(R"("key":"items")"), std::string::npos) << jsonRoot.body;
    EXPECT_NE(jsonRoot.body.find(R"("nextOffset":2)"), std::string::npos) << jsonRoot.body;
    const auto jsonArray = foundation.Handle(Tool("bn_project_json_read",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\","
            "\"pointer\":\"/items\",\"offset\":1,\"limit\":1}"),
        principal, current.session, {}, 1);
    EXPECT_NE(jsonArray.body.find(R"("index":1)"), std::string::npos) << jsonArray.body;
    EXPECT_NE(jsonArray.body.find(R"("pointer":"/items/1")"), std::string::npos)
        << jsonArray.body;
    EXPECT_NE(jsonArray.body.find(R"("type":"object")"), std::string::npos) << jsonArray.body;
    const auto jsonScalar = foundation.Handle(Tool("bn_project_json_read",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\","
            "\"pointer\":\"/meta/name\"}"), principal, current.session, {}, 1);
    EXPECT_NE(jsonScalar.body.find(R"("value":"fixture")"), std::string::npos)
        << jsonScalar.body;
    {
        std::ofstream stream(source, std::ios::binary | std::ios::trunc);
        stream << "fixture";
    }

    const binjad::security::TokenRecord userPrincipal{
        std::string(64, 'c'), std::string(64, 'd'),
        binjad::security::TokenRole::User, "test", 1, {}};
    const auto deniedRegistration = foundation.Handle(Tool("bn_local_project_register",
        R"({"path":"/private/Registered.bnpr"})"), userPrincipal, {}, {}, 1);
    EXPECT_NE(deniedRegistration.body.find("administrator token required"), std::string::npos);
    const auto registeredPath = temporary / "Registered.bnpr";
    std::filesystem::create_directories(registeredPath);
    {
        std::ofstream stream(registeredPath / "project-data", std::ios::binary);
        stream << "registered fixture";
    }
    const auto registeredProject = foundation.Handle(Tool("bn_local_project_register",
        "{\"path\":\"" + registeredPath.string() + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(registeredProject.body.find("Registered"), std::string::npos)
        << registeredProject.body;
    const auto registeredPaths = knownProjects.Paths();
    EXPECT_NE(std::find(registeredPaths.begin(), registeredPaths.end(),
        registeredPath), registeredPaths.end());
    auto registeredProjectJson = Parse(registeredProject.body);
    const std::string registeredReference =
        registeredProjectJson["result"]["structuredContent"]["project"].GetString();

    const auto roots = foundation.Handle(Tool("bn_local_project_root_list", "{}"),
        principal, current.session, {}, 1);
    EXPECT_NE(roots.body.find(R"("index":0)"), std::string::npos) << roots.body;
    EXPECT_NE(roots.body.find(R"("default":true)"), std::string::npos) << roots.body;
    EXPECT_EQ(roots.body.find((temporary / "projects").string()), std::string::npos) << roots.body;

    const auto relocated = foundation.Handle(Tool("bn_local_project_relocate",
        "{\"project\":\"" + registeredReference + "\",\"root\":0,\"path\":\"Adopted.bnpr\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(relocated.body.find(R"("sourceRetained":true)"), std::string::npos) << relocated.body;
    EXPECT_TRUE(std::filesystem::is_directory(registeredPath));
    EXPECT_TRUE(std::filesystem::is_directory(temporary / "projects" / "Adopted.bnpr"));
    const auto pathsAfterRelocation = knownProjects.Paths();
    EXPECT_EQ(std::find(pathsAfterRelocation.begin(), pathsAfterRelocation.end(), registeredPath),
        pathsAfterRelocation.end());
    const auto relocatedRecord = projects.Find(registeredReference);
    ASSERT_TRUE(relocatedRecord);
    EXPECT_EQ(relocatedRecord->storagePath, temporary / "projects" / "Adopted.bnpr");

    const auto createdFolder = foundation.Handle(Tool("bn_local_project_folder_create",
        "{\"project\":\"" + project + "\",\"name\":\"Folder\"}"),
        principal, current.session, {}, 1);
    auto folderJson = Parse(createdFolder.body);
    const std::string folder =
        folderJson["result"]["structuredContent"]["path"].GetString();

    const auto deniedImport = foundation.Handle(Tool("bn_local_project_file_import",
        "{\"project\":\"" + project + "\",\"source\":\"" + source.string() + "\"}"),
        userPrincipal, {}, {}, 1);
    EXPECT_NE(deniedImport.body.find("administrator token required"), std::string::npos);
    const auto imported = foundation.Handle(Tool("bn_local_project_file_import",
        "{\"project\":\"" + project + "\",\"folder\":\"" + folder +
            "\",\"source\":\"" + source.string() + "\",\"name\":\"import-one\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(imported.body.find("Renamed/import-one"), std::string::npos) << imported.body;
    const auto importedBatch = foundation.Handle(Tool("bn_local_project_file_import_batch",
        "{\"project\":\"" + project + "\",\"folder\":\"" + folder +
            "\",\"files\":[{\"source\":\"" + source.string() +
            "\",\"name\":\"batch-one\"},{\"source\":\"" + source.string() +
            "\",\"name\":\"batch-two\"}]}"), principal, current.session, {}, 1);
    EXPECT_NE(importedBatch.body.find(R"("imported":2)"), std::string::npos)
        << importedBatch.body;
    const auto directorySource = temporary / "directory-import";
    std::filesystem::create_directories(directorySource / "nested");
    {
        std::ofstream stream(directorySource / ".hidden", std::ios::binary);
        stream << "hidden";
    }
    {
        std::ofstream stream(directorySource / "nested" / "item.bin", std::ios::binary);
        stream << "nested";
    }
    std::filesystem::create_symlink(directorySource / ".hidden", directorySource / "ignored-link", ignored);
    const auto importedDirectory = foundation.Handle(Tool("bn_local_project_directory_import",
        "{\"project\":\"" + project + "\",\"source\":\"" + directorySource.string()
            + "\",\"folder\":\"Tree\"}"), principal, current.session, {}, 1);
    EXPECT_NE(importedDirectory.body.find(R"("imported":2)"), std::string::npos) << importedDirectory.body;
    EXPECT_NE(importedDirectory.body.find(R"("skippedSymlinks":1)"), std::string::npos) << importedDirectory.body;
    const auto resumedDirectory = foundation.Handle(Tool("bn_local_project_directory_import",
        "{\"project\":\"" + project + "\",\"source\":\"" + directorySource.string()
            + "\",\"folder\":\"TreeResume\",\"startAfter\":\".hidden\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(resumedDirectory.body.find(R"("imported":1)"), std::string::npos) << resumedDirectory.body;
    EXPECT_NE(resumedDirectory.body.find(R"("lastCompleted":"nested/item.bin")"), std::string::npos)
        << resumedDirectory.body;
    const auto filtered = foundation.Handle(Tool("bn_local_project_file_list",
        "{\"project\":\"" + project + "\",\"folder\":\"" + folder +
            "\",\"query\":\"batch-two\"}"), principal, current.session, {}, 1);
    EXPECT_NE(filtered.body.find(R"("total":1)"), std::string::npos) << filtered.body;

    const auto uploadUrl = foundation.Handle(Tool("bn_upload_get_url",
        "{\"project\":\"" + project + "\",\"filename\":\"uploaded.bin\"}"),
        principal, current.session, {}, 1);
    auto uploadJson = Parse(uploadUrl.body);
    const auto& uploadContent = uploadJson["result"]["structuredContent"];
    const std::string uploadId = uploadContent["id"].GetString();
    const std::string uploadUrlValue = uploadContent["url"].GetString();
    const auto capability = uploadUrlValue.substr(uploadUrlValue.find_last_of('/') + 1);
    auto transfer = uploads.Begin(capability, principal.id, {}).first;
    ASSERT_TRUE(transfer);
    std::string transferError;
    ASSERT_TRUE(transfer->Write("uploaded", transferError)) << transferError;
    ASSERT_TRUE(transfer->Finish(transferError)) << transferError;
    const auto committedUpload = foundation.Handle(Tool("bn_upload_commit",
        "{\"id\":\"" + uploadId +
            "\",\"folder\":\"" + folder + "\",\"open\":true}"),
        principal, current.session, {}, 1);
    EXPECT_NE(committedUpload.body.find("Renamed/uploaded.bin"), std::string::npos)
        << committedUpload.body;
    EXPECT_EQ(uploads.Size(), 1U);
    const auto repeatedCommit = foundation.Handle(Tool("bn_upload_commit",
        "{\"id\":\"" + uploadId + "\",\"open\":true}"),
        principal, current.session, {}, 1);
    EXPECT_NE(repeatedCommit.body.find("Renamed/uploaded.bin"), std::string::npos)
        << repeatedCommit.body;
    auto committedUploadJson = Parse(committedUpload.body);
    const std::string uploadedOpenItem = committedUploadJson["result"]
        ["structuredContent"]["openItem"]["openItem"].GetString();
    EXPECT_FALSE(fileCoordinator.Close(principal.id, uploadedOpenItem, true).size());
    const auto listedUploads = foundation.Handle(Tool("bn_upload_list", "{}"),
        principal, current.session, {}, 1);
    EXPECT_NE(listedUploads.body.find(R"("state":"committed")"), std::string::npos);
    const auto cancelledUpload = foundation.Handle(Tool("bn_upload_cancel",
        "{\"id\":\"" + uploadId + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(cancelledUpload.body.find(R"("cancelled":true)"), std::string::npos);
    EXPECT_EQ(uploads.Size(), 0U);

    const auto opened = foundation.Handle(Tool("bn_project_file_open",
        "{\"project\":\"" + project + "\",\"path\":\"folder/true\"}"),
        principal, current.session, {}, 1);
    auto openedJson = Parse(opened.body);
    const auto& content = openedJson["result"]["structuredContent"];
    EXPECT_STREQ(content["sourceKind"].GetString(), "local_project");
    EXPECT_STREQ(content["source"].GetString(), "folder/true");
    EXPECT_EQ(std::string(content["project"].GetString()), project);
    const std::string openItem = content["openItem"].GetString();
    std::string binaryView;
    for (const auto& candidate : content["binaryViews"].GetArray())
    {
        if (candidate["recommended"].GetBool())
            binaryView = candidate["binaryView"].GetString();
    }
    ASSERT_FALSE(binaryView.empty());
    const auto materialized = foundation.Handle(Tool("bn_binary_view_open",
        "{\"binaryView\":\"" + binaryView + "\",\"analyze\":false}"),
        principal, current.session, {}, 1);
    EXPECT_NE(materialized.body.find(R"("created":true)"), std::string::npos);
    const auto unsavedProjectUrl = foundation.Handle(Tool("bn_url_project_file",
        "{\"openItem\":\"" + openItem
            + R"(","updated_bndb_has_been_saved":true})"),
        principal, current.session, {}, 1);
    EXPECT_NE(unsavedProjectUrl.body.find("does not target a saved BNDB"), std::string::npos)
        << unsavedProjectUrl.body;
    const auto saved = foundation.Handle(Tool("bn_binary_view_save",
        "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(saved.body.find(R"("createdDatabase":true)"), std::string::npos);
    const auto updated = openItems.FindOpenItem(principal.id, openItem);
    ASSERT_TRUE(updated);
    EXPECT_EQ(updated->source, "folder/true.bndb");
    const auto missingSaveAcknowledgement = foundation.Handle(Tool("bn_url_project_file",
        "{\"openItem\":\"" + openItem + "\"}"), principal, current.session, {}, 1);
    ASSERT_TRUE(missingSaveAcknowledgement.error.has_value());
    EXPECT_EQ(missingSaveAcknowledgement.error->code, -32602);
    const auto falseSaveAcknowledgement = foundation.Handle(Tool("bn_url_project_file",
        "{\"openItem\":\"" + openItem
            + R"(","updated_bndb_has_been_saved":false})"),
        principal, current.session, {}, 1);
    ASSERT_TRUE(falseSaveAcknowledgement.error.has_value());
    EXPECT_EQ(falseSaveAcknowledgement.error->code, -32602);
    const auto projectUrl = foundation.Handle(Tool("bn_url_project_file",
        "{\"openItem\":\"" + openItem
            + R"(","updated_bndb_has_been_saved":true,"expr":"main + 4"})"),
        principal, current.session, {}, 1);
    EXPECT_NE(projectUrl.body.find("binaryninja:///"), std::string::npos) << projectUrl.body;
    EXPECT_NE(projectUrl.body.find("project-data/saved-file-id-"), std::string::npos) << projectUrl.body;
    EXPECT_NE(projectUrl.body.find("?expr=main%20%2B%204"), std::string::npos) << projectUrl.body;
    EXPECT_NE(projectUrl.body.find(R"("sourceKind":"local_project")"), std::string::npos);
    EXPECT_NE(projectUrl.body.find(R"("path":"folder/true.bndb")"), std::string::npos);
    const auto detached = foundation.Handle(Tool("bn_binary_view_save_async",
        "{\"binaryView\":\"" + binaryView + "\"}"),
        principal, current.session, {}, 1);
    auto detachedJson = Parse(detached.body);
    const std::string job =
        detachedJson["result"]["structuredContent"]["job"].GetString();
    for (int attempt = 0; attempt < 100; ++attempt)
    {
        const auto info = jobs.Info(principal.id, job);
        ASSERT_TRUE(info.job);
        if (info.job->state == binjad::session::JobState::Complete)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const auto asyncResult = foundation.Handle(Tool("bn_job_result",
        "{\"job\":\"" + job + "\"}"), principal, current.session, {}, 1);
    EXPECT_NE(asyncResult.body.find(R"("createdDatabase":false)"), std::string::npos);
    EXPECT_TRUE(foundation.Handle(Tool("bn_open_item_close",
        "{\"openItem\":\"" + openItem + "\",\"save\":\"discard\"}"),
        principal, current.session, {}, 1).error == std::nullopt);

    const auto arbitraryProjectPath = (temporary / "arbitrary" / "Created.bnpr").string();
    const auto deniedProject = foundation.Handle(Tool("bn_local_project_create",
        "{\"name\":\"Denied\",\"path\":\"" + arbitraryProjectPath + "\"}"),
        userPrincipal, {}, {}, 1);
    EXPECT_NE(deniedProject.body.find("administrator token required"), std::string::npos);
    const auto createdProject = foundation.Handle(Tool("bn_local_project_create",
        "{\"name\":\"Created\",\"path\":\"" + arbitraryProjectPath + "\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(createdProject.body.find("Created"), std::string::npos);
    auto createdProjectJson = Parse(createdProject.body);
    const std::string createdProjectReference = createdProjectJson["result"]
        ["structuredContent"]["project"].GetString();
    const auto updatedProject = foundation.Handle(Tool("bn_local_project_update",
        "{\"project\":\"" + project + "\",\"description\":\"Updated\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(updatedProject.body.find("Updated"), std::string::npos);
    const auto updatedFolder = foundation.Handle(Tool("bn_local_project_folder_update",
        "{\"project\":\"" + project + "\",\"path\":\"" + folder +
            "\",\"name\":\"Renamed\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(updatedFolder.body.find("Renamed"), std::string::npos);
    const auto updatedFile = foundation.Handle(Tool("bn_local_project_file_update",
        "{\"project\":\"" + project + "\",\"path\":\"" + filePath +
            "\",\"name\":\"renamed\","
            "\"description\":\"Firmware entry test\",\"folder\":\"" +
            "Renamed\"}"), principal, current.session, {}, 1);
    EXPECT_NE(updatedFile.body.find("renamed"), std::string::npos) << updatedFile.body;
    EXPECT_NE(updatedFile.body.find("Firmware entry test"), std::string::npos)
        << updatedFile.body;
    auto updatedFileJson = Parse(updatedFile.body);
    const std::string updatedPath = updatedFileJson["result"]
        ["structuredContent"]["path"].GetString();
    const auto clearedDescription = foundation.Handle(Tool("bn_local_project_file_update",
        "{\"project\":\"" + project + "\",\"path\":\"" + updatedPath +
            "\",\"description\":\"\"}"),
        principal, current.session, {}, 1);
    EXPECT_NE(clearedDescription.body.find(R"("description":"")"), std::string::npos);
    const auto unconfirmedDelete = foundation.Handle(Tool("bn_local_project_file_delete",
        "{\"project\":\"" + project + "\",\"path\":\"" + updatedPath +
            "\",\"delete\":false}"),
        principal, current.session, {}, 1);
    EXPECT_TRUE(unconfirmedDelete.error.has_value());
    const auto deletedFile = foundation.Handle(Tool("bn_local_project_file_delete",
        "{\"project\":\"" + project + "\",\"path\":\"" + updatedPath +
            "\",\"delete\":true}"),
        principal, current.session, {}, 1);
    EXPECT_NE(deletedFile.body.find(R"("deleted":true)"), std::string::npos);
    const auto deletedFolder = foundation.Handle(Tool("bn_local_project_folder_delete",
        "{\"project\":\"" + project +
            "\",\"path\":\"Renamed\",\"recursive\":true}"),
        principal, current.session, {}, 1);
    EXPECT_NE(deletedFolder.body.find(R"("deleted":true)"), std::string::npos);
    EXPECT_TRUE(projectCoordinator.DeleteProject(createdProjectReference).empty());
    EXPECT_FALSE(projects.Find(createdProjectReference));
    ASSERT_EQ(supervisor.roles.size(), 3U);
    EXPECT_EQ(supervisor.roles[0], binjad::ProcessRole::ProjectChild);
    EXPECT_EQ(supervisor.roles[1], binjad::ProcessRole::FileChild);
    EXPECT_EQ(supervisor.roles[2], binjad::ProcessRole::FileChild);
}
