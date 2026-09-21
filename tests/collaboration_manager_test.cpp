#include "binjad/ipc/envelope.hpp"
#include "binjad/mcp/foundation.hpp"
#include "binjad/overseer/collaboration_child_manager.hpp"

#include <gtest/gtest.h>

#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <unistd.h>

namespace
{
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

class ScriptChannel final : public binjad::ipc::ByteChannel
{
  public:
    void Send(std::span<const std::uint8_t> payload) override
    {
        const auto request = binjad::ipc::ParseEnvelope(payload);
        binjad::ipc::Envelope response;
        response.set_protocol_version(binjad::ipc::kProtocolVersion);
        response.set_request_id(request.request_id());
        auto* reply = response.mutable_reply();
        reply->set_success(true);
        const auto& command = request.command();
        if (command.has_configure_collaboration())
        {
            username = command.configure_collaboration().username();
            token = command.configure_collaboration().access_token();
        }
        else if (command.has_list_collaboration_projects())
        {
            auto* project = reply->mutable_collaboration_project_catalog()->add_projects();
            project->set_id("remote-project");
            project->set_name("Remote");
            project->set_description("Project");
        }
        else if (command.has_list_collaboration_files())
        {
            auto* file = reply->mutable_collaboration_files()->add_files();
            file->set_id("remote-file");
            file->set_path("folder/sample.bin");
            file->set_name("sample.bin");
            file->set_size(7);
            file->set_type(0);
        }
        else if (command.has_download_collaboration_file())
        {
            std::ofstream stream(command.download_collaboration_file().destination(),
                std::ios::binary);
            stream << "fixture";
            auto* downloaded = reply->mutable_collaboration_file_downloaded();
            downloaded->set_id("remote-file");
            downloaded->set_path(command.download_collaboration_file().destination());
            downloaded->set_database_backed(false);
        }
        else if (command.has_save_collaboration_database())
        {
            message = command.save_collaboration_database().message();
            resolutions = command.save_collaboration_database().resolutions_json();
            auto* saved = reply->mutable_collaboration_database_saved();
            saved->set_synchronized(true);
            saved->set_path("folder/sample.bin");
        }
        else if (command.has_upload_collaboration_file())
        {
            auto* file = reply->mutable_collaboration_file();
            file->set_id("uploaded-file");
            file->set_path(command.upload_collaboration_file().folder() + "/" +
                command.upload_collaboration_file().filename());
            file->set_name(command.upload_collaboration_file().filename());
            file->set_type(0);
        }
        responses.push_back(binjad::ipc::SerializeEnvelope(response));
    }

    std::vector<std::uint8_t> Receive() override
    {
        if (responses.empty())
            throw binjad::ipc::ChannelError("no scripted response");
        auto response = std::move(responses.front());
        responses.pop_front();
        return response;
    }

    std::string username;
    std::string token;
    std::string message;
    std::string resolutions;
    std::deque<std::vector<std::uint8_t>> responses;
};

class Supervisor final : public binjad::ProcessSupervisor
{
  public:
    binjad::ProcessId Spawn(const std::filesystem::path&, binjad::ProcessRole role) override
    {
        EXPECT_EQ(role, binjad::ProcessRole::ProjectChild);
        return ++spawns;
    }
    void Terminate(binjad::ProcessId) override {}
    void SetExitCallback(ExitCallback) override {}
    std::size_t spawns = 0;
};

class Acceptor final : public binjad::ChildChannelAcceptor
{
  public:
    std::unique_ptr<binjad::ipc::ByteChannel> Accept(
        binjad::ProcessId, binjad::ProcessRole) override
    {
        auto channel = std::make_unique<ScriptChannel>();
        latest = channel.get();
        return channel;
    }
    ScriptChannel* latest = nullptr;
};
}

TEST(CollaborationManagerTest, IsolatesCatalogAndRestartsForBindingChange)
{
    const auto temporary = std::filesystem::temp_directory_path() /
        ("binjad-collaboration-" + std::to_string(getpid()));
    std::error_code ignored;
    std::filesystem::remove_all(temporary, ignored);
    struct Cleanup { std::filesystem::path path; ~Cleanup() {
        std::error_code ignored; std::filesystem::remove_all(path, ignored); } } cleanup{temporary};
    binjad::Config config;
    config.mode = binjad::Mode::Collaboration;
    config.collaboration.remote = binjad::CollaborationRemoteConfig{"remote", "https://example.invalid"};
    config.storage.spoolPath = temporary / "spool";
    binjad::reference::FriendlyReferencePool references;
    binjad::project::CollaborationProjectRegistry projects(references);
    Supervisor supervisor;
    Acceptor acceptor;
    std::string accessToken = "first";
    binjad::overseer::CollaborationChildManager manager(config, "/usr/local/bin/binjad",
        supervisor, acceptor, projects,
        [&](const auto&) -> binjad::overseer::CollaborationResult<binjad::overseer::CollaborationIdentity> {
            return {binjad::overseer::CollaborationIdentity{"analyst", accessToken}, {}};
        });
    const binjad::security::TokenRecord principal{
        std::string(64, 'a'), std::string(64, 'b'),
        binjad::security::TokenRole::User, {}, 1, {}};
    const auto listed = manager.ListProjects(principal);
    ASSERT_TRUE(listed.value) << listed.error;
    ASSERT_EQ(listed.value->size(), 1U);
    const auto project = listed.value->front().reference;
    EXPECT_FALSE(projects.Find(std::string(64, 'c'), project));
    const auto files = manager.ListFiles(principal, project);
    ASSERT_TRUE(files.value) << files.error;
    ASSERT_EQ(files.value->front().path, "folder/sample.bin");
    const auto downloaded = manager.DownloadFile(principal, project, "folder/sample.bin");
    ASSERT_TRUE(downloaded.value) << downloaded.error;
    EXPECT_TRUE(std::filesystem::is_regular_file(downloaded.value->path));
    const auto saved = manager.SaveDatabase(principal, project, "folder/sample.bin",
        downloaded.value->path, false, "Investigated parser", R"({"key":"first"})");
    ASSERT_TRUE(saved.value) << saved.error;
    EXPECT_TRUE(saved.value->synchronized);
    EXPECT_EQ(acceptor.latest->message, "Investigated parser");
    EXPECT_EQ(acceptor.latest->resolutions, R"({"key":"first"})");
    const auto uploaded = manager.UploadFile(principal, project,
        downloaded.value->path, "incoming", "uploaded.bin");
    ASSERT_TRUE(uploaded.value) << uploaded.error;
    EXPECT_EQ(uploaded.value->path, "incoming/uploaded.bin");
    std::filesystem::remove_all(downloaded.value->workingDirectory, ignored);

    accessToken = "second";
    ASSERT_TRUE(manager.ListProjects(principal).value);
    EXPECT_EQ(supervisor.spawns, 2U);
    EXPECT_EQ(acceptor.latest->token, "second");

    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    const auto session = sessions.Create(principal.id, 1, {});
    ASSERT_TRUE(session.session);
    binjad::mcp::Foundation foundation(config, sessions, "0.1.0", nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &projects, &manager);
    const auto tools = foundation.Handle(Tool("bn_collaboration_project_list", "{}"),
        principal, session.session, {}, 1);
    EXPECT_NE(tools.body.find("Remote"), std::string::npos);
    const auto filesResult = foundation.Handle(Tool("bn_collaboration_project_file_list",
        "{\"project\":\"" + project + "\"}"), principal, session.session, {}, 1);
    EXPECT_NE(filesResult.body.find("folder/sample.bin"), std::string::npos);
}
