#include "binjad/upload/upload_registry.hpp"

#include "binjad/platform/paths.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <unistd.h>

namespace
{
class TemporaryDirectory
{
  public:
    TemporaryDirectory()
        : path(std::filesystem::temp_directory_path() /
            ("binjad-upload-" + std::to_string(getpid())))
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    ~TemporaryDirectory()
    {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};
}

TEST(UploadRegistryTest, StreamsSpillsHashesAndConsumesCompletedUpload)
{
    TemporaryDirectory temporary;
    binjad::Config config;
    config.http.publicBaseUrl = "http://127.0.0.1:8712";
    config.storage.spoolPath = temporary.path / "spool";
    config.uploads.maxBytes = 16;
    config.uploads.memoryThresholdBytes = 4;
    config.uploads.urlTtl = std::chrono::seconds(60);
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    binjad::project::LocalProjectRegistry projects(references);
    binjad::project::LocalProjectRecord project{{}, "native", "/private/Test.bnpr", "Test", {}};
    ASSERT_TRUE(projects.Upsert(project).empty());
    const auto session = sessions.Create(std::string(64, 'a'), 10, {});
    ASSERT_TRUE(session.session);
    binjad::upload::UploadRegistry uploads(config, references, sessions, projects);

    const auto issued = uploads.Issue(std::string(64, 'a'), session.session->reference,
        project.reference, "sample.bin", 10, {});
    ASSERT_TRUE(issued.upload) << issued.error;
    EXPECT_NE(issued.url.find(config.http.uploadPath), std::string::npos);
    const auto capability = issued.url.substr(issued.url.find_last_of('/') + 1);
    EXPECT_FALSE(uploads.Begin(capability, std::string(64, 'b'), {}).first);
    auto [transfer, beginError] = uploads.Begin(capability, std::string(64, 'a'), {});
    ASSERT_TRUE(transfer) << beginError;
    std::string error;
    EXPECT_TRUE(transfer->Write("abc", error)) << error;
    EXPECT_TRUE(transfer->Write("def", error)) << error;
    const auto completed = transfer->Finish(error);
    ASSERT_TRUE(completed) << error;
    EXPECT_EQ(completed->size, 6U);
    EXPECT_EQ(completed->sha256,
        "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721");
    EXPECT_FALSE(uploads.Begin(capability, std::string(64, 'a'), {}).first);
    uploads.Sweep(binjad::upload::UploadRegistry::Clock::time_point(
        std::chrono::seconds(61)));
    EXPECT_TRUE(uploads.FindCompleted(std::string(64, 'a'),
        session.session->reference, completed->id, {}));
    const auto payload = uploads.PreparePayload(std::string(64, 'a'),
        session.session->reference, completed->id, {});
    ASSERT_TRUE(payload.first) << payload.second;
    const auto contents = binjad::platform::ReadPrivateFile(payload.first->path);
    ASSERT_TRUE(contents.contents) << contents.error;
    EXPECT_EQ(*contents.contents, "abcdef");
    EXPECT_TRUE(uploads.RecordCommit(std::string(64, 'a'), completed->id,
        R"({"committed":true})"));
    ASSERT_TRUE(uploads.FindCommitResult(std::string(64, 'a'),
        session.session->reference, completed->id));
    EXPECT_EQ(*uploads.FindCommitResult(std::string(64, 'a'),
        session.session->reference, completed->id), R"({"committed":true})");
    ASSERT_EQ(uploads.List(std::string(64, 'a')).size(), 1U);
    EXPECT_EQ(uploads.List(std::string(64, 'a')).front().state,
        binjad::upload::UploadState::Committed);
    EXPECT_TRUE(uploads.Cancel(std::string(64, 'a'), completed->id).empty());
    EXPECT_EQ(uploads.Size(), 0U);
}

TEST(UploadRegistryTest, FailedAttemptCanRetryUntilCompletion)
{
    TemporaryDirectory temporary;
    binjad::Config config;
    config.http.publicBaseUrl = "http://127.0.0.1:8712";
    config.storage.spoolPath = temporary.path / "spool";
    config.uploads.maxBytes = 4;
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, std::chrono::minutes(30));
    binjad::project::LocalProjectRegistry projects(references);
    binjad::project::LocalProjectRecord project{{}, "native", "/private/Test.bnpr", "Test", {}};
    ASSERT_TRUE(projects.Upsert(project).empty());
    const auto session = sessions.Create(std::string(64, 'a'), 10, {});
    ASSERT_TRUE(session.session);
    binjad::upload::UploadRegistry uploads(config, references, sessions, projects);
    const auto issued = uploads.Issue(std::string(64, 'a'), session.session->reference,
        project.reference, "sample.bin", 10, {});
    ASSERT_TRUE(issued.upload);
    const auto capability = issued.url.substr(issued.url.find_last_of('/') + 1);
    {
        auto attempt = uploads.Begin(capability, std::string(64, 'a'), {}).first;
        ASSERT_TRUE(attempt);
        std::string error;
        EXPECT_FALSE(attempt->Write("12345", error));
    }
    auto retry = uploads.Begin(capability, std::string(64, 'a'), {}).first;
    ASSERT_TRUE(retry);
    std::string error;
    EXPECT_TRUE(retry->Write("1234", error));
    EXPECT_TRUE(retry->Finish(error));
    const auto payload = uploads.PreparePayload(std::string(64, 'a'),
        session.session->reference, issued.upload->id, {});
    ASSERT_TRUE(payload.first);
    EXPECT_TRUE(uploads.CommitFailed(std::string(64, 'a'), issued.upload->id));
    EXPECT_TRUE(uploads.FindCompleted(std::string(64, 'a'),
        session.session->reference, issued.upload->id, {}));
}
