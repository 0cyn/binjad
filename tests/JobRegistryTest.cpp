#include "binjad/session/job_registry.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <vector>

using namespace std::chrono_literals;

TEST(JobRegistryTest, RetainsSessionUntilTerminalAndConsumesResultOnce)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    const auto now = binjad::session::AnalysisSessionRegistry::Clock::time_point{};
    const auto session = sessions.Create(std::string(64, 'a'), 1, now);
    ASSERT_TRUE(session.session);
    binjad::session::JobRegistry jobs(references, sessions);
    const auto created = jobs.Create(std::string(64, 'a'), session.session->reference,
        "BinaryViewRef", "analysis", 10, now);
    ASSERT_TRUE(created.job) << created.error;
    EXPECT_EQ(sessions.Find(session.session->reference, std::string(64, 'a'), now)->retainers, 1U);
    EXPECT_FALSE(sessions.Close(session.session->reference, std::string(64, 'a')));
    EXPECT_TRUE(jobs.Start(std::string(64, 'a'), created.job->reference, 11));
    EXPECT_TRUE(jobs.Complete(std::string(64, 'a'), created.job->reference,
        R"({"state":"complete"})", 12));
    EXPECT_EQ(sessions.Find(session.session->reference, std::string(64, 'a'), now)->retainers, 0U);
    const auto result = jobs.TakeResult(std::string(64, 'a'), created.job->reference);
    ASSERT_TRUE(result.job) << result.error;
    EXPECT_EQ(result.job->resultJson, R"({"state":"complete"})");
    EXPECT_FALSE(jobs.TakeResult(std::string(64, 'a'), created.job->reference).job);
}

TEST(JobRegistryTest, SequencesProgressAndHidesForeignJobs)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    const auto created = jobs.Create(std::string(64, 'a'), {}, {}, "test", 1, {});
    ASSERT_TRUE(created.job);
    binjad::session::JobRecord observed;
    jobs.SetProgressCallback([&](const auto& job) { observed = job; });
    EXPECT_TRUE(jobs.ReportProgress(std::string(64, 'a'), created.job->reference,
        "load", 1, 3, "opening", 2));
    EXPECT_TRUE(jobs.ReportProgress(std::string(64, 'a'), created.job->reference,
        "analysis", 2, 3, {}, 3));
    ASSERT_TRUE(observed.progress);
    EXPECT_EQ(observed.progress->sequence, 2U);
    EXPECT_EQ(observed.progress->phase, "analysis");
    EXPECT_FALSE(jobs.Info(std::string(64, 'b'), created.job->reference).job);
}

TEST(JobRegistryTest, CancellationInvokesBoundCallback)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    int cancellations = 0;
    const auto created = jobs.Create(std::string(64, 'a'), {}, {}, "test", 1, {},
        [&] {
            ++cancellations;
            return std::string{};
        });
    ASSERT_TRUE(created.job);
    EXPECT_TRUE(jobs.Cancel(std::string(64, 'a'), created.job->reference).empty());
    EXPECT_EQ(cancellations, 1);
    const auto info = jobs.Info(std::string(64, 'a'), created.job->reference);
    ASSERT_TRUE(info.job);
    EXPECT_TRUE(info.job->cancelRequested);
    EXPECT_TRUE(jobs.MarkCancelled(std::string(64, 'a'), created.job->reference,
        R"({"state":"cancelled"})", 2));
}

TEST(JobRegistryTest, TokenRemovalCancelsAndPurgesAllJobs)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    int cancellations = 0;
    ASSERT_TRUE(jobs.Create(std::string(64, 'a'), {}, {}, "active", 1, {}, [&] {
        ++cancellations;
        return std::string{};
    }).job);
    const auto terminal = jobs.Create(std::string(64, 'a'), {}, {}, "terminal", 1, {});
    ASSERT_TRUE(terminal.job);
    ASSERT_TRUE(jobs.Complete(std::string(64, 'a'), terminal.job->reference, "{}", 2));
    ASSERT_TRUE(jobs.Create(std::string(64, 'b'), {}, {}, "foreign", 1, {}).job);
    jobs.CancelByToken(std::string(64, 'a'));
    jobs.RemoveByToken(std::string(64, 'a'));
    EXPECT_EQ(cancellations, 1);
    EXPECT_EQ(jobs.List(std::string(64, 'a')).size(), 0U);
    EXPECT_EQ(jobs.Size(), 1U);
}

TEST(JobRegistryTest, WaitsForTerminalStateOrReturnsActiveJobAtDeadline)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    const auto created = jobs.Create(std::string(64, 'a'), {}, {}, "test", 1, {});
    ASSERT_TRUE(created.job);
    ASSERT_TRUE(jobs.Start(std::string(64, 'a'), created.job->reference, 2));
    const auto active = jobs.WaitForTerminal(
        std::string(64, 'a'), created.job->reference, 0ms);
    ASSERT_TRUE(active.job);
    EXPECT_EQ(active.job->state, binjad::session::JobState::Running);

    std::jthread finisher([&] {
        std::this_thread::sleep_for(1ms);
        jobs.Complete(std::string(64, 'a'), created.job->reference, "{}", 3);
    });
    const auto terminal = jobs.WaitForTerminal(
        std::string(64, 'a'), created.job->reference, 1s);
    ASSERT_TRUE(terminal.job);
    EXPECT_EQ(terminal.job->state, binjad::session::JobState::Complete);
}

TEST(JobRegistryTest, ReportsEveryObservableJobStateChange)
{
    binjad::reference::FriendlyReferencePool references;
    binjad::session::AnalysisSessionRegistry sessions(references, 30min);
    binjad::session::JobRegistry jobs(references, sessions);
    std::vector<binjad::session::JobState> observed;
    jobs.SetChangedCallback([&](const auto& job) { observed.push_back(job.state); });

    const auto created = jobs.Create(std::string(64, 'a'), {}, {}, "test", 1, {});
    ASSERT_TRUE(created.job);
    ASSERT_TRUE(jobs.Start(std::string(64, 'a'), created.job->reference, 2));
    ASSERT_TRUE(jobs.Complete(
        std::string(64, 'a'), created.job->reference, "{}", 3));
    ASSERT_TRUE(jobs.TakeResult(std::string(64, 'a'), created.job->reference).job);

    EXPECT_EQ(observed, (std::vector<binjad::session::JobState>{
        binjad::session::JobState::Queued,
        binjad::session::JobState::Running,
        binjad::session::JobState::Complete,
        binjad::session::JobState::Complete}));
}
