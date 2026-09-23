#include "binjad/overseer/analysis_scheduler.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>

using namespace std::chrono_literals;

namespace
{
binjad::overseer::AnalysisScheduleRequest Request(
    std::string job, std::string session = "session", std::string file = "file")
{
    return {"token", std::move(session), std::move(file), std::move(job)};
}
}

TEST(AnalysisSchedulerTest, DividesBudgetAndQueuesExcessJobs)
{
    binjad::CpuConfig config;
    config.percentage = 75;
    binjad::overseer::AnalysisScheduler scheduler(config,
        [] { return binjad::platform::CpuCapacityResult{8, {}}; });
    std::string error;
    std::atomic_size_t firstWorkers = 0;
    auto first = scheduler.Acquire(Request("one", "one", "one"),
        [&](std::size_t workers) { firstWorkers = workers; }, error);
    ASSERT_TRUE(first) << error;
    EXPECT_EQ(firstWorkers, 6U);

    std::atomic_size_t secondWorkers = 0;
    auto second = scheduler.Acquire(Request("two", "two", "two"),
        [&](std::size_t workers) { secondWorkers = workers; }, error);
    ASSERT_TRUE(second) << error;
    EXPECT_EQ(firstWorkers, 3U);
    EXPECT_EQ(secondWorkers, 3U);

    std::vector<std::optional<binjad::overseer::AnalysisScheduler::Lease>> leases;
    for (int index = 0; index < 4; ++index)
    {
        leases.push_back(scheduler.Acquire(Request(std::to_string(index),
            "s" + std::to_string(index), "f" + std::to_string(index)), {}, error));
        ASSERT_TRUE(leases.back()) << error;
    }
    auto queued = std::async(std::launch::async, [&] {
        std::string acquireError;
        return scheduler.Acquire(Request("queued", "queued", "queued"), {}, acquireError);
    });
    EXPECT_EQ(queued.wait_for(20ms), std::future_status::timeout);
    leases.front().reset();
    ASSERT_EQ(queued.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(queued.get());
}

TEST(AnalysisSchedulerTest, SerialSubdivisionRunsOneFilePerSession)
{
    binjad::CpuConfig config;
    config.percentage = 100;
    config.fairness = binjad::FairnessUnit::AnalysisSession;
    config.subdivision = "serial";
    binjad::overseer::AnalysisScheduler scheduler(config,
        [] { return binjad::platform::CpuCapacityResult{4, {}}; });
    std::string error;
    auto first = scheduler.Acquire(Request("one", "shared", "first"), {}, error);
    ASSERT_TRUE(first) << error;
    auto second = std::async(std::launch::async, [&] {
        std::string acquireError;
        return scheduler.Acquire(Request("two", "shared", "second"), {}, acquireError);
    });
    EXPECT_EQ(second.wait_for(20ms), std::future_status::timeout);
    first.reset();
    ASSERT_EQ(second.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(second.get());
}

TEST(AnalysisSchedulerTest, CapacityShrinkDoesNotAbortActiveUnit)
{
    binjad::CpuConfig config;
    config.percentage = 100;
    std::atomic_size_t capacity = 4;
    binjad::overseer::AnalysisScheduler scheduler(config, [&] {
        return binjad::platform::CpuCapacityResult{capacity.load(), {}};
    });
    std::atomic_size_t workers = 0;
    std::string error;
    auto first = scheduler.Acquire(Request("one", "one", "one"),
        [&](std::size_t count) { workers = count; }, error);
    ASSERT_TRUE(first) << error;
    EXPECT_EQ(workers, 4U);
    capacity = 1;
    auto queued = std::async(std::launch::async, [&] {
        std::string acquireError;
        return scheduler.Acquire(Request("two", "two", "two"), {}, acquireError);
    });
    EXPECT_EQ(queued.wait_for(20ms), std::future_status::timeout);
    EXPECT_EQ(workers, 1U);
    first.reset();
    ASSERT_EQ(queued.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(queued.get());
}

TEST(AnalysisSchedulerTest, JobFairnessStillSerializesOneFileChild)
{
    binjad::CpuConfig config;
    config.percentage = 100;
    binjad::overseer::AnalysisScheduler scheduler(config,
        [] { return binjad::platform::CpuCapacityResult{2, {}}; });
    std::string error;
    auto first = scheduler.Acquire(Request("one", "one", "shared"), {}, error);
    ASSERT_TRUE(first) << error;
    auto sameFile = std::async(std::launch::async, [&] {
        std::string acquireError;
        return scheduler.Acquire(Request("two", "two", "shared"), {}, acquireError);
    });
    EXPECT_EQ(sameFile.wait_for(20ms), std::future_status::timeout);
    auto otherFile = scheduler.Acquire(Request("three", "three", "other"), {}, error);
    ASSERT_TRUE(otherFile) << error;
    first.reset();
    ASSERT_EQ(sameFile.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(sameFile.get());
}
