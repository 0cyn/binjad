#include "binjad/process/supervisor.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>

TEST(ProcessSupervisorTest, StartsAndStopsMonitoringThreads)
{
    auto supervisor = binjad::CreateNativeProcessSupervisor();
    ASSERT_NE(supervisor, nullptr);
}

TEST(ProcessSupervisorTest, ReapsNormallyExitedChild)
{
    auto supervisor = binjad::CreateNativeProcessSupervisor();
    std::mutex mutex;
    std::condition_variable condition;
    std::optional<binjad::ChildExit> observed;
    supervisor->SetExitCallback([&](const binjad::ChildExit& exit) {
        std::lock_guard lock(mutex);
        observed = exit;
        condition.notify_one();
    });

    const auto process = supervisor->Spawn("/usr/bin/true", binjad::ProcessRole::FileChild);
    std::unique_lock lock(mutex);
    ASSERT_TRUE(condition.wait_for(lock, std::chrono::seconds(5), [&] {
        return observed.has_value();
    }));
    EXPECT_EQ(observed->processId, process);
    EXPECT_EQ(observed->role, binjad::ProcessRole::FileChild);
    EXPECT_EQ(observed->exitCode, 0);
    EXPECT_FALSE(observed->signal.has_value());
    EXPECT_FALSE(observed->crash.has_value());
}
