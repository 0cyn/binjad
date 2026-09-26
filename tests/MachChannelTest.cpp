#include "binjad/platform/macos/MachChannel.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <future>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

TEST(MachChannelTest, TransfersInlineAndOutOfLinePayloads)
{
    auto [first, second] = binjad::platform::macos::CreateMachChannelPair();

    for (std::size_t length = 0; length < 9; ++length)
    {
        std::vector<std::uint8_t> small(length);
        for (std::size_t index = 0; index < length; ++index)
            small[index] = static_cast<std::uint8_t>(index + 1);
        first.Send(small);
        EXPECT_EQ(second.Receive(), small);
    }

    std::vector<std::uint8_t> large(binjad::ipc::kInlinePayloadLimit + 4096);
    for (std::size_t index = 0; index < large.size(); ++index)
        large[index] = static_cast<std::uint8_t>(index);
    second.Send(large);
    EXPECT_EQ(first.Receive(), large);
}

TEST(MachChannelTest, CloseInterruptsBlockedReceive)
{
    auto [first, second] = binjad::platform::macos::CreateMachChannelPair();
    auto receive = std::async(std::launch::async, [&] {
        try
        {
            first.Receive();
            return false;
        }
        catch (const binjad::ipc::ChannelError&)
        {
            return true;
        }
    });
    std::this_thread::sleep_for(10ms);
    first.Close();
    ASSERT_EQ(receive.wait_for(1s), std::future_status::ready);
    EXPECT_TRUE(receive.get());
}
