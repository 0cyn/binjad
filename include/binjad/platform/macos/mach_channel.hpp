#pragma once

#include "binjad/ipc/channel.hpp"

#include <mach/mach.h>

#include <atomic>
#include <utility>

namespace binjad::platform::macos
{
class MachChannel final : public ipc::ByteChannel
{
  public:
    MachChannel(mach_port_t receivePort, mach_port_t sendPort);
    MachChannel(const MachChannel&) = delete;
    MachChannel& operator=(const MachChannel&) = delete;
    MachChannel(MachChannel&& other) noexcept;
    MachChannel& operator=(MachChannel&& other) noexcept;
    ~MachChannel() override;

    void Send(std::span<const std::uint8_t> payload) override;
    std::vector<std::uint8_t> Receive() override;
    void Close() override;

    mach_port_t ReceivePort() const { return receivePort_.load(); }
    mach_port_t SendPort() const { return sendPort_.load(); }

  private:
    void Reset();

    std::atomic<mach_port_t> receivePort_{MACH_PORT_NULL};
    std::atomic<mach_port_t> sendPort_{MACH_PORT_NULL};
};

std::pair<MachChannel, MachChannel> CreateMachChannelPair();
}
