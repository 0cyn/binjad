#pragma once

#include "binjad/platform/macos/mach_channel.hpp"
#include "binjad/process/supervisor.hpp"

#include <mach/mach.h>

#include <string_view>

namespace binjad::platform::macos
{
inline constexpr std::string_view kMachServiceName = "me.cynder.binjad";

class MachBootstrapServer : public ChildChannelAcceptor
{
  public:
    explicit MachBootstrapServer(
        ProcessSupervisor& supervisor, std::string_view serviceName = kMachServiceName);
    MachBootstrapServer(const MachBootstrapServer&) = delete;
    MachBootstrapServer& operator=(const MachBootstrapServer&) = delete;
    MachBootstrapServer(MachBootstrapServer&& other) noexcept;
    MachBootstrapServer& operator=(MachBootstrapServer&& other) noexcept;
    ~MachBootstrapServer();

    std::unique_ptr<ipc::ByteChannel> Accept(
        ProcessId expectedProcess, ProcessRole expectedRole) override;

  private:
    mach_port_t servicePort_ = MACH_PORT_NULL;
    mach_port_t exceptionPort_ = MACH_PORT_NULL;
};

MachChannel ConnectToOverseer(
    ProcessRole role, std::string_view serviceName = kMachServiceName);
}
