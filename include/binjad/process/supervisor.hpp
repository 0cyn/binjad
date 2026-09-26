#pragma once

#include "binjad/ipc/Channel.hpp"
#include "binjad/process/Role.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace binjad
{
using ProcessId = std::uint64_t;

struct CrashInfo
{
    int exception = 0;
    std::vector<std::int64_t> codes;
};

struct ChildExit
{
    ProcessId processId = 0;
    ProcessRole role = ProcessRole::Overseer;
    std::optional<int> exitCode;
    std::optional<int> signal;
    std::optional<CrashInfo> crash;
};

class ProcessSupervisor
{
  public:
    using ExitCallback = std::function<void(const ChildExit&)>;

    virtual ~ProcessSupervisor() = default;
    virtual ProcessId Spawn(const std::filesystem::path& executable, ProcessRole role) = 0;
    virtual void Terminate(ProcessId processId) = 0;
    virtual void SetExitCallback(ExitCallback callback) = 0;
};

class ChildChannelAcceptor
{
  public:
    virtual ~ChildChannelAcceptor() = default;
    virtual std::unique_ptr<ipc::ByteChannel> Accept(
        ProcessId expectedProcess, ProcessRole expectedRole) = 0;
};

std::unique_ptr<ProcessSupervisor> CreateNativeProcessSupervisor();
}
