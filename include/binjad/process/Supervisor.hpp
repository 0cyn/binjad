#pragma once

#include "binjad/ipc/Channel.hpp"
#include "binjad/process/Role.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <vector>

namespace binjad {
	using ProcessId = std::uint64_t;

	enum class ProcessMemoryMetric
	{
		ResidentSet,
		PhysicalFootprint,
	};

	struct ProcessMemoryUsage
	{
		// Process ID zero identifies the overseer. Child IDs retain their
		// platform-independent ProcessSupervisor identity.
		ProcessId processId = 0;
		ProcessRole role = ProcessRole::Overseer;
		std::uint64_t residentBytes = 0;
		std::uint64_t memoryBytes = 0;
	};

	struct ProcessMemorySnapshot
	{
		ProcessMemoryMetric metric = ProcessMemoryMetric::ResidentSet;
		std::vector<ProcessMemoryUsage> processes;

		[[nodiscard]] std::uint64_t TotalMemoryBytes() const noexcept
		{
			std::uint64_t total = 0;
			for (const auto& process : processes)
			{
				if (process.memoryBytes > std::numeric_limits<std::uint64_t>::max() - total)
					return std::numeric_limits<std::uint64_t>::max();
				total += process.memoryBytes;
			}
			return total;
		}
	};

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
		virtual ProcessMemorySnapshot MemoryUsage() = 0;
	};

	class ChildChannelAcceptor
	{
	public:
		virtual ~ChildChannelAcceptor() = default;
		virtual std::unique_ptr<ipc::ByteChannel> Accept(ProcessId expectedProcess, ProcessRole expectedRole) = 0;
	};

	class ChildProcessRuntime
	{
	public:
		virtual ~ChildProcessRuntime() = default;
		virtual ProcessSupervisor& Supervisor() = 0;
		virtual ChildChannelAcceptor& Acceptor() = 0;
		virtual void TerminateChildren() = 0;
	};

	std::unique_ptr<ProcessSupervisor> CreateNativeProcessSupervisor();
	std::unique_ptr<ChildProcessRuntime> CreateNativeChildProcessRuntime();
}  // namespace binjad
