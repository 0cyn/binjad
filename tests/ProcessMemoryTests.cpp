#include "binjad/process/Role.hpp"
#include "binjad/process/Supervisor.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
	struct CallbackState
	{
		std::mutex mutex;
		std::condition_variable condition;
		std::optional<binjad::ChildExit> exit;
	};

	void Require(bool condition, std::string_view message)
	{
		if (!condition)
			throw std::runtime_error(std::string(message));
	}

	const binjad::ProcessMemoryUsage* FindProcess(
		const binjad::ProcessMemorySnapshot& snapshot, binjad::ProcessId processId, binjad::ProcessRole role)
	{
		const auto found = std::find_if(snapshot.processes.begin(), snapshot.processes.end(), [&](const auto& process) {
			return process.processId == processId && process.role == role;
		});
		return found == snapshot.processes.end() ? nullptr : &*found;
	}
}  // namespace

int main(int argc, char** argv)
{
	try
	{
		const auto role = binjad::RoleFromArgv0(argc > 0 ? argv[0] : "");
		if (role != binjad::ProcessRole::Overseer)
		{
			std::vector<std::uint8_t> allocation(8 * 1024 * 1024);
			for (std::size_t offset = 0; offset < allocation.size(); offset += 4096)
				allocation[offset] = static_cast<std::uint8_t>(offset);
			std::this_thread::sleep_for(std::chrono::seconds(1));
			return allocation[0];
		}

		auto supervisor = binjad::CreateNativeProcessSupervisor();
		auto state = std::make_shared<CallbackState>();
		supervisor->SetExitCallback([state](const binjad::ChildExit& exit) {
			{
				std::lock_guard lock(state->mutex);
				state->exit = exit;
			}
			state->condition.notify_all();
		});

		const auto initial = supervisor->MemoryUsage();
		Require(initial.metric == binjad::ProcessMemoryMetric::PhysicalFootprint,
			"macOS memory accounting did not use physical footprint");
		const auto* overseer = FindProcess(initial, 0, binjad::ProcessRole::Overseer);
		Require(
			overseer && overseer->residentBytes != 0 && overseer->memoryBytes != 0, "overseer memory was not reported");

		const auto child = supervisor->Spawn(std::filesystem::absolute(argv[0]), binjad::ProcessRole::FileChild);
		bool observedChild = false;
		const auto sampleDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
		while (std::chrono::steady_clock::now() < sampleDeadline)
		{
			const auto snapshot = supervisor->MemoryUsage();
			const auto* currentOverseer = FindProcess(snapshot, 0, binjad::ProcessRole::Overseer);
			const auto* childUsage = FindProcess(snapshot, child, binjad::ProcessRole::FileChild);
			if (currentOverseer && childUsage && childUsage->residentBytes != 0 && childUsage->memoryBytes != 0
				&& snapshot.TotalMemoryBytes() >= currentOverseer->memoryBytes + childUsage->memoryBytes)
			{
				observedChild = true;
				break;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		Require(observedChild, "file-child memory was not reported");

		{
			std::unique_lock lock(state->mutex);
			Require(state->condition.wait_for(lock, std::chrono::seconds(5), [&] { return state->exit.has_value(); }),
				"child was not reaped");
			Require(state->exit->processId == child && state->exit->role == binjad::ProcessRole::FileChild,
				"child exit identity was incorrect");
			Require(state->exit->exitCode == 0, "child exited unsuccessfully");
		}
		std::cout << "Process memory tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "Process memory test failed: " << exception.what() << '\n';
		return 1;
	}
}
