#include "binjad/platform/linux/UnixChannel.hpp"
#include "binjad/process/Role.hpp"
#include "binjad/process/Supervisor.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {
	struct CallbackState
	{
		std::mutex mutex;
		std::condition_variable condition;
		std::unordered_map<binjad::ProcessId, binjad::ChildExit> exits;
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
			auto channel = binjad::platform::linux::ConnectToOverseer(role);
			if (role == binjad::ProcessRole::ProjectChild)
			{
				std::this_thread::sleep_for(std::chrono::seconds(1));
				return 0;
			}
			auto payload = channel->Receive();
			for (auto& byte : payload)
				byte ^= 0x5a;
			channel->Send(payload);
			return 0;
		}

		auto state = std::make_shared<CallbackState>();
		auto runtime = binjad::CreateNativeChildProcessRuntime();
		runtime->Supervisor().SetExitCallback([state](const binjad::ChildExit& exit) {
			{
				std::lock_guard lock(state->mutex);
				state->exits[exit.processId] = exit;
			}
			state->condition.notify_all();
		});
		const auto initialMemory = runtime->Supervisor().MemoryUsage();
		Require(initialMemory.metric == binjad::ProcessMemoryMetric::ResidentSet,
			"Linux memory accounting did not use resident memory");
		const auto* overseerMemory = FindProcess(initialMemory, 0, binjad::ProcessRole::Overseer);
		Require(overseerMemory && overseerMemory->residentBytes != 0 && overseerMemory->memoryBytes != 0,
			"overseer memory was not reported");
		Require(
			initialMemory.TotalMemoryBytes() >= overseerMemory->memoryBytes, "aggregate memory excluded the overseer");

		const auto executable = std::filesystem::absolute(argv[0]);
		const auto fileProcess = runtime->Supervisor().Spawn(executable, binjad::ProcessRole::FileChild);
		auto fileChannel = runtime->Acceptor().Accept(fileProcess, binjad::ProcessRole::FileChild);
		const auto fileMemory = runtime->Supervisor().MemoryUsage();
		const auto* fileChildMemory = FindProcess(fileMemory, fileProcess, binjad::ProcessRole::FileChild);
		Require(fileChildMemory && fileChildMemory->residentBytes != 0 && fileChildMemory->memoryBytes != 0,
			"file-child memory was not reported");
		std::vector<std::uint8_t> payload(128 * 1024);
		for (std::size_t index = 0; index < payload.size(); ++index)
			payload[index] = static_cast<std::uint8_t>(index);
		fileChannel->Send(payload);
		const auto transformed = fileChannel->Receive();
		Require(transformed.size() == payload.size(), "large framed response changed size");
		for (std::size_t index = 0; index < payload.size(); ++index)
			Require(transformed[index] == static_cast<std::uint8_t>(payload[index] ^ 0x5a),
				"large framed response changed contents");
		fileChannel->Close();

		const auto projectProcess = runtime->Supervisor().Spawn(executable, binjad::ProcessRole::ProjectChild);
		auto projectChannel = runtime->Acceptor().Accept(projectProcess, binjad::ProcessRole::ProjectChild);
		const auto projectMemory = runtime->Supervisor().MemoryUsage();
		const auto* projectChildMemory = FindProcess(projectMemory, projectProcess, binjad::ProcessRole::ProjectChild);
		Require(projectChildMemory && projectChildMemory->residentBytes != 0 && projectChildMemory->memoryBytes != 0,
			"project-child memory was not reported");
		{
			std::unique_lock lock(state->mutex);
			Require(state->condition.wait_for(lock, std::chrono::seconds(5),
						[&] { return state->exits.contains(fileProcess) && state->exits.contains(projectProcess); }),
				"children were not reaped");
			Require(state->exits[fileProcess].exitCode == 0 && state->exits[projectProcess].exitCode == 0,
				"child exited unsuccessfully");
		}

		bool closedSendFailed = false;
		try
		{
			const std::array<std::uint8_t, 1> byte {0};
			projectChannel->Send(byte);
		}
		catch (const binjad::ipc::ChannelError&)
		{
			closedSendFailed = true;
		}
		Require(closedSendFailed, "send to an exited child did not fail safely");

		const auto forcedProcess = runtime->Supervisor().Spawn(executable, binjad::ProcessRole::FileChild);
		auto forcedChannel = runtime->Acceptor().Accept(forcedProcess, binjad::ProcessRole::FileChild);
		runtime->TerminateChildren();
		bool forcedChannelClosed = false;
		try
		{
			forcedChannel->Receive();
		}
		catch (const binjad::ipc::ChannelError&)
		{
			forcedChannelClosed = true;
		}
		Require(forcedChannelClosed, "forced teardown did not close an accepted channel");
		{
			std::unique_lock lock(state->mutex);
			Require(state->condition.wait_for(
						lock, std::chrono::seconds(5), [&] { return state->exits.contains(forcedProcess); }),
				"force-terminated child was not reaped");
			Require(state->exits[forcedProcess].signal.has_value(), "force-terminated child did not report a signal");
		}
		std::cout << "Linux child runtime tests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "Linux child runtime test failed: " << exception.what() << '\n';
		return 1;
	}
}
