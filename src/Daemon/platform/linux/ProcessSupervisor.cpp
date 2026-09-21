#include "binjad/process/Supervisor.hpp"

#include "binjad/platform/linux/UnixChannel.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <signal.h>
#include <spawn.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>
#include <unistd.h>

extern char** environ;

namespace binjad {
	namespace {
		struct ChildRecord
		{
			pid_t pid = 0;
			int pidfd = -1;
			ProcessRole role = ProcessRole::Overseer;
			int pendingChannel = -1;
			int acceptedControl = -1;
		};

		[[noreturn]] void ThrowSystemError(std::string_view operation, int error)
		{
			throw std::runtime_error(std::string(operation) + ": " + std::strerror(error));
		}

		class LinuxChildRuntime final :
			public ChildProcessRuntime,
			public ProcessSupervisor,
			public ChildChannelAcceptor
		{
		public:
			LinuxChildRuntime();
			~LinuxChildRuntime() override;

			ProcessSupervisor& Supervisor() override { return *this; }
			ChildChannelAcceptor& Acceptor() override { return *this; }
			void TerminateChildren() override;
			ProcessId Spawn(const std::filesystem::path& executable, ProcessRole role) override;
			void Terminate(ProcessId processId) override;
			void SetExitCallback(ExitCallback callback) override;
			ProcessMemorySnapshot MemoryUsage() override;
			std::unique_ptr<ipc::ByteChannel> Accept(ProcessId expectedProcess, ProcessRole expectedRole) override;

		private:
			void ReaperLoop();
			void PublishExit(ProcessId processId, ChildRecord child, std::optional<int> status);

			std::mutex spawnMutex_;
			std::mutex mutex_;
			std::condition_variable condition_;
			std::condition_variable stoppedCondition_;
			std::unordered_map<ProcessId, ChildRecord> children_;
			ProcessId nextProcessId_ = 1;
			ExitCallback exitCallback_;
			bool stopping_ = false;
			struct sigaction previousSigchldAction_ {};
			bool sigchldActionSet_ = false;
			std::thread reaper_;
		};

		void CloseDescriptor(int& descriptor)
		{
			if (descriptor >= 0)
			{
				::close(descriptor);
				descriptor = -1;
			}
		}

		int SignalChild(const ChildRecord& child, int signal)
		{
			return static_cast<int>(::syscall(SYS_pidfd_send_signal, child.pidfd, signal, nullptr, 0));
		}

		void CloseAcceptedChannel(ChildRecord& child)
		{
			if (child.acceptedControl >= 0)
			{
				::shutdown(child.acceptedControl, SHUT_RDWR);
				CloseDescriptor(child.acceptedControl);
			}
		}

		void SignalOrFallback(const ChildRecord& child, int signal)
		{
			if (SignalChild(child, signal) != 0 && errno != ESRCH)
				::kill(child.pid, signal);
		}

		std::optional<std::uint64_t> ResidentBytes(pid_t pid)
		{
			std::ifstream status("/proc/" + std::to_string(pid) + "/statm");
			std::uint64_t virtualPages = 0;
			std::uint64_t residentPages = 0;
			if (!(status >> virtualPages >> residentPages))
				return std::nullopt;
			(void)virtualPages;
			const auto pageSize = ::sysconf(_SC_PAGESIZE);
			if (pageSize <= 0)
				return std::nullopt;
			const auto bytesPerPage = static_cast<std::uint64_t>(pageSize);
			if (residentPages > std::numeric_limits<std::uint64_t>::max() / bytesPerPage)
				return std::numeric_limits<std::uint64_t>::max();
			return residentPages * bytesPerPage;
		}

		std::atomic<bool> gRuntimeExists {false};
	}  // namespace

	LinuxChildRuntime::LinuxChildRuntime()
	{
		bool expected = false;
		if (!gRuntimeExists.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
			throw std::runtime_error("only one Linux child process runtime may exist");
		struct sigaction action {};
		action.sa_handler = SIG_DFL;
		sigemptyset(&action.sa_mask);
		if (::sigaction(SIGCHLD, &action, &previousSigchldAction_) != 0)
		{
			gRuntimeExists.store(false, std::memory_order_release);
			ThrowSystemError("sigaction SIGCHLD", errno);
		}
		sigchldActionSet_ = true;
		try
		{
			reaper_ = std::thread([this] { ReaperLoop(); });
		}
		catch (...)
		{
			::sigaction(SIGCHLD, &previousSigchldAction_, nullptr);
			sigchldActionSet_ = false;
			gRuntimeExists.store(false, std::memory_order_release);
			throw;
		}
	}

	LinuxChildRuntime::~LinuxChildRuntime()
	{
		{
			std::lock_guard lock(mutex_);
			stopping_ = true;
			for (auto& [id, child] : children_)
			{
				(void)id;
				CloseDescriptor(child.pendingChannel);
				CloseAcceptedChannel(child);
				SignalOrFallback(child, SIGTERM);
			}
		}
		condition_.notify_all();
		{
			std::unique_lock lock(mutex_);
			stoppedCondition_.wait_for(lock, std::chrono::seconds(2), [this] { return children_.empty(); });
			for (const auto& [id, child] : children_)
			{
				(void)id;
				SignalOrFallback(child, SIGKILL);
			}
		}
		condition_.notify_all();
		if (reaper_.joinable())
			reaper_.join();
		if (sigchldActionSet_)
			::sigaction(SIGCHLD, &previousSigchldAction_, nullptr);
		gRuntimeExists.store(false, std::memory_order_release);
	}

	void LinuxChildRuntime::TerminateChildren()
	{
		{
			std::lock_guard lock(mutex_);
			stopping_ = true;
			for (auto& [id, child] : children_)
			{
				(void)id;
				CloseDescriptor(child.pendingChannel);
				CloseAcceptedChannel(child);
				SignalOrFallback(child, SIGKILL);
			}
		}
		condition_.notify_all();
	}

	ProcessId LinuxChildRuntime::Spawn(const std::filesystem::path& executable, ProcessRole role)
	{
		if (role == ProcessRole::Overseer)
			throw std::invalid_argument("cannot spawn an overseer child");
		if (executable.empty())
			throw std::invalid_argument("child executable path must not be empty");

		std::lock_guard spawnLock(spawnMutex_);
		for (int descriptor = 0; descriptor <= 2; ++descriptor)
		{
			if (::fcntl(descriptor, F_GETFD) < 0)
				throw std::runtime_error("standard descriptors must be open before spawning a child");
		}

		int sockets[2] {-1, -1};
		if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
			ThrowSystemError("socketpair", errno);
		if (sockets[1] < 4)
		{
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			throw std::runtime_error("child channel source descriptor is unexpectedly below four");
		}
		int passCredentials = 1;
		if (::setsockopt(sockets[0], SOL_SOCKET, SO_PASSCRED, &passCredentials, sizeof(passCredentials)) != 0)
		{
			const auto error = errno;
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("setsockopt SO_PASSCRED", error);
		}

		posix_spawn_file_actions_t actions;
		posix_spawnattr_t attributes;
		int result = ::posix_spawn_file_actions_init(&actions);
		if (result != 0)
		{
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("posix_spawn_file_actions_init", result);
		}
		result = ::posix_spawnattr_init(&attributes);
		if (result != 0)
		{
			::posix_spawn_file_actions_destroy(&actions);
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("posix_spawnattr_init", result);
		}
		auto cleanup = [&] {
			::posix_spawnattr_destroy(&attributes);
			::posix_spawn_file_actions_destroy(&actions);
		};

		if (sockets[0] == platform::linux::kChildChannelDescriptor
			&& (result = ::posix_spawn_file_actions_addclose(&actions, sockets[0])) != 0)
		{
			cleanup();
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("posix_spawn_file_actions_addclose", result);
		}
		if ((result = ::posix_spawn_file_actions_adddup2(
				 &actions, sockets[1], platform::linux::kChildChannelDescriptor))
				!= 0
			|| (result = ::posix_spawn_file_actions_addclosefrom_np(&actions, 4)) != 0)
		{
			cleanup();
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("configure child descriptor actions", result);
		}

		sigset_t emptyMask;
		sigemptyset(&emptyMask);
		sigset_t defaults;
		sigemptyset(&defaults);
		sigaddset(&defaults, SIGINT);
		sigaddset(&defaults, SIGTERM);
		sigaddset(&defaults, SIGPIPE);
		const short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF;
		if ((result = ::posix_spawnattr_setsigmask(&attributes, &emptyMask)) != 0
			|| (result = ::posix_spawnattr_setsigdefault(&attributes, &defaults)) != 0
			|| (result = ::posix_spawnattr_setflags(&attributes, flags)) != 0)
		{
			cleanup();
			CloseDescriptor(sockets[0]);
			CloseDescriptor(sockets[1]);
			ThrowSystemError("configure child spawn attributes", result);
		}

		std::string executableString = executable.string();
		std::string childName(ChildArgv0(role));
		char* arguments[] = {childName.data(), nullptr};
		pid_t pid = 0;
		result = ::posix_spawn(&pid, executableString.c_str(), &actions, &attributes, arguments, environ);
		cleanup();
		CloseDescriptor(sockets[1]);
		if (result != 0)
		{
			CloseDescriptor(sockets[0]);
			ThrowSystemError("posix_spawn", result);
		}
		const int pidfd = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
		if (pidfd < 0)
		{
			const auto error = errno;
			::kill(pid, SIGKILL);
			while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR)
			{
			}
			CloseDescriptor(sockets[0]);
			ThrowSystemError("pidfd_open", error);
		}

		ProcessId processId = 0;
		try
		{
			std::lock_guard lock(mutex_);
			if (stopping_)
				throw std::runtime_error("child process runtime is stopping");
			if (nextProcessId_ == 0 || nextProcessId_ == std::numeric_limits<ProcessId>::max())
				throw std::runtime_error("child process ID space exhausted");
			processId = nextProcessId_++;
			children_.emplace(processId, ChildRecord {pid, pidfd, role, sockets[0], -1});
		}
		catch (...)
		{
			::syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, nullptr, 0);
			while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR)
			{
			}
			::close(pidfd);
			CloseDescriptor(sockets[0]);
			throw;
		}
		condition_.notify_all();
		return processId;
	}

	void LinuxChildRuntime::Terminate(ProcessId processId)
	{
		std::lock_guard lock(mutex_);
		const auto child = children_.find(processId);
		if (child == children_.end())
			throw std::invalid_argument("process ID is not an active child");
		CloseAcceptedChannel(child->second);
		if (SignalChild(child->second, SIGTERM) != 0 && errno != ESRCH)
			ThrowSystemError("kill child", errno);
	}

	void LinuxChildRuntime::SetExitCallback(ExitCallback callback)
	{
		std::lock_guard lock(mutex_);
		exitCallback_ = std::move(callback);
	}

	ProcessMemorySnapshot LinuxChildRuntime::MemoryUsage()
	{
		ProcessMemorySnapshot snapshot;
		snapshot.metric = ProcessMemoryMetric::ResidentSet;
		if (const auto resident = ResidentBytes(::getpid()))
			snapshot.processes.push_back({0, ProcessRole::Overseer, *resident, *resident});

		// The reaper holds this lock while it calls waitpid and removes a child.
		// Holding it here keeps every /proc PID bound to the recorded child.
		std::lock_guard lock(mutex_);
		for (const auto& [processId, child] : children_)
		{
			if (const auto resident = ResidentBytes(child.pid))
				snapshot.processes.push_back({processId, child.role, *resident, *resident});
		}
		return snapshot;
	}

	std::unique_ptr<ipc::ByteChannel> LinuxChildRuntime::Accept(ProcessId expectedProcess, ProcessRole expectedRole)
	{
		int descriptor = -1;
		pid_t pid = 0;
		{
			std::lock_guard lock(mutex_);
			if (stopping_)
				throw std::runtime_error("child process runtime is stopping");
			const auto child = children_.find(expectedProcess);
			if (child == children_.end() || child->second.role != expectedRole)
				throw std::runtime_error("child channel did not match the expected process and role");
			if (child->second.pendingChannel < 0)
				throw std::runtime_error("child channel was already accepted");
			const int control = ::fcntl(child->second.pendingChannel, F_DUPFD_CLOEXEC, 4);
			if (control < 0)
				ThrowSystemError("duplicate accepted child channel", errno);
			child->second.acceptedControl = control;
			descriptor = std::exchange(child->second.pendingChannel, -1);
			pid = child->second.pid;
		}
		try
		{
			return platform::linux::AcceptChildChannel(descriptor, pid, expectedRole);
		}
		catch (...)
		{
			::close(descriptor);
			try
			{
				Terminate(expectedProcess);
			}
			catch (...)
			{}
			throw;
		}
	}

	void LinuxChildRuntime::ReaperLoop()
	{
		while (true)
		{
			std::vector<std::tuple<ProcessId, ChildRecord, std::optional<int>>> exits;
			{
				std::unique_lock lock(mutex_);
				for (auto child = children_.begin(); child != children_.end();)
				{
					int status = 0;
					pid_t result;
					do
					{
						result = ::waitpid(child->second.pid, &status, WNOHANG);
					} while (result < 0 && errno == EINTR);
					if (result == child->second.pid)
					{
						CloseDescriptor(child->second.pendingChannel);
						CloseDescriptor(child->second.acceptedControl);
						CloseDescriptor(child->second.pidfd);
						exits.emplace_back(child->first, child->second, status);
						child = children_.erase(child);
						continue;
					}
					if (result < 0 && errno == ECHILD)
					{
						CloseDescriptor(child->second.pendingChannel);
						CloseDescriptor(child->second.acceptedControl);
						CloseDescriptor(child->second.pidfd);
						exits.emplace_back(child->first, child->second, std::nullopt);
						child = children_.erase(child);
						continue;
					}
					++child;
				}
				if (stopping_ && children_.empty())
				{
					stoppedCondition_.notify_all();
					lock.unlock();
					for (auto& [processId, child, status] : exits)
						PublishExit(processId, std::move(child), status);
					return;
				}
				if (exits.empty())
					condition_.wait_for(lock, std::chrono::milliseconds(25));
			}
			for (auto& [processId, child, status] : exits)
				PublishExit(processId, std::move(child), status);
		}
	}

	void LinuxChildRuntime::PublishExit(ProcessId processId, ChildRecord child, std::optional<int> status)
	{
		ChildExit exit;
		exit.processId = processId;
		exit.role = child.role;
		if (status && WIFEXITED(*status))
			exit.exitCode = WEXITSTATUS(*status);
		if (status && WIFSIGNALED(*status))
			exit.signal = WTERMSIG(*status);
		ExitCallback callback;
		{
			std::lock_guard lock(mutex_);
			callback = exitCallback_;
		}
		if (callback)
		{
			try
			{
				callback(exit);
			}
			catch (...)
			{}
		}
	}

	std::unique_ptr<ChildProcessRuntime> CreateNativeChildProcessRuntime()
	{
		return std::make_unique<LinuxChildRuntime>();
	}
}  // namespace binjad
