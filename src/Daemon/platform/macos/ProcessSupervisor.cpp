#include "binjad/process/Supervisor.hpp"

#include "binjad/ipc/Channel.hpp"
#include "binjad/platform/macos/ProcessSupervisor.hpp"

extern "C"
{
#include "mach_excServer.h"
}

#include <mach/error.h>
#include <mach/exception_types.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/mach_traps.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

extern char** environ;

namespace binjad {
	namespace {
		struct ChildRecord
		{
			ProcessRole role;
			std::optional<CrashInfo> crash;
		};

		class NativeProcessSupervisor final : public ProcessSupervisor
		{
		public:
			NativeProcessSupervisor();
			~NativeProcessSupervisor() override;

			ProcessId Spawn(const std::filesystem::path& executable, ProcessRole role) override;
			void Terminate(ProcessId processId) override;
			void SetExitCallback(ExitCallback callback) override;
			mach_port_t ExceptionPort() const { return exceptionPort_; }

			kern_return_t HandleException(mach_port_t thread, mach_port_t task, exception_type_t exception,
				mach_exception_data_t codes, mach_msg_type_number_t codeCount);

		private:
			void ExceptionLoop(std::stop_token stopToken);
			void ReaperLoop(std::stop_token stopToken);
			void PublishExit(pid_t pid, int status);

			mach_port_t exceptionPort_ = MACH_PORT_NULL;
			bool typedExceptionPort_ = false;
			struct sigaction previousSigchldAction_ {};
			bool sigchldActionSet_ = false;
			int kqueue_ = -1;
			std::jthread exceptionThread_;
			std::jthread reaperThread_;
			std::mutex spawnMutex_;
			std::mutex mutex_;
			std::unordered_map<pid_t, ChildRecord> children_;
			ExitCallback exitCallback_;
		};

		std::atomic<NativeProcessSupervisor*> gExceptionSupervisor = nullptr;

		[[noreturn]] void ThrowSystemError(std::string_view operation, int error)
		{
			throw std::runtime_error(std::string(operation) + ": " + std::strerror(error));
		}

		[[noreturn]] void ThrowMachError(std::string_view operation, kern_return_t error)
		{
			throw std::runtime_error(std::string(operation) + ": " + mach_error_string(error));
		}

		pid_t CheckedPid(ProcessId processId)
		{
			if (processId == 0 || processId > static_cast<ProcessId>(std::numeric_limits<pid_t>::max()))
				throw std::invalid_argument("invalid child process ID");
			return static_cast<pid_t>(processId);
		}
	}  // namespace

	extern "C" kern_return_t catch_mach_exception_raise(mach_port_t, mach_port_t thread, mach_port_t task,
		exception_type_t exception, mach_exception_data_t codes, mach_msg_type_number_t codeCount)
	{
		auto* supervisor = gExceptionSupervisor.load(std::memory_order_acquire);
		if (!supervisor)
			return KERN_FAILURE;
		return supervisor->HandleException(thread, task, exception, codes, codeCount);
	}

	extern "C" kern_return_t catch_mach_exception_raise_state(mach_port_t, exception_type_t,
		const mach_exception_data_t, mach_msg_type_number_t, int*, const thread_state_t, mach_msg_type_number_t,
		thread_state_t, mach_msg_type_number_t*)
	{
		return KERN_INVALID_ARGUMENT;
	}

	extern "C" kern_return_t catch_mach_exception_raise_state_identity(mach_port_t, mach_port_t thread,
		mach_port_t task, exception_type_t exception, mach_exception_data_t codes, mach_msg_type_number_t codeCount,
		int*, thread_state_t oldState, mach_msg_type_number_t oldStateCount, thread_state_t newState,
		mach_msg_type_number_t* newStateCount)
	{
		if (oldStateCount > *newStateCount)
			return KERN_INVALID_ARGUMENT;
		std::memcpy(newState, oldState, oldStateCount * sizeof(natural_t));
		*newStateCount = oldStateCount;
		auto* supervisor = gExceptionSupervisor.load(std::memory_order_acquire);
		if (!supervisor)
			return KERN_FAILURE;
		return supervisor->HandleException(thread, task, exception, codes, codeCount);
	}

	NativeProcessSupervisor::NativeProcessSupervisor()
	{
		NativeProcessSupervisor* expected = nullptr;
		if (!gExceptionSupervisor.compare_exchange_strong(
				expected, this, std::memory_order_acq_rel, std::memory_order_acquire))
			throw std::runtime_error("only one native process supervisor may own the exception port");

		try
		{
			mach_port_options_t portOptions {};
			portOptions.flags = MPO_EXCEPTION_PORT | MPO_INSERT_SEND_RIGHT;
			auto result = mach_port_construct(mach_task_self(), &portOptions, 0, &exceptionPort_);
			if (result != KERN_SUCCESS)
			{
				result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &exceptionPort_);
				if (result != KERN_SUCCESS)
					ThrowMachError("allocate exception port", result);
				result =
					mach_port_insert_right(mach_task_self(), exceptionPort_, exceptionPort_, MACH_MSG_TYPE_MAKE_SEND);
				if (result != KERN_SUCCESS)
					ThrowMachError("insert exception port send right", result);
			}
			else
			{
				typedExceptionPort_ = true;
			}

			struct sigaction action {};
			action.sa_handler = SIG_DFL;
			sigemptyset(&action.sa_mask);
			if (sigaction(SIGCHLD, &action, &previousSigchldAction_) != 0)
				ThrowSystemError("sigaction SIGCHLD", errno);
			sigchldActionSet_ = true;

			kqueue_ = kqueue();
			if (kqueue_ < 0)
				ThrowSystemError("kqueue", errno);
			struct kevent wakeEvent;
			EV_SET(&wakeEvent, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, nullptr);
			if (kevent(kqueue_, &wakeEvent, 1, nullptr, 0, nullptr) != 0)
				ThrowSystemError("register kqueue wake event", errno);

			exceptionThread_ = std::jthread([this](std::stop_token token) { ExceptionLoop(token); });
			reaperThread_ = std::jthread([this](std::stop_token token) { ReaperLoop(token); });
		}
		catch (...)
		{
			gExceptionSupervisor.store(nullptr, std::memory_order_release);
			if (MACH_PORT_VALID(exceptionPort_))
			{
				if (typedExceptionPort_)
					mach_port_destruct(mach_task_self(), exceptionPort_, -1, 0);
				else
				{
					mach_port_mod_refs(mach_task_self(), exceptionPort_, MACH_PORT_RIGHT_RECEIVE, -1);
					mach_port_deallocate(mach_task_self(), exceptionPort_);
				}
			}
			if (kqueue_ >= 0)
				close(kqueue_);
			if (sigchldActionSet_)
				sigaction(SIGCHLD, &previousSigchldAction_, nullptr);
			throw;
		}
	}

	NativeProcessSupervisor::~NativeProcessSupervisor()
	{
		reaperThread_.request_stop();
		if (kqueue_ >= 0)
		{
			struct kevent wakeEvent;
			EV_SET(&wakeEvent, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, nullptr);
			kevent(kqueue_, &wakeEvent, 1, nullptr, 0, nullptr);
		}
		exceptionThread_.request_stop();
		if (reaperThread_.joinable())
			reaperThread_.join();
		if (exceptionThread_.joinable())
			exceptionThread_.join();
		gExceptionSupervisor.store(nullptr, std::memory_order_release);
		if (sigchldActionSet_)
			sigaction(SIGCHLD, &previousSigchldAction_, nullptr);
		if (kqueue_ >= 0)
			close(kqueue_);
		if (MACH_PORT_VALID(exceptionPort_))
		{
			if (typedExceptionPort_)
				mach_port_destruct(mach_task_self(), exceptionPort_, -1, 0);
			else
			{
				mach_port_mod_refs(mach_task_self(), exceptionPort_, MACH_PORT_RIGHT_RECEIVE, -1);
				mach_port_deallocate(mach_task_self(), exceptionPort_);
			}
		}
	}

	ProcessId NativeProcessSupervisor::Spawn(const std::filesystem::path& executable, ProcessRole role)
	{
		if (role == ProcessRole::Overseer)
			throw std::invalid_argument("cannot spawn an overseer child");

		posix_spawnattr_t attributes = nullptr;
		posix_spawn_file_actions_t actions = nullptr;
		int result = posix_spawnattr_init(&attributes);
		if (result != 0)
			ThrowSystemError("posix_spawnattr_init", result);
		result = posix_spawn_file_actions_init(&actions);
		if (result != 0)
		{
			posix_spawnattr_destroy(&attributes);
			ThrowSystemError("posix_spawn_file_actions_init", result);
		}

		auto cleanup = [&] {
			posix_spawn_file_actions_destroy(&actions);
			posix_spawnattr_destroy(&attributes);
		};
		sigset_t childMask;
		sigemptyset(&childMask);
		short flags = POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_CLOEXEC_DEFAULT;
		if ((result = posix_spawnattr_setsigmask(&attributes, &childMask)) != 0
			|| (result = posix_spawnattr_setflags(&attributes, flags)) != 0)
		{
			cleanup();
			ThrowSystemError("configure posix_spawn attributes", result);
		}
		for (int descriptor = 0; descriptor <= 2; ++descriptor)
		{
			result = posix_spawn_file_actions_addinherit_np(&actions, descriptor);
			if (result != 0)
			{
				cleanup();
				ThrowSystemError("posix_spawn_file_actions_addinherit_np", result);
			}
		}

		std::string executableString = executable.string();
		std::string childName(ChildArgv0(role));
		char* arguments[] = {childName.data(), nullptr};
		pid_t pid = 0;
		{
			std::lock_guard spawnLock(spawnMutex_);
			result = posix_spawn(&pid, executableString.c_str(), &actions, &attributes, arguments, environ);
			cleanup();
			if (result != 0)
				ThrowSystemError("posix_spawn", result);
			std::lock_guard lock(mutex_);
			children_.emplace(pid, ChildRecord {role, std::nullopt});
			struct kevent childEvent;
			EV_SET(&childEvent, static_cast<uintptr_t>(pid), EVFILT_PROC, EV_ADD | EV_ENABLE | EV_ONESHOT, NOTE_EXIT, 0,
				nullptr);
			if (kevent(kqueue_, &childEvent, 1, nullptr, 0, nullptr) != 0)
			{
				const auto error = errno;
				children_.erase(pid);
				kill(pid, SIGKILL);
				ThrowSystemError("register child process event", error);
			}
		}
		return static_cast<ProcessId>(pid);
	}

	void NativeProcessSupervisor::Terminate(ProcessId processId)
	{
		const auto pid = CheckedPid(processId);
		std::lock_guard lock(mutex_);
		if (!children_.contains(pid))
			throw std::invalid_argument("process ID is not an active child");
		if (kill(pid, SIGTERM) != 0 && errno != ESRCH)
			ThrowSystemError("kill child", errno);
	}

	void NativeProcessSupervisor::SetExitCallback(ExitCallback callback)
	{
		std::lock_guard lock(mutex_);
		exitCallback_ = std::move(callback);
	}

	kern_return_t NativeProcessSupervisor::HandleException(mach_port_t thread, mach_port_t task,
		exception_type_t exception, mach_exception_data_t codes, mach_msg_type_number_t codeCount)
	{
		pid_t pid = 0;
		const auto pidResult = pid_for_task(task, &pid);
		if (pidResult == KERN_SUCCESS)
		{
			CrashInfo crash;
			crash.exception = exception;
			crash.codes.assign(codes, codes + codeCount);
			std::lock_guard lock(mutex_);
			if (const auto child = children_.find(pid); child != children_.end())
				child->second.crash = std::move(crash);
		}
		task_terminate(task);
		mach_port_deallocate(mach_task_self(), thread);
		mach_port_deallocate(mach_task_self(), task);
		return KERN_SUCCESS;
	}

	void NativeProcessSupervisor::ExceptionLoop(std::stop_token stopToken)
	{
		const auto messageSize = catch_mach_exc_subsystem.maxsize + MAX_TRAILER_SIZE;
		std::vector<std::uint8_t> requestStorage(messageSize);
		std::vector<std::uint8_t> replyStorage(messageSize);
		while (!stopToken.stop_requested())
		{
			auto* request = reinterpret_cast<mach_msg_header_t*>(requestStorage.data());
			auto* reply = reinterpret_cast<mach_msg_header_t*>(replyStorage.data());
			const auto result = mach_msg(request, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0,
				static_cast<mach_msg_size_t>(requestStorage.size()), exceptionPort_, 100, MACH_PORT_NULL);
			if (result == MACH_RCV_TIMED_OUT)
				continue;
			if (result != MACH_MSG_SUCCESS)
				continue;
			if (!mach_exc_server(request, reply))
			{
				mach_msg_destroy(request);
				continue;
			}
			if (MACH_PORT_VALID(reply->msgh_remote_port))
				mach_msg(
					reply, MACH_SEND_MSG, reply->msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		}
	}

	void NativeProcessSupervisor::ReaperLoop(std::stop_token stopToken)
	{
		while (!stopToken.stop_requested())
		{
			struct kevent event;
			const auto result = kevent(kqueue_, nullptr, 0, &event, 1, nullptr);
			if (result < 0 && errno == EINTR)
				continue;
			if (result <= 0)
				continue;
			if (event.filter == EVFILT_USER || stopToken.stop_requested())
				break;
			if (event.filter != EVFILT_PROC || (event.fflags & NOTE_EXIT) == 0)
				continue;

			const auto pid = static_cast<pid_t>(event.ident);
			int status = 0;
			pid_t waited;
			do
			{
				waited = waitpid(pid, &status, 0);
			} while (waited < 0 && errno == EINTR);
			if (waited != pid)
				continue;
			PublishExit(pid, status);
		}
	}

	void NativeProcessSupervisor::PublishExit(pid_t pid, int status)
	{
		ChildExit exit;
		ExitCallback callback;
		{
			std::lock_guard lock(mutex_);
			const auto child = children_.find(pid);
			if (child == children_.end())
				return;
			exit.processId = static_cast<ProcessId>(pid);
			exit.role = child->second.role;
			exit.crash = std::move(child->second.crash);
			children_.erase(child);
			callback = exitCallback_;
		}
		if (WIFEXITED(status))
			exit.exitCode = WEXITSTATUS(status);
		if (WIFSIGNALED(status))
			exit.signal = WTERMSIG(status);
		if (callback)
			callback(exit);
	}

	std::unique_ptr<ProcessSupervisor> CreateNativeProcessSupervisor()
	{
		return std::make_unique<NativeProcessSupervisor>();
	}

	namespace platform::macos {
		mach_port_t ExceptionPort(ProcessSupervisor& supervisor)
		{
			auto* native = dynamic_cast<NativeProcessSupervisor*>(&supervisor);
			if (!native)
				throw std::invalid_argument("process supervisor is not the macOS implementation");
			return native->ExceptionPort();
		}
	}  // namespace platform::macos
}  // namespace binjad
