#include "binjad/platform/linux/UnixChannel.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <optional>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace binjad::platform::linux {
	namespace {
		constexpr std::array<std::uint8_t, 4> kRegistrationMagic {'B', 'J', 'U', '1'};
		constexpr std::size_t kRegistrationSize = 8;
		constexpr std::size_t kReceiveQuota = 512 * 1024 * 1024;
		constexpr auto kFrameIdleTimeout = std::chrono::seconds(30);
		std::atomic<std::size_t> gInFlightReceiveBytes {0};

		class Descriptor
		{
		public:
			explicit Descriptor(int value) : value_(value) {}
			Descriptor(const Descriptor&) = delete;
			Descriptor& operator=(const Descriptor&) = delete;
			~Descriptor()
			{
				if (value_ >= 0)
					::close(value_);
			}
			int Get() const { return value_; }

		private:
			int value_;
		};

		class ReceiveReservation
		{
		public:
			explicit ReceiveReservation(std::size_t size) : size_(size)
			{
				auto current = gInFlightReceiveBytes.load(std::memory_order_relaxed);
				while (true)
				{
					if (size > kReceiveQuota - current)
						throw ipc::ChannelError("Unix channel receive quota exceeded");
					if (gInFlightReceiveBytes.compare_exchange_weak(
							current, current + size, std::memory_order_acq_rel, std::memory_order_relaxed))
						break;
				}
			}
			~ReceiveReservation() { gInFlightReceiveBytes.fetch_sub(size_, std::memory_order_acq_rel); }

		private:
			std::size_t size_;
		};

		[[noreturn]] void ThrowSocketError(std::string_view operation)
		{
			throw ipc::ChannelError(std::string(operation) + ": " + std::strerror(errno));
		}

		std::uint32_t WireRole(ProcessRole role)
		{
			switch (role)
			{
			case ProcessRole::FileChild:
				return 1;
			case ProcessRole::ProjectChild:
				return 2;
			case ProcessRole::Overseer:
				break;
			}
			throw ipc::ChannelError("overseer cannot use a child channel");
		}

		void WaitReadable(int descriptor)
		{
			pollfd event {descriptor, POLLIN, 0};
			while (true)
			{
				const auto result = ::poll(&event, 1, static_cast<int>(kFrameIdleTimeout.count() * 1000));
				if (result > 0)
				{
					if ((event.revents & (POLLERR | POLLNVAL)) != 0)
						throw ipc::ChannelError("Unix channel failed while receiving a frame");
					return;
				}
				if (result == 0)
					throw ipc::ChannelError("Unix channel frame receive timed out");
				if (errno != EINTR)
					ThrowSocketError("poll Unix channel");
			}
		}

		void SendAll(int descriptor, std::span<const std::uint8_t> bytes)
		{
			while (!bytes.empty())
			{
				const auto count = ::send(descriptor, bytes.data(), bytes.size(), MSG_NOSIGNAL);
				if (count > 0)
				{
					bytes = bytes.subspan(static_cast<std::size_t>(count));
					continue;
				}
				if (count < 0 && errno == EINTR)
					continue;
				if (count == 0)
					errno = EPIPE;
				ThrowSocketError("send Unix channel frame");
			}
		}

		void ReceiveExact(
			int descriptor, std::span<std::uint8_t> bytes, bool allowCleanEof, bool waitBeforeFirstByte = false)
		{
			bool receivedAny = false;
			while (!bytes.empty())
			{
				if (receivedAny || waitBeforeFirstByte)
					WaitReadable(descriptor);
				waitBeforeFirstByte = false;
				const auto count = ::recv(descriptor, bytes.data(), bytes.size(), 0);
				if (count > 0)
				{
					receivedAny = true;
					bytes = bytes.subspan(static_cast<std::size_t>(count));
					continue;
				}
				if (count < 0 && errno == EINTR)
					continue;
				if (count == 0)
				{
					if (allowCleanEof && !receivedAny)
						throw ipc::ChannelError("Unix channel is closed");
					throw ipc::ChannelError("Unix channel received a truncated frame");
				}
				ThrowSocketError("receive Unix channel frame");
			}
		}

		std::array<std::uint8_t, 8> EncodeSize(std::size_t size)
		{
			std::array<std::uint8_t, 8> bytes {};
			for (std::size_t index = 0; index < bytes.size(); ++index)
				bytes[index] = static_cast<std::uint8_t>((static_cast<std::uint64_t>(size) >> (index * 8)) & 0xff);
			return bytes;
		}

		std::uint64_t DecodeSize(const std::array<std::uint8_t, 8>& bytes)
		{
			std::uint64_t size = 0;
			for (std::size_t index = 0; index < bytes.size(); ++index)
				size |= static_cast<std::uint64_t>(bytes[index]) << (index * 8);
			return size;
		}

		std::array<std::uint8_t, kRegistrationSize> Registration(ProcessRole role)
		{
			std::array<std::uint8_t, kRegistrationSize> result {};
			std::copy(kRegistrationMagic.begin(), kRegistrationMagic.end(), result.begin());
			const auto wireRole = WireRole(role);
			for (std::size_t index = 0; index < 4; ++index)
				result[4 + index] = static_cast<std::uint8_t>((wireRole >> (index * 8)) & 0xff);
			return result;
		}
	}  // namespace

	UnixChannel::UnixChannel(int descriptor) : descriptor_(descriptor)
	{
		if (descriptor < 0)
			throw ipc::ChannelError("Unix channel requires a valid descriptor");
	}

	UnixChannel::~UnixChannel()
	{
		Close();
	}

	int UnixChannel::DuplicateDescriptor()
	{
		std::lock_guard lock(stateMutex_);
		if (descriptor_ < 0)
			throw ipc::ChannelError("Unix channel is closed");
		const int duplicate = ::fcntl(descriptor_, F_DUPFD_CLOEXEC, 4);
		if (duplicate < 0)
			ThrowSocketError("duplicate Unix channel descriptor");
		return duplicate;
	}

	void UnixChannel::Send(std::span<const std::uint8_t> payload)
	{
		if (payload.size() > ipc::kMaximumPayloadSize)
			throw ipc::ChannelError("Unix channel payload exceeds maximum size");
		std::lock_guard lock(sendMutex_);
		Descriptor descriptor(DuplicateDescriptor());
		const auto size = EncodeSize(payload.size());
		SendAll(descriptor.Get(), size);
		SendAll(descriptor.Get(), payload);
	}

	std::vector<std::uint8_t> UnixChannel::Receive()
	{
		std::lock_guard lock(receiveMutex_);
		try
		{
			Descriptor descriptor(DuplicateDescriptor());
			std::array<std::uint8_t, 8> encodedSize {};
			ReceiveExact(descriptor.Get(), encodedSize, true);
			const auto wireSize = DecodeSize(encodedSize);
			if (wireSize > ipc::kMaximumPayloadSize || wireSize > std::numeric_limits<std::size_t>::max())
				throw ipc::ChannelError("Unix channel payload exceeds maximum size");
			const auto size = static_cast<std::size_t>(wireSize);
			ReceiveReservation reservation(size);
			std::vector<std::uint8_t> payload(size);
			ReceiveExact(descriptor.Get(), payload, false, true);
			return payload;
		}
		catch (...)
		{
			Close();
			throw;
		}
	}

	void UnixChannel::Close()
	{
		int descriptor = -1;
		{
			std::lock_guard lock(stateMutex_);
			descriptor = std::exchange(descriptor_, -1);
		}
		if (descriptor >= 0)
		{
			::shutdown(descriptor, SHUT_RDWR);
			::close(descriptor);
		}
	}

	std::unique_ptr<ipc::ByteChannel> AcceptChildChannel(
		int descriptor, int expectedProcessId, ProcessRole expectedRole)
	{
		pollfd event {descriptor, POLLIN, 0};
		int result;
		do
		{
			result = ::poll(&event, 1, 5000);
		} while (result < 0 && errno == EINTR);
		if (result <= 0)
			throw ipc::ChannelError(result == 0 ?
					"child channel registration timed out" :
					"cannot poll child channel registration: " + std::string(std::strerror(errno)));

		std::array<std::uint8_t, kRegistrationSize> registration {};
		alignas(cmsghdr) std::array<std::byte, CMSG_SPACE(sizeof(ucred))> control {};
		iovec bytes {registration.data(), registration.size()};
		msghdr message {};
		message.msg_iov = &bytes;
		message.msg_iovlen = 1;
		message.msg_control = control.data();
		message.msg_controllen = control.size();
		timeval timeout {5, 0};
		if (::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
			ThrowSocketError("set child registration timeout");
		do
		{
			result = static_cast<int>(::recvmsg(descriptor, &message, MSG_WAITALL | MSG_CMSG_CLOEXEC));
		} while (result < 0 && errno == EINTR);
		timeout = {};
		if (::setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
			ThrowSocketError("clear child registration timeout");
		if (result != static_cast<int>(registration.size()) || (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0)
			throw ipc::ChannelError("invalid child channel registration");

		std::optional<ucred> credentials;
		for (auto* header = CMSG_FIRSTHDR(&message); header; header = CMSG_NXTHDR(&message, header))
		{
			if (header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_CREDENTIALS
				|| header->cmsg_len != CMSG_LEN(sizeof(ucred)) || credentials)
				throw ipc::ChannelError("invalid child channel credentials");
			ucred value {};
			std::memcpy(&value, CMSG_DATA(header), sizeof(value));
			credentials = value;
		}
		if (!credentials || credentials->pid != expectedProcessId || credentials->uid != ::geteuid())
			throw ipc::ChannelError("child channel peer identity did not match the expected spawn");
		if (!std::equal(kRegistrationMagic.begin(), kRegistrationMagic.end(), registration.begin()))
			throw ipc::ChannelError("invalid child channel registration magic");
		std::uint32_t role = 0;
		for (std::size_t index = 0; index < 4; ++index)
			role |= static_cast<std::uint32_t>(registration[4 + index]) << (index * 8);
		if (role != WireRole(expectedRole))
			throw ipc::ChannelError("child channel role did not match the expected spawn");
		return std::make_unique<UnixChannel>(descriptor);
	}

	std::unique_ptr<ipc::ByteChannel> ConnectToOverseer(ProcessRole role)
	{
		const int descriptor = kChildChannelDescriptor;
		int type = 0;
		socklen_t typeSize = sizeof(type);
		if (::getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &typeSize) != 0 || type != SOCK_STREAM)
			throw ipc::ChannelError("inherited child channel descriptor is not a stream socket");

		ucred credentials {};
		socklen_t credentialSize = sizeof(credentials);
		if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &credentialSize) != 0
			|| credentialSize != sizeof(credentials) || credentials.pid != ::getppid()
			|| credentials.uid != ::geteuid())
			throw ipc::ChannelError("inherited child channel has an unexpected parent");
		const auto flags = ::fcntl(descriptor, F_GETFD);
		if (flags < 0 || ::fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0)
			ThrowSocketError("set close-on-exec on child channel");
		const auto registration = Registration(role);
		SendAll(descriptor, registration);
		return std::make_unique<UnixChannel>(descriptor);
	}
}  // namespace binjad::platform::linux
