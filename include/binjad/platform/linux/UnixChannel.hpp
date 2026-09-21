#pragma once

#include "binjad/ipc/Channel.hpp"
#include "binjad/process/Role.hpp"

#include <atomic>
#include <memory>
#include <mutex>

namespace binjad::platform::linux {
	inline constexpr int kChildChannelDescriptor = 3;

	class UnixChannel final : public ipc::ByteChannel
	{
	public:
		explicit UnixChannel(int descriptor);
		UnixChannel(const UnixChannel&) = delete;
		UnixChannel& operator=(const UnixChannel&) = delete;
		~UnixChannel() override;

		void Send(std::span<const std::uint8_t> payload) override;
		std::vector<std::uint8_t> Receive() override;
		void Close() override;

	private:
		int DuplicateDescriptor();

		int descriptor_ = -1;
		std::mutex stateMutex_;
		std::mutex sendMutex_;
		std::mutex receiveMutex_;
	};

	std::unique_ptr<ipc::ByteChannel> AcceptChildChannel(
		int descriptor, int expectedProcessId, ProcessRole expectedRole);
	std::unique_ptr<ipc::ByteChannel> ConnectToOverseer(ProcessRole role);
}  // namespace binjad::platform::linux
