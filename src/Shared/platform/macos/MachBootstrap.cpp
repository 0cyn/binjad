#include "binjad/platform/macos/MachBootstrap.hpp"

#include "binjad/ipc/Envelope.hpp"
#include "binjad/platform/macos/ProcessSupervisor.hpp"

#include <bootstrap.h>
#include <bsm/libbsm.h>
#include <mach/error.h>
#include <mach/exception_types.h>
#if defined(__arm64__)
	#include <mach/arm/thread_status.h>
#elif defined(__x86_64__)
	#include <mach/i386/thread_status.h>
#endif

#include <cstddef>
#include <cstring>
#include <utility>
#include <vector>

namespace binjad::platform::macos {
	namespace {
		constexpr mach_msg_id_t kBootstrapMessageId = 0x424a4201;

		struct BootstrapRequest
		{
			mach_msg_header_t header;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t channelPort;
			std::uint64_t payloadSize;
			std::uint8_t payload[ipc::kInlinePayloadLimit];
		};

		struct BootstrapReply
		{
			mach_msg_header_t header;
			mach_msg_body_t body;
			mach_msg_port_descriptor_t channelPort;
			mach_msg_port_descriptor_t exceptionPort;
			std::uint64_t payloadSize;
			std::uint8_t payload[ipc::kInlinePayloadLimit];
		};

		[[noreturn]] void ThrowMachError(std::string_view operation, kern_return_t error)
		{
			throw ipc::ChannelError(std::string(operation) + ": " + mach_error_string(error));
		}

		ipc::ChildRole ToWireRole(ProcessRole role)
		{
			switch (role)
			{
			case ProcessRole::FileChild:
				return ipc::CHILD_ROLE_FILE;
			case ProcessRole::ProjectChild:
				return ipc::CHILD_ROLE_PROJECT;
			case ProcessRole::Overseer:
				break;
			}
			throw ipc::ChannelError("overseer cannot register as a child");
		}

		mach_port_t AllocateChannelPort()
		{
			mach_port_t port = MACH_PORT_NULL;
			auto result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
			if (result != KERN_SUCCESS)
				ThrowMachError("mach_port_allocate", result);
			result = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
			if (result != KERN_SUCCESS)
			{
				mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
				ThrowMachError("mach_port_insert_right", result);
			}
			return port;
		}

		mach_port_t AllocateReplyPort()
		{
			mach_port_t port = MACH_PORT_NULL;
			const auto result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
			if (result != KERN_SUCCESS)
				ThrowMachError("mach_port_allocate reply port", result);
			return port;
		}

		void DestroyChannelPort(mach_port_t port)
		{
			if (!MACH_PORT_VALID(port))
				return;
			mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
			mach_port_deallocate(mach_task_self(), port);
		}

		std::vector<std::uint8_t> RegistrationPayload(ProcessRole role, bool accepted)
		{
			ipc::Envelope envelope;
			envelope.set_protocol_version(ipc::kProtocolVersion);
			envelope.set_request_id(1);
			if (accepted)
				envelope.mutable_register_accepted();
			else
				envelope.mutable_register_child()->set_role(ToWireRole(role));
			return ipc::SerializeEnvelope(envelope);
		}

		void FillBootstrapRequest(BootstrapRequest& message, mach_port_t remotePort, mach_port_t localPort,
			mach_msg_type_name_t localDisposition, mach_port_t channelPort, std::span<const std::uint8_t> payload)
		{
			if (payload.size() > ipc::kInlinePayloadLimit)
				throw ipc::ChannelError("bootstrap payload exceeds inline limit");
			message = {};
			message.header.msgh_bits =
				MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, localDisposition);
			message.header.msgh_size =
				static_cast<mach_msg_size_t>(round_msg(offsetof(BootstrapRequest, payload) + payload.size()));
			message.header.msgh_remote_port = remotePort;
			message.header.msgh_local_port = localPort;
			message.header.msgh_id = kBootstrapMessageId;
			message.body.msgh_descriptor_count = 1;
			message.channelPort.name = channelPort;
			message.channelPort.disposition = MACH_MSG_TYPE_COPY_SEND;
			message.channelPort.type = MACH_MSG_PORT_DESCRIPTOR;
			message.payloadSize = payload.size();
			std::memcpy(message.payload, payload.data(), payload.size());
		}

		void FillBootstrapReply(BootstrapReply& message, mach_port_t remotePort, mach_port_t channelPort,
			mach_port_t exceptionPort, std::span<const std::uint8_t> payload)
		{
			if (payload.size() > ipc::kInlinePayloadLimit)
				throw ipc::ChannelError("bootstrap payload exceeds inline limit");
			message = {};
			message.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
			message.header.msgh_size =
				static_cast<mach_msg_size_t>(round_msg(offsetof(BootstrapReply, payload) + payload.size()));
			message.header.msgh_remote_port = remotePort;
			message.header.msgh_id = kBootstrapMessageId;
			message.body.msgh_descriptor_count = 2;
			message.channelPort.name = channelPort;
			message.channelPort.disposition = MACH_MSG_TYPE_COPY_SEND;
			message.channelPort.type = MACH_MSG_PORT_DESCRIPTOR;
			message.exceptionPort.name = exceptionPort;
			message.exceptionPort.disposition = MACH_MSG_TYPE_COPY_SEND;
			message.exceptionPort.type = MACH_MSG_PORT_DESCRIPTOR;
			message.payloadSize = payload.size();
			std::memcpy(message.payload, payload.data(), payload.size());
		}

		ipc::Envelope ParseBootstrapPayload(const BootstrapRequest& message)
		{
			const auto prefix = offsetof(BootstrapRequest, payload);
			if (message.header.msgh_size < prefix || message.payloadSize > ipc::kInlinePayloadLimit
				|| message.header.msgh_size != round_msg(prefix + message.payloadSize)
				|| message.body.msgh_descriptor_count != 1 || message.channelPort.type != MACH_MSG_PORT_DESCRIPTOR)
				throw ipc::ChannelError("invalid Mach bootstrap message");
			return ipc::ParseEnvelope(std::span(message.payload, static_cast<std::size_t>(message.payloadSize)));
		}

		ipc::Envelope ParseBootstrapPayload(const BootstrapReply& message)
		{
			const auto prefix = offsetof(BootstrapReply, payload);
			if (message.header.msgh_size < prefix || message.payloadSize > ipc::kInlinePayloadLimit
				|| message.header.msgh_size != round_msg(prefix + message.payloadSize)
				|| message.body.msgh_descriptor_count != 2 || message.channelPort.type != MACH_MSG_PORT_DESCRIPTOR
				|| message.exceptionPort.type != MACH_MSG_PORT_DESCRIPTOR)
				throw ipc::ChannelError("invalid Mach bootstrap reply");
			return ipc::ParseEnvelope(std::span(message.payload, static_cast<std::size_t>(message.payloadSize)));
		}

		void InstallExceptionPort(mach_port_t exceptionPort)
		{
			const auto exceptionMask = EXC_MASK_BAD_ACCESS | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_ARITHMETIC
				| EXC_MASK_BREAKPOINT | EXC_MASK_CRASH | EXC_MASK_GUARD;
#if defined(__arm64__)
			constexpr thread_state_flavor_t threadStateFlavor = ARM_THREAD_STATE;
#elif defined(__x86_64__)
			constexpr thread_state_flavor_t threadStateFlavor = x86_THREAD_STATE;
#else
	#error Unsupported macOS architecture
#endif
			const auto result = task_set_exception_ports(mach_task_self(), exceptionMask, exceptionPort,
				EXCEPTION_STATE_IDENTITY | MACH_EXCEPTION_CODES, threadStateFlavor);
			if (result != KERN_SUCCESS)
				ThrowMachError("task_set_exception_ports", result);
		}
	}  // namespace

	MachBootstrapServer::MachBootstrapServer(ProcessSupervisor& supervisor, std::string_view serviceName) :
		exceptionPort_(ExceptionPort(supervisor))
	{
		if (serviceName.empty() || serviceName.size() >= BOOTSTRAP_MAX_NAME_LEN)
			throw ipc::ChannelError("invalid launchd Mach service name");
		name_t name {};
		std::memcpy(name, serviceName.data(), serviceName.size());
		const auto result = bootstrap_check_in(bootstrap_port, name, &servicePort_);
		if (result != BOOTSTRAP_SUCCESS)
			throw ipc::ChannelError(std::string("bootstrap_check_in: ") + bootstrap_strerror(result));
	}

	MachBootstrapServer::MachBootstrapServer(MachBootstrapServer&& other) noexcept :
		servicePort_(std::exchange(other.servicePort_, MACH_PORT_NULL)),
		exceptionPort_(std::exchange(other.exceptionPort_, MACH_PORT_NULL))
	{}

	MachBootstrapServer& MachBootstrapServer::operator=(MachBootstrapServer&& other) noexcept
	{
		if (this != &other)
		{
			if (MACH_PORT_VALID(servicePort_))
				mach_port_mod_refs(mach_task_self(), servicePort_, MACH_PORT_RIGHT_RECEIVE, -1);
			servicePort_ = std::exchange(other.servicePort_, MACH_PORT_NULL);
			exceptionPort_ = std::exchange(other.exceptionPort_, MACH_PORT_NULL);
		}
		return *this;
	}

	MachBootstrapServer::~MachBootstrapServer()
	{
		if (MACH_PORT_VALID(servicePort_))
			mach_port_mod_refs(mach_task_self(), servicePort_, MACH_PORT_RIGHT_RECEIVE, -1);
	}

	std::unique_ptr<ipc::ByteChannel> MachBootstrapServer::Accept(ProcessId expectedProcess, ProcessRole expectedRole)
	{
		std::vector<std::uint8_t> storage(sizeof(BootstrapRequest) + MAX_TRAILER_SIZE);
		auto* message = reinterpret_cast<BootstrapRequest*>(storage.data());
		const auto options = MACH_RCV_MSG | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)
			| MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT);
		const auto result = mach_msg(&message->header, options, 0, static_cast<mach_msg_size_t>(storage.size()),
			servicePort_, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
		if (result != MACH_MSG_SUCCESS)
			ThrowMachError("Mach bootstrap receive", result);
		if (message->header.msgh_id != kBootstrapMessageId)
		{
			mach_msg_destroy(&message->header);
			throw ipc::ChannelError("unexpected Mach bootstrap message ID");
		}

		const auto trailerOffset = round_msg(message->header.msgh_size);
		const auto* trailer = reinterpret_cast<const mach_msg_audit_trailer_t*>(storage.data() + trailerOffset);
		if (trailerOffset + sizeof(*trailer) > storage.size() || trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0
			|| trailer->msgh_trailer_size < sizeof(*trailer))
		{
			mach_msg_destroy(&message->header);
			throw ipc::ChannelError("Mach bootstrap message has no valid audit trailer");
		}
		const auto senderPid = audit_token_to_pid(trailer->msgh_audit);
		ipc::Envelope envelope;
		try
		{
			envelope = ParseBootstrapPayload(*message);
		}
		catch (...)
		{
			mach_msg_destroy(&message->header);
			throw;
		}
		if (!envelope.has_register_child() || envelope.request_id() != 1
			|| static_cast<ProcessId>(senderPid) != expectedProcess
			|| envelope.register_child().role() != ToWireRole(expectedRole))
		{
			mach_msg_destroy(&message->header);
			throw ipc::ChannelError("Mach bootstrap child identity did not match the expected spawn");
		}

		const auto parentPort = AllocateChannelPort();
		const auto childPort = message->channelPort.name;
		try
		{
			BootstrapReply reply {};
			const auto payload = RegistrationPayload(expectedRole, true);
			FillBootstrapReply(reply, message->header.msgh_remote_port, parentPort, exceptionPort_, payload);
			const auto sendResult = mach_msg(&reply.header, MACH_SEND_MSG, reply.header.msgh_size, 0, MACH_PORT_NULL,
				MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
			if (sendResult != MACH_MSG_SUCCESS)
				ThrowMachError("Mach bootstrap reply", sendResult);
			mach_port_deallocate(mach_task_self(), parentPort);
			return std::make_unique<MachChannel>(parentPort, childPort);
		}
		catch (...)
		{
			DestroyChannelPort(parentPort);
			mach_port_deallocate(mach_task_self(), childPort);
			throw;
		}
	}

	MachChannel ConnectToOverseer(ProcessRole role, std::string_view serviceName)
	{
		if (role == ProcessRole::Overseer)
			throw ipc::ChannelError("overseer cannot connect as a child");
		if (serviceName.empty() || serviceName.size() >= BOOTSTRAP_MAX_NAME_LEN)
			throw ipc::ChannelError("invalid launchd Mach service name");

		name_t name {};
		std::memcpy(name, serviceName.data(), serviceName.size());
		mach_port_t servicePort = MACH_PORT_NULL;
		auto result = bootstrap_look_up(bootstrap_port, name, &servicePort);
		if (result != BOOTSTRAP_SUCCESS)
			throw ipc::ChannelError(std::string("bootstrap_look_up: ") + bootstrap_strerror(result));

		const auto childPort = AllocateChannelPort();
		const auto replyPort = AllocateReplyPort();
		try
		{
			BootstrapRequest request {};
			const auto payload = RegistrationPayload(role, false);
			FillBootstrapRequest(request, servicePort, replyPort, MACH_MSG_TYPE_MAKE_SEND_ONCE, childPort, payload);
			result = mach_msg(&request.header, MACH_SEND_MSG, request.header.msgh_size, 0, MACH_PORT_NULL,
				MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
			mach_port_deallocate(mach_task_self(), servicePort);
			servicePort = MACH_PORT_NULL;
			if (result != MACH_MSG_SUCCESS)
				ThrowMachError("Mach bootstrap send", result);
			mach_port_deallocate(mach_task_self(), childPort);

			BootstrapReply reply {};
			result = mach_msg(
				&reply.header, MACH_RCV_MSG, 0, sizeof(reply), replyPort, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
			if (result != MACH_MSG_SUCCESS)
				ThrowMachError("Mach bootstrap reply receive", result);
			if (reply.header.msgh_id != kBootstrapMessageId)
			{
				mach_msg_destroy(&reply.header);
				throw ipc::ChannelError("unexpected Mach bootstrap reply ID");
			}
			ipc::Envelope envelope;
			try
			{
				envelope = ParseBootstrapPayload(reply);
			}
			catch (...)
			{
				mach_msg_destroy(&reply.header);
				throw;
			}
			if (!envelope.has_register_accepted() || envelope.request_id() != 1)
			{
				mach_msg_destroy(&reply.header);
				throw ipc::ChannelError("overseer rejected Mach bootstrap registration");
			}
			const auto parentPort = reply.channelPort.name;
			const auto exceptionPort = reply.exceptionPort.name;
			try
			{
				InstallExceptionPort(exceptionPort);
			}
			catch (...)
			{
				mach_msg_destroy(&reply.header);
				throw;
			}
			mach_port_deallocate(mach_task_self(), exceptionPort);
			mach_port_mod_refs(mach_task_self(), replyPort, MACH_PORT_RIGHT_RECEIVE, -1);
			return MachChannel(childPort, parentPort);
		}
		catch (...)
		{
			if (MACH_PORT_VALID(servicePort))
				mach_port_deallocate(mach_task_self(), servicePort);
			if (MACH_PORT_VALID(replyPort))
				mach_port_mod_refs(mach_task_self(), replyPort, MACH_PORT_RIGHT_RECEIVE, -1);
			DestroyChannelPort(childPort);
			throw;
		}
	}
}  // namespace binjad::platform::macos
