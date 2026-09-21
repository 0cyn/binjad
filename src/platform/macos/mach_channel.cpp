#include "binjad/platform/macos/mach_channel.hpp"

#include <mach/error.h>
#include <mach/mach_vm.h>

#include <cstring>
#include <string>

namespace binjad::platform::macos
{
namespace
{
constexpr mach_msg_id_t kChannelMessageId = 0x424a4401;

struct OolMessage
{
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t payload;
    std::uint64_t payloadSize;
};

[[noreturn]] void ThrowMachError(std::string_view operation, kern_return_t error)
{
    throw ipc::ChannelError(std::string(operation) + ": " + mach_error_string(error));
}

mach_port_t AllocateReceivePort()
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
}

MachChannel::MachChannel(mach_port_t receivePort, mach_port_t sendPort) :
    receivePort_(receivePort), sendPort_(sendPort)
{
    if (!MACH_PORT_VALID(receivePort) || !MACH_PORT_VALID(sendPort))
        throw ipc::ChannelError("Mach channel requires valid receive and send ports");
}

MachChannel::MachChannel(MachChannel&& other) noexcept :
    receivePort_(other.receivePort_.exchange(MACH_PORT_NULL)),
    sendPort_(other.sendPort_.exchange(MACH_PORT_NULL))
{}

MachChannel& MachChannel::operator=(MachChannel&& other) noexcept
{
    if (this != &other)
    {
        Reset();
        receivePort_.store(other.receivePort_.exchange(MACH_PORT_NULL));
        sendPort_.store(other.sendPort_.exchange(MACH_PORT_NULL));
    }
    return *this;
}

MachChannel::~MachChannel()
{
    Reset();
}

void MachChannel::Reset()
{
    const auto receivePort = receivePort_.exchange(MACH_PORT_NULL);
    const auto sendPort = sendPort_.exchange(MACH_PORT_NULL);
    if (MACH_PORT_VALID(receivePort))
        mach_port_mod_refs(mach_task_self(), receivePort, MACH_PORT_RIGHT_RECEIVE, -1);
    if (MACH_PORT_VALID(sendPort))
        mach_port_deallocate(mach_task_self(), sendPort);
}

void MachChannel::Close()
{
    Reset();
}

void MachChannel::Send(std::span<const std::uint8_t> payload)
{
    if (payload.size() > ipc::kMaximumPayloadSize)
        throw ipc::ChannelError("Mach channel payload exceeds maximum size");

    const auto sendPort = sendPort_.load();
    if (!MACH_PORT_VALID(sendPort))
        throw ipc::ChannelError("Mach channel is closed");
    mach_msg_return_t result;
    if (payload.size() <= ipc::kInlinePayloadLimit)
    {
        const auto wireSize = sizeof(mach_msg_header_t) + sizeof(std::uint64_t) + payload.size();
        const auto messageSize = round_msg(wireSize);
        std::vector<std::uint8_t> storage(messageSize);
        auto* header = reinterpret_cast<mach_msg_header_t*>(storage.data());
        header->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        header->msgh_size = static_cast<mach_msg_size_t>(messageSize);
        header->msgh_remote_port = sendPort;
        header->msgh_local_port = MACH_PORT_NULL;
        header->msgh_voucher_port = MACH_PORT_NULL;
        header->msgh_id = kChannelMessageId;
        const auto payloadSize = static_cast<std::uint64_t>(payload.size());
        std::memcpy(storage.data() + sizeof(mach_msg_header_t), &payloadSize, sizeof(payloadSize));
        std::memcpy(storage.data() + sizeof(mach_msg_header_t) + sizeof(payloadSize),
            payload.data(), payload.size());
        result = mach_msg(header, MACH_SEND_MSG, header->msgh_size, 0,
            MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    else
    {
        OolMessage message{};
        message.header.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
        message.header.msgh_size = sizeof(message);
        message.header.msgh_remote_port = sendPort;
        message.header.msgh_id = kChannelMessageId;
        message.body.msgh_descriptor_count = 1;
        message.payload.address = const_cast<std::uint8_t*>(payload.data());
        message.payload.size = static_cast<mach_msg_size_t>(payload.size());
        message.payload.deallocate = false;
        message.payload.copy = MACH_MSG_VIRTUAL_COPY;
        message.payload.type = MACH_MSG_OOL_DESCRIPTOR;
        message.payloadSize = payload.size();
        result = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0,
            MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    }
    if (result != MACH_MSG_SUCCESS)
        ThrowMachError("mach_msg send", result);
}

std::vector<std::uint8_t> MachChannel::Receive()
{
    const auto receivePort = receivePort_.load();
    if (!MACH_PORT_VALID(receivePort))
        throw ipc::ChannelError("Mach channel is closed");
    const auto capacity = sizeof(mach_msg_header_t) + sizeof(std::uint64_t) +
        ipc::kInlinePayloadLimit + MAX_TRAILER_SIZE;
    std::vector<std::uint8_t> storage(capacity);
    auto* header = reinterpret_cast<mach_msg_header_t*>(storage.data());
    const auto result = mach_msg(header, MACH_RCV_MSG | MACH_RCV_LARGE, 0,
        static_cast<mach_msg_size_t>(storage.size()), receivePort,
        MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if (result != MACH_MSG_SUCCESS)
        ThrowMachError("mach_msg receive", result);
    if (header->msgh_id != kChannelMessageId)
    {
        mach_msg_destroy(header);
        throw ipc::ChannelError("Mach channel received an unexpected message ID");
    }

    if ((header->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0)
    {
        if (header->msgh_size < sizeof(OolMessage))
        {
            mach_msg_destroy(header);
            throw ipc::ChannelError("truncated Mach OOL message");
        }
        auto* message = reinterpret_cast<OolMessage*>(header);
        if (message->body.msgh_descriptor_count != 1 ||
            message->payload.type != MACH_MSG_OOL_DESCRIPTOR ||
            message->payloadSize != message->payload.size ||
            message->payloadSize <= ipc::kInlinePayloadLimit ||
            message->payloadSize > ipc::kMaximumPayloadSize)
        {
            mach_msg_destroy(header);
            throw ipc::ChannelError("invalid Mach OOL payload descriptor");
        }
        const auto* bytes = static_cast<const std::uint8_t*>(message->payload.address);
        std::vector<std::uint8_t> payload(bytes, bytes + message->payloadSize);
        mach_vm_deallocate(mach_task_self(),
            reinterpret_cast<mach_vm_address_t>(message->payload.address), message->payload.size);
        message->payload.address = nullptr;
        message->payload.size = 0;
        return payload;
    }

    constexpr auto prefixSize = sizeof(mach_msg_header_t) + sizeof(std::uint64_t);
    if (header->msgh_size < prefixSize)
        throw ipc::ChannelError("truncated inline Mach message");
    std::uint64_t payloadSize = 0;
    std::memcpy(&payloadSize, storage.data() + sizeof(mach_msg_header_t), sizeof(payloadSize));
    if (payloadSize > ipc::kInlinePayloadLimit ||
        header->msgh_size != round_msg(prefixSize + payloadSize))
        throw ipc::ChannelError("invalid inline Mach payload size");
    const auto* payload = storage.data() + prefixSize;
    return {payload, payload + payloadSize};
}

std::pair<MachChannel, MachChannel> CreateMachChannelPair()
{
    const auto first = AllocateReceivePort();
    mach_port_t second = MACH_PORT_NULL;
    try
    {
        second = AllocateReceivePort();
        return {MachChannel(first, second), MachChannel(second, first)};
    }
    catch (...)
    {
        if (MACH_PORT_VALID(second))
        {
            mach_port_mod_refs(mach_task_self(), second, MACH_PORT_RIGHT_RECEIVE, -1);
            mach_port_deallocate(mach_task_self(), second);
        }
        mach_port_mod_refs(mach_task_self(), first, MACH_PORT_RIGHT_RECEIVE, -1);
        mach_port_deallocate(mach_task_self(), first);
        throw;
    }
}
}
