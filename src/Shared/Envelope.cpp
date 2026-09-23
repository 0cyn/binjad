#include "binjad/ipc/envelope.hpp"

#include <limits>

namespace binjad::ipc
{
std::uint64_t RequestIdSource::Next()
{
    auto value = next_.load(std::memory_order_relaxed);
    while (value != 0 && value != std::numeric_limits<std::uint64_t>::max())
    {
        if (next_.compare_exchange_weak(value, value + 1,
            std::memory_order_relaxed, std::memory_order_relaxed))
            return value;
    }
    throw ChannelError("IPC request ID space exhausted");
}

std::vector<std::uint8_t> SerializeEnvelope(const Envelope& envelope)
{
    if (envelope.protocol_version() != kProtocolVersion)
        throw ChannelError("cannot serialize an unsupported IPC envelope version");
    const auto size = envelope.ByteSizeLong();
    if (size > kMaximumPayloadSize)
        throw ChannelError("IPC envelope exceeds the maximum payload size");
    std::vector<std::uint8_t> payload(size);
    if (!envelope.SerializeToArray(payload.data(), static_cast<int>(payload.size())))
        throw ChannelError("failed to serialize IPC envelope");
    return payload;
}

Envelope ParseEnvelope(std::span<const std::uint8_t> payload)
{
    if (payload.size() > kMaximumPayloadSize || payload.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw ChannelError("IPC payload exceeds the maximum size");
    Envelope envelope;
    if (!envelope.ParseFromArray(payload.data(), static_cast<int>(payload.size())))
        throw ChannelError("invalid IPC Protobuf payload");
    if (envelope.protocol_version() != kProtocolVersion)
        throw ChannelError("unsupported IPC envelope version");
    if (envelope.request_id() == 0 && !envelope.has_event())
        throw ChannelError("IPC request ID zero is reserved for events");
    if (envelope.request_id() != 0 && envelope.has_event())
        throw ChannelError("IPC events must use request ID zero");
    if (envelope.payload_case() == Envelope::PAYLOAD_NOT_SET)
        throw ChannelError("IPC envelope has no payload");
    return envelope;
}

void SendEnvelope(ByteChannel& channel, const Envelope& envelope)
{
    channel.Send(SerializeEnvelope(envelope));
}

Envelope ReceiveEnvelope(ByteChannel& channel)
{
    return ParseEnvelope(channel.Receive());
}
}
