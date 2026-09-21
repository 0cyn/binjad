#pragma once

#include "binjad/ipc/channel.hpp"

#include <ipc.pb.h>

#include <atomic>
#include <cstdint>
#include <span>
#include <vector>

namespace binjad::ipc
{
class RequestIdSource
{
  public:
    std::uint64_t Next();

  private:
    std::atomic<std::uint64_t> next_{1};
};

std::vector<std::uint8_t> SerializeEnvelope(const Envelope& envelope);
Envelope ParseEnvelope(std::span<const std::uint8_t> payload);
void SendEnvelope(ByteChannel& channel, const Envelope& envelope);
Envelope ReceiveEnvelope(ByteChannel& channel);
}
