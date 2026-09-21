#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

namespace binjad::ipc
{
inline constexpr std::uint32_t kProtocolVersion = 1;
inline constexpr std::size_t kInlinePayloadLimit = 64 * 1024;
inline constexpr std::size_t kMaximumPayloadSize = 256 * 1024 * 1024;

class ChannelError : public std::runtime_error
{
  public:
    using std::runtime_error::runtime_error;
};

class ByteChannel
{
  public:
    virtual ~ByteChannel() = default;
    virtual void Send(std::span<const std::uint8_t> payload) = 0;
    virtual std::vector<std::uint8_t> Receive() = 0;
    virtual void Close() {}
};
}
