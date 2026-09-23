#include "binjad/security/random.hpp"

#include "platform_random.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <utility>

namespace binjad::security
{
namespace
{
std::string Hex(std::span<const unsigned char> bytes)
{
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string output(bytes.size() * 2, '\0');
    for (std::size_t index = 0; index < bytes.size(); ++index)
    {
        output[index * 2] = alphabet[bytes[index] >> 4];
        output[index * 2 + 1] = alphabet[bytes[index] & 0xf];
    }
    return output;
}

std::string Base64Url(std::span<const unsigned char> bytes)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string output;
    output.reserve((bytes.size() * 4 + 2) / 3);
    std::size_t offset = 0;
    while (offset + 3 <= bytes.size())
    {
        const std::uint32_t value = (static_cast<std::uint32_t>(bytes[offset]) << 16) |
            (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) | bytes[offset + 2];
        output.push_back(alphabet[(value >> 18) & 0x3f]);
        output.push_back(alphabet[(value >> 12) & 0x3f]);
        output.push_back(alphabet[(value >> 6) & 0x3f]);
        output.push_back(alphabet[value & 0x3f]);
        offset += 3;
    }
    if (offset < bytes.size())
    {
        std::uint32_t value = static_cast<std::uint32_t>(bytes[offset]) << 16;
        if (offset + 1 < bytes.size())
            value |= static_cast<std::uint32_t>(bytes[offset + 1]) << 8;
        output.push_back(alphabet[(value >> 18) & 0x3f]);
        output.push_back(alphabet[(value >> 12) & 0x3f]);
        if (offset + 1 < bytes.size())
            output.push_back(alphabet[(value >> 6) & 0x3f]);
    }
    return output;
}

template <typename Encode>
RandomStringResult Generate(Encode encode)
{
    std::array<unsigned char, 32> bytes{};
    if (auto error = FillSecureRandom(bytes); !error.empty())
        return {{}, std::move(error)};
    return {encode(bytes), {}};
}
}

RandomStringResult GenerateHex256()
{
    return Generate([](const auto& bytes) { return Hex(bytes); });
}

RandomStringResult GenerateBase64Url256()
{
    return Generate([](const auto& bytes) { return Base64Url(bytes); });
}
}
