#pragma once

#include <binaryninjacore.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace binjad::binary_ninja
{
struct StringPreview
{
    bool decoded;
    std::string text;
    std::size_t length;
    bool truncated;
};

struct StringChunk
{
    std::string text;
    std::size_t offset;
    std::size_t count;
    std::size_t total;
    std::optional<std::size_t> nextOffset;
    bool truncated;
};

std::optional<std::vector<std::size_t>> Utf8Boundaries(std::string_view text);
std::string HexBytes(std::span<const std::uint8_t> bytes);
StringPreview DecodeString(BNStringType type, std::span<const std::uint8_t> bytes,
    std::size_t maxCharacters = 128);
StringChunk SliceString(const StringPreview& decoded, std::span<const std::uint8_t> bytes,
    std::size_t offset, std::size_t limit);
const char* StringEncodingName(BNStringType type);
}
