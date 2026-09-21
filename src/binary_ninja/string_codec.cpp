#include "binjad/binary_ninja/string_codec.hpp"

#include <base/unicode.h>

#include <algorithm>
#include <utility>

namespace binjad::binary_ninja
{
std::optional<std::vector<std::size_t>> Utf8Boundaries(std::string_view text)
{
    std::vector<std::size_t> boundaries{0};
    for (std::size_t offset = 0; offset < text.size();)
    {
        const auto first = static_cast<unsigned char>(text[offset]);
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        if (first < 0x80) { length = 1; codepoint = first; }
        else if ((first & 0xe0) == 0xc0) { length = 2; codepoint = first & 0x1f; }
        else if ((first & 0xf0) == 0xe0) { length = 3; codepoint = first & 0x0f; }
        else if ((first & 0xf8) == 0xf0) { length = 4; codepoint = first & 0x07; }
        else return std::nullopt;
        if (offset + length > text.size())
            return std::nullopt;
        for (std::size_t index = 1; index < length; ++index)
        {
            const auto next = static_cast<unsigned char>(text[offset + index]);
            if ((next & 0xc0) != 0x80)
                return std::nullopt;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((length == 2 && codepoint < 0x80) ||
            (length == 3 && codepoint < 0x800) ||
            (length == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return std::nullopt;
        offset += length;
        boundaries.push_back(offset);
    }
    return boundaries;
}

std::string HexBytes(std::span<const std::uint8_t> bytes)
{
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.resize(bytes.size() * 2);
    for (std::size_t index = 0; index < bytes.size(); ++index)
    {
        result[index * 2] = hex[bytes[index] >> 4];
        result[index * 2 + 1] = hex[bytes[index] & 0xf];
    }
    return result;
}

StringPreview DecodeString(BNStringType type, std::span<const std::uint8_t> bytes,
    std::size_t maxCharacters)
{
    std::string decoded;
    if (type == AsciiString || type == Utf8String)
        decoded.assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    else if (type == Utf16String)
        decoded = bn::base::UTF16ToUTF8<std::string>(bytes);
    else if (type == Utf32String)
        decoded = bn::base::UTF32ToUTF8<std::string>(bytes);
    else
    {
        const auto count = std::min(maxCharacters, bytes.size());
        return {false, HexBytes(bytes.first(count)), bytes.size(), bytes.size() > count};
    }
    const auto boundaries = Utf8Boundaries(decoded);
    if (!boundaries)
    {
        const auto count = std::min(maxCharacters, bytes.size());
        return {false, HexBytes(bytes.first(count)), bytes.size(), bytes.size() > count};
    }
    const auto characterCount = boundaries->size() - 1;
    if (characterCount <= maxCharacters)
        return {true, std::move(decoded), characterCount, false};
    return {true, decoded.substr(0, (*boundaries)[maxCharacters]), characterCount, true};
}

StringChunk SliceString(const StringPreview& decoded, std::span<const std::uint8_t> bytes,
    std::size_t offset, std::size_t limit)
{
    StringChunk result;
    if (decoded.decoded)
    {
        const auto boundaries = Utf8Boundaries(decoded.text);
        if (!boundaries)
            return result;
        result.total = boundaries->size() - 1;
        result.offset = std::min(offset, result.total);
        const auto finish = result.offset + std::min(limit, result.total - result.offset);
        result.count = finish - result.offset;
        result.text = decoded.text.substr((*boundaries)[result.offset],
            (*boundaries)[finish] - (*boundaries)[result.offset]);
        if (finish < result.total)
            result.nextOffset = finish;
    }
    else
    {
        result.total = bytes.size();
        result.offset = std::min(offset, result.total);
        const auto finish = result.offset + std::min(limit, result.total - result.offset);
        result.count = finish - result.offset;
        result.text = HexBytes(bytes.subspan(result.offset, result.count));
        if (finish < result.total)
            result.nextOffset = finish;
    }
    result.truncated = result.nextOffset.has_value();
    return result;
}

const char* StringEncodingName(BNStringType type)
{
    switch (type)
    {
        case AsciiString: return "ascii";
        case Utf8String: return "utf-8";
        case Utf16String: return "utf-16le";
        case Utf32String: return "utf-32le";
    }
    return nullptr;
}
}
