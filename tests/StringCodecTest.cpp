#include "binjad/binary_ninja/string_codec.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace
{
using binjad::binary_ninja::DecodeString;
using binjad::binary_ninja::HexBytes;
using binjad::binary_ninja::StringEncodingName;
using binjad::binary_ninja::SliceString;
using binjad::binary_ninja::Utf8Boundaries;

TEST(StringCodecTest, DecodesAsciiWithoutOptionalTruncationMetadata)
{
    const std::string input = "Undefined error %d";
    const auto preview = DecodeString(AsciiString,
        {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()});
    EXPECT_TRUE(preview.decoded);
    EXPECT_EQ(preview.text, input);
    EXPECT_EQ(preview.length, input.size());
    EXPECT_FALSE(preview.truncated);
    EXPECT_STREQ(StringEncodingName(AsciiString), "ascii");
}

TEST(StringCodecTest, HandlesEmptyAndZeroLengthPreviews)
{
    const std::array<std::uint8_t, 0> empty{};
    const auto emptyPreview = DecodeString(AsciiString, empty);
    EXPECT_TRUE(emptyPreview.decoded);
    EXPECT_TRUE(emptyPreview.text.empty());
    EXPECT_EQ(emptyPreview.length, 0U);
    EXPECT_FALSE(emptyPreview.truncated);

    const std::array<std::uint8_t, 3> input{'a', 'b', 'c'};
    const auto zeroPreview = DecodeString(AsciiString, input, 0);
    EXPECT_TRUE(zeroPreview.decoded);
    EXPECT_TRUE(zeroPreview.text.empty());
    EXPECT_EQ(zeroPreview.length, 3U);
    EXPECT_TRUE(zeroPreview.truncated);
}

TEST(StringCodecTest, TruncatesUtf8ByCharactersWithoutSplittingCodepoints)
{
    std::vector<std::uint8_t> input;
    for (std::size_t index = 0; index < 130; ++index)
    {
        input.push_back(0xc3);
        input.push_back(0xa9);
    }
    const auto preview = DecodeString(Utf8String, input);
    EXPECT_TRUE(preview.decoded);
    EXPECT_EQ(preview.length, 130U);
    EXPECT_EQ(preview.text.size(), 256U);
    EXPECT_TRUE(preview.truncated);
    const auto boundaries = Utf8Boundaries(preview.text);
    ASSERT_TRUE(boundaries.has_value());
    EXPECT_EQ(boundaries->size() - 1, 128U);
}

TEST(StringCodecTest, DecodesUtf16SurrogatePairsAndUsesCharacterLimit)
{
    const std::array<std::uint8_t, 8> input{
        0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde, 0x42, 0x00};
    const auto preview = DecodeString(Utf16String, input, 2);
    EXPECT_TRUE(preview.decoded);
    EXPECT_EQ(preview.length, 3U);
    EXPECT_EQ(preview.text, std::string("A\xf0\x9f\x98\x80", 5));
    EXPECT_TRUE(preview.truncated);
    EXPECT_STREQ(StringEncodingName(Utf16String), "utf-16le");
}

TEST(StringCodecTest, DecodesUtf32AndPreservesFullLength)
{
    const std::array<std::uint8_t, 8> input{
        0x42, 0x00, 0x00, 0x00, 0xa9, 0x03, 0x00, 0x00};
    const auto preview = DecodeString(Utf32String, input);
    EXPECT_TRUE(preview.decoded);
    EXPECT_EQ(preview.length, 2U);
    EXPECT_EQ(preview.text, std::string("B\xce\xa9", 3));
    EXPECT_FALSE(preview.truncated);
    EXPECT_STREQ(StringEncodingName(Utf32String), "utf-32le");
}

TEST(StringCodecTest, FallsBackToBoundedRawBytesForMalformedUtf8)
{
    const std::array<std::uint8_t, 4> input{0xf0, 0x28, 0x8c, 0x28};
    const auto preview = DecodeString(Utf8String, input, 3);
    EXPECT_FALSE(preview.decoded);
    EXPECT_EQ(preview.text, "f0288c");
    EXPECT_EQ(preview.length, 4U);
    EXPECT_TRUE(preview.truncated);
}

TEST(StringCodecTest, RejectsInvalidUtf8Forms)
{
    EXPECT_FALSE(Utf8Boundaries(std::string("\xc0\x80", 2)));
    EXPECT_FALSE(Utf8Boundaries(std::string("\xed\xa0\x80", 3)));
    EXPECT_FALSE(Utf8Boundaries(std::string("\xf4\x90\x80\x80", 4)));
    EXPECT_FALSE(Utf8Boundaries(std::string("\xe2\x82", 2)));
}

TEST(StringCodecTest, EncodesRawBytesAsLowercaseHex)
{
    const std::array<std::uint8_t, 4> input{0x00, 0x7f, 0x80, 0xff};
    EXPECT_EQ(HexBytes(input), "007f80ff");
    const auto preview = DecodeString(static_cast<BNStringType>(0xff), input,
        std::numeric_limits<std::size_t>::max());
    EXPECT_FALSE(preview.decoded);
    EXPECT_EQ(preview.text, "007f80ff");
    EXPECT_EQ(StringEncodingName(static_cast<BNStringType>(0xff)), nullptr);
}

TEST(StringCodecTest, SlicesDecodedStringsByUnicodeCharacters)
{
    const std::string input("A\xc3\xa9\xf0\x9f\x98\x80" "B", 8);
    const auto decoded = DecodeString(Utf8String,
        {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()},
        std::numeric_limits<std::size_t>::max());
    const auto middle = SliceString(decoded, {}, 1, 2);
    EXPECT_EQ(middle.text, std::string("\xc3\xa9\xf0\x9f\x98\x80", 6));
    EXPECT_EQ(middle.offset, 1U);
    EXPECT_EQ(middle.count, 2U);
    EXPECT_EQ(middle.total, 4U);
    EXPECT_EQ(middle.nextOffset, 3U);
    EXPECT_TRUE(middle.truncated);

    const auto final = SliceString(decoded, {}, 3, 100);
    EXPECT_EQ(final.text, "B");
    EXPECT_EQ(final.count, 1U);
    EXPECT_FALSE(final.nextOffset.has_value());
    EXPECT_FALSE(final.truncated);

    const auto beyond = SliceString(decoded, {}, 100, 4);
    EXPECT_TRUE(beyond.text.empty());
    EXPECT_EQ(beyond.offset, 4U);
    EXPECT_EQ(beyond.count, 0U);
}

TEST(StringCodecTest, SlicesRawFallbackByBytes)
{
    const std::array<std::uint8_t, 4> input{0x00, 0x7f, 0x80, 0xff};
    const auto decoded = DecodeString(static_cast<BNStringType>(0xff), input,
        std::numeric_limits<std::size_t>::max());
    const auto chunk = SliceString(decoded, input, 1, 2);
    EXPECT_EQ(chunk.text, "7f80");
    EXPECT_EQ(chunk.offset, 1U);
    EXPECT_EQ(chunk.count, 2U);
    EXPECT_EQ(chunk.total, 4U);
    EXPECT_EQ(chunk.nextOffset, 3U);
    EXPECT_TRUE(chunk.truncated);
}
}
