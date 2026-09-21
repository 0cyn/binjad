#include "binjad/security/password.hpp"

#include "platform_random.hpp"

#include <argon2.h>

#include <limits>
#include <vector>

namespace binjad::security
{
namespace
{
std::string Error(int code)
{
    const char* message = argon2_error_message(code);
    return message ? message : "unknown Argon2 error";
}

bool FitsArgonLength(std::size_t size)
{
    return size <= std::numeric_limits<std::uint32_t>::max();
}

bool ValidUtf8(std::string_view value)
{
    for (std::size_t offset = 0; offset < value.size();)
    {
        const auto first = static_cast<unsigned char>(value[offset]);
        std::uint32_t codepoint = 0;
        std::size_t length = 1;
        if (first <= 0x7f)
            codepoint = first;
        else if (first >= 0xc2 && first <= 0xdf)
        {
            codepoint = first & 0x1f;
            length = 2;
        }
        else if (first >= 0xe0 && first <= 0xef)
        {
            codepoint = first & 0x0f;
            length = 3;
        }
        else if (first >= 0xf0 && first <= 0xf4)
        {
            codepoint = first & 0x07;
            length = 4;
        }
        else
            return false;
        if (offset + length > value.size())
            return false;
        for (std::size_t index = 1; index < length; ++index)
        {
            const auto continuation = static_cast<unsigned char>(value[offset + index]);
            if ((continuation & 0xc0) != 0x80)
                return false;
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((length == 3 && codepoint < 0x800) || (length == 4 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff)
            return false;
        offset += length;
    }
    return true;
}
}

PasswordHashResult HashPassword(std::string_view password, const Argon2Profile& profile)
{
    if (!FitsArgonLength(password.size()))
        return {{}, "password is too large for Argon2"};
    if (profile.saltBytes < ARGON2_MIN_SALT_LENGTH || profile.outputBytes < ARGON2_MIN_OUTLEN ||
        profile.memoryKib < ARGON2_MIN_MEMORY || profile.iterations < ARGON2_MIN_TIME ||
        profile.lanes < ARGON2_MIN_LANES)
        return {{}, "Argon2 profile is outside the supported minimums"};

    std::vector<unsigned char> salt(profile.saltBytes);
    if (const auto error = FillSecureRandom(salt); !error.empty())
        return {{}, "cannot generate password salt: " + error};
    const auto encodedLength = argon2_encodedlen(profile.iterations, profile.memoryKib,
        profile.lanes, profile.saltBytes, profile.outputBytes, Argon2_id);
    if (encodedLength == 0)
        return {{}, "cannot determine Argon2 encoded length"};
    std::string encoded(encodedLength, '\0');
    const auto status = argon2id_hash_encoded(profile.iterations, profile.memoryKib,
        profile.lanes, password.data(), password.size(), salt.data(), salt.size(),
        profile.outputBytes, encoded.data(), encoded.size());
    if (status != ARGON2_OK)
        return {{}, Error(status)};
    encoded.resize(std::char_traits<char>::length(encoded.c_str()));
    return {std::move(encoded), {}};
}

PasswordVerifyResult VerifyPassword(std::string_view password, std::string_view encoded)
{
    if (!FitsArgonLength(password.size()) || encoded.find('\0') != std::string_view::npos)
        return {PasswordVerification::Error, "password verifier input is malformed"};
    const std::string terminated(encoded);
    const auto status = argon2id_verify(terminated.c_str(), password.data(), password.size());
    if (status == ARGON2_OK)
        return {PasswordVerification::Match, {}};
    if (status == ARGON2_VERIFY_MISMATCH)
        return {PasswordVerification::Mismatch, {}};
    return {PasswordVerification::Error, Error(status)};
}

bool IsValidPortalPassword(std::string_view password)
{
    return password.size() >= 9 && password.size() <= 1024 && ValidUtf8(password);
}
}
