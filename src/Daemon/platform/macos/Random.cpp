#include "../../security/PlatformRandom.hpp"

#include <Security/SecRandom.h>

namespace binjad::security
{
std::string FillSecureRandom(std::span<unsigned char> output)
{
    const auto status = SecRandomCopyBytes(kSecRandomDefault, output.size(), output.data());
    return status == errSecSuccess
        ? std::string{} : "SecRandomCopyBytes failed with status " + std::to_string(status);
}
}
