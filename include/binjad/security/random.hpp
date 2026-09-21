#pragma once

#include <optional>
#include <string>

namespace binjad::security
{
struct RandomStringResult
{
    std::optional<std::string> value;
    std::string error;
};

RandomStringResult GenerateHex256();
RandomStringResult GenerateBase64Url256();
}
