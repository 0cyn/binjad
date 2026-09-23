#pragma once

#include <span>
#include <string>

namespace binjad::security
{
std::string FillSecureRandom(std::span<unsigned char> output);
}
