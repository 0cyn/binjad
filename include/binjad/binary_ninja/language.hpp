#pragma once

#include <string_view>

namespace binjad::binary_ninja
{
struct LanguagePreference
{
    std::string_view name;
    std::string_view reason;
};

LanguagePreference PreferredLanguageForSymbol(
    std::string_view shortName, std::string_view rawName);
}
