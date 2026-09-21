#include "binjad/binary_ninja/language.hpp"

namespace binjad::binary_ninja
{
LanguagePreference PreferredLanguageForSymbol(
    std::string_view shortName, std::string_view rawName)
{
    if (shortName.starts_with("-[") || shortName.starts_with("+["))
        return {"Pseudo Objective-C", "objective-c-symbol"};
    if (rawName.starts_with("_R") || rawName.starts_with("__R"))
        return {"Pseudo Rust", "rust-symbol"};
    return {"Pseudo C", "default"};
}
}
