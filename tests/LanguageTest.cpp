#include "binjad/binary_ninja/language.hpp"

#include <gtest/gtest.h>

TEST(LanguageTest, SelectsRepresentationFromSymbolConvention)
{
    using binjad::binary_ninja::PreferredLanguageForSymbol;
    EXPECT_EQ(PreferredLanguageForSymbol("-[SBHIconManager isEditing]", "").name,
        "Pseudo Objective-C");
    EXPECT_EQ(PreferredLanguageForSymbol("+[Widget factory]", "").name,
        "Pseudo Objective-C");
    EXPECT_EQ(PreferredLanguageForSymbol("crate::module::function", "_RNvCs123_4test" ).name,
        "Pseudo Rust");
    EXPECT_EQ(PreferredLanguageForSymbol("ordinary_function", "_ordinary_function").name,
        "Pseudo C");
}
