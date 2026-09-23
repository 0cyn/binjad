#include <cstdint>

extern "C" {
volatile std::int32_t binjad_fixture_sink = 0;
extern const char binjad_fixture_message[] = "binjad-analysis-fixture-marker";
extern const char binjad_fixture_long_message[] =
    "binjad-long-string-"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
extern const char binjad_fixture_utf8_message[] =
    "binjad-utf8-\xc3\xa9-\xf0\x9f\x98\x80";
extern const char binjad_fixture_short_message[] = "udf";

__attribute__((noinline, used)) std::int32_t binjad_fixture_helper(std::int32_t value)
{
    if (value < 0)
        return -1;
    if (value == 7)
        return 42;
    return value + 3;
}
}

int main(int argc, char**)
{
    binjad_fixture_sink = binjad_fixture_helper(argc);
    const auto index = binjad_fixture_sink & 1;
    return binjad_fixture_message[index] == '\0' ||
        binjad_fixture_long_message[index] == '\0' ||
        binjad_fixture_utf8_message[index] == '\0';
}
