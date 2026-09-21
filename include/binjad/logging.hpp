#pragma once

#include <string_view>

namespace binjad
{
enum class LogLevel
{
    Debug,
    Info,
    Notice,
    Error,
    Fault,
};

void Log(LogLevel level, std::string_view message);
}
