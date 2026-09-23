#include "binjad/logging.hpp"

#include <iostream>

namespace binjad
{
void Log(LogLevel, std::string_view message)
{
    std::clog << message << '\n';
}
}
