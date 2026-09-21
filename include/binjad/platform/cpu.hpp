#pragma once

#include <cstddef>
#include <optional>
#include <string>

namespace binjad::platform
{
struct CpuCapacityResult
{
    std::optional<std::size_t> logicalCpuCount;
    std::string error;
};

CpuCapacityResult ActiveLogicalCpuCount();
}
