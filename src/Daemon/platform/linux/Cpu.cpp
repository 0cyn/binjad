#include "binjad/platform/cpu.hpp"

#include <unistd.h>

namespace binjad::platform
{
CpuCapacityResult ActiveLogicalCpuCount()
{
    const long count = ::sysconf(_SC_NPROCESSORS_ONLN);
    if (count <= 0)
        return {{}, "cannot query online logical CPU count"};
    return {static_cast<std::size_t>(count), {}};
}
}
