#include "binjad/platform/Cpu.hpp"

#include <sys/sysctl.h>

#include <cerrno>
#include <cstdint>
#include <cstring>

namespace binjad::platform
{
CpuCapacityResult ActiveLogicalCpuCount()
{
    std::uint32_t count = 0;
    std::size_t size = sizeof(count);
    if (::sysctlbyname("hw.activecpu", &count, &size, nullptr, 0) != 0)
        return {{}, std::string("cannot query hw.activecpu: ") + std::strerror(errno)};
    if (size != sizeof(count) || count == 0)
        return {{}, "hw.activecpu returned an invalid logical CPU count"};
    return {count, {}};
}
}
